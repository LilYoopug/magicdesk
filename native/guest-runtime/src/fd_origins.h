#ifndef MD_FD_ORIGINS_H
#define MD_FD_ORIGINS_H
#include "fs_anchor.h"
#include "resource_order.h"

/* Application provenance retains no data open description or offset.
 * Typed infrastructure entries own their transport, not application files.
 * Task-owner operations run on the supervisor; pins do not count as owners. */
struct md_fd_origins;
struct md_fd_channel;
struct md_fd_origin_entry;
struct md_fd_origin_update {
    struct md_fd_origins *table;
    struct md_fd_origin_entry *entry;
};

/* Zero-initialized, intrusive, caller-owned request. Each record belongs to one
 * event loop; the shared table serializes admission across event loops.
 * Records remain alive until cancellation removes them or completion retires
 * them. A RUNNING cancellation still needs the exact kernel terminal event. */
struct md_fd_order {
    struct md_fd_origins *table;
    struct md_resource_order order;
};
/* Short FD capture/publication only, never blocking receive/FIFO readiness.
 * Begin returns 1 when ready, 0 when queued, or a negative errno. No allocation,
 * waits or callbacks. Each accepted record pins its shared file-table owner. */
/* NULL wakeup is for a synchronous owner. Readiness is a hint; the owning loop
 * rechecks through state(). The caller owns each record until its retirement. */
int md_fd_order_begin(struct md_fd_origins *, struct md_fd_order *, struct md_resource_wakeup *);
enum md_resource_order_state md_fd_order_state(const struct md_fd_order *);
int md_fd_order_start(struct md_fd_order *);
/* Cancel returns 1 if kernel completion is still required, otherwise 0.
 * A newly ready successor wakes its owner without exposing its request pointer.
 * Complete is called only after the kernel result AND its metadata publication. */
int md_fd_order_cancel(struct md_fd_order *);
int md_fd_order_complete(struct md_fd_order *);

struct md_fd_origins *md_fd_origins_new(void);
struct md_fd_origins *md_fd_origins_fork(struct md_fd_origins *, int shared);
struct md_fd_origins *md_fd_origins_unshare_prepare(struct md_fd_origins *);
void md_fd_origins_release(struct md_fd_origins *);
struct md_fd_origins *md_fd_origins_pin(struct md_fd_origins *);
void md_fd_origins_unpin(struct md_fd_origins *);
/* A retained origin, or NULL for an untracked descriptor, not proof of EBADF. */
struct md_fs_anchor *md_fd_origins_get(struct md_fd_origins *, int fd, unsigned *flags);
/* Caller-owned vector of retained origins, captured under one metadata lock.
 * -1 and unannotated FDs produce NULL, not a guessed mount. Repeated source
 * numbers retain independent references. The caller holds the source table
 * turn through actual kernel FD capture; these anchors retain no data OFDs. */
int md_fd_origins_capture(struct md_fd_origins *, const int *fds, unsigned count,
        struct md_fs_anchor **origins);
/* Prepare before a kernel mutation; finish is allocation-free. A negative
 * result discards it. NULL origin removes any prior destination annotation.
 * The caller orders kernel mutations; this lock alone cannot order syscalls. */
int md_fd_origins_prepare(struct md_fd_origins *, struct md_fs_anchor *, unsigned flags,
        struct md_fd_origin_update *);
/* The same publication/mutation path owns both origins and infrastructure.
 * These operations require the table turn, just like ordinary descriptor dup. */
int md_fd_origins_prepare_copy(struct md_fd_origins *, int source, unsigned flags,
        struct md_fd_origin_update *);
int md_fd_origins_prepare_channel(struct md_fd_origins *, struct md_fd_channel *, unsigned flags,
        struct md_fd_origin_update *);
/* No entry yields NULL/-1; ambiguous terminal mutations fail with ESTALE,
 * rather than creating another potentially orphaned infrastructure slot. */
int md_fd_origins_channel(struct md_fd_origins *, int *number, struct md_fd_channel **);
/* Only used after ESTALE, under the same table turn. A retained candidate is
 * not usable until an actual kernel observation resolves its identity/flags. */
int md_fd_origins_channel_candidate(struct md_fd_origins *, int *number, struct md_fd_channel **);
/* same==0 retires metadata only, never the guest slot. No allocations. */
int md_fd_origins_channel_resolve(struct md_fd_origins *, int number, struct md_fd_channel *, int same, unsigned flags);
void md_fd_origins_finish(struct md_fd_origin_update *, int result_fd);
/* Prepare a complete delivery before the kernel receive. Failure cancels all
 * prepared entries. A retained origin vector can prepare several independent
 * deliveries (MSG_PEEK); it is never consumed by preparation or publication. */
int md_fd_origins_prepare_batch(struct md_fd_origins *, struct md_fs_anchor *const *origins,
        unsigned flags, unsigned count, struct md_fd_origin_update *updates);
/* Publish an installed prefix in one metadata transaction, discard the rest.
 * The destination table turn must cover kernel installation and publication.
 * All numbers/owners are validated first; failure changes nothing. Zero received
 * discards the prepared delivery, not the source snapshot. No allocation;
 * retired anchors are released outside the metadata lock. */
int md_fd_origins_finish_batch(struct md_fd_origin_update *, unsigned count,
        const int *received_fds, unsigned received);
int md_fd_origins_set_flags(struct md_fd_origins *, int fd, unsigned flags);
int md_fd_origins_close_range(struct md_fd_origins *, unsigned first, unsigned last, int cloexec);
int md_fd_origins_abandon_range(struct md_fd_origins *, unsigned first, unsigned last);
void md_fd_origins_exec(struct md_fd_origins *);
#endif
