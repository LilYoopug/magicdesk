#ifndef MD_FD_ORIGINS_H
#define MD_FD_ORIGINS_H
#include "fs_anchor.h"
#include "resource_order.h"

/* Guest provenance only: no kernel FD, offset or open description is owned.
 * Task-owner operations run on the supervisor; pins do not count as owners. */
struct md_fd_origins;
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
/* Prepare before a kernel mutation; finish is allocation-free. A negative
 * result discards it. NULL origin removes any prior destination annotation.
 * The caller orders kernel mutations; this lock alone cannot order syscalls. */
int md_fd_origins_prepare(struct md_fd_origins *, struct md_fs_anchor *, unsigned flags,
        struct md_fd_origin_update *);
void md_fd_origins_finish(struct md_fd_origin_update *, int result_fd);
int md_fd_origins_set_flags(struct md_fd_origins *, int fd, unsigned flags);
int md_fd_origins_close_range(struct md_fd_origins *, unsigned first, unsigned last, int cloexec);
void md_fd_origins_exec(struct md_fd_origins *);
#endif
