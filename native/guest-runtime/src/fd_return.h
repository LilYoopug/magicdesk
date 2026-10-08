#ifndef MD_FD_RETURN_H
#define MD_FD_RETURN_H
#include "fd_delivery.h"

/* One retained result/vector, ordered by destination table and shared channel.
 * The caller keeps sources until offered and mapped/scratch storage through
 * finish/cancel. No application FD is retained after this operation. */
struct md_fd_channel;
struct md_fd_return {
    struct md_fd_order files;
    struct md_resource_order channel_order;
    struct md_fd_channel *channel;
    struct md_fd_delivery delivery;
    struct md_fd_table_observation *observation;
    struct md_fd_origin_update update;
    int source, endpoint, number, offered, admission, checking, observation_directory;
    const int *vector;
    unsigned count;
    uint64_t request;
};
enum { MD_FD_RETURN_WAIT, MD_FD_RETURN_READY, MD_FD_RETURN_ADMIT, MD_FD_RETURN_CHECK };
struct md_fd_channel_observation;
int md_fd_return_begin(struct md_fd_return *, struct md_fd_origins *, int source,
        struct md_fd_object *, unsigned flags, struct md_fd_receipt *, struct md_resource_wakeup *);
/* Optional vector publication. All scratch storage remains caller-owned through
 * finish/cancel. Select exactly one: a kernel-written shared memory receipt, or
 * table observation for direct application-control output. The latter borrows
 * the task-captured directory and arms only after infrastructure admission. */
struct md_fd_return_publication {
    struct md_fd_object *const *origins;
    struct md_fd_origin_update *updates;
    int *numbers;
    struct md_fd_receipt *memory;
    struct md_fd_table_observation *observation;
    int directory;
    unsigned flags;
};
/* Without publication, ancillary delivery goes directly into application control
 * memory: the kernel owns partial-copy installation and cancellation only drains
 * unreceived rights. This mode does not publish origins. */
int md_fd_return_vector_begin(struct md_fd_return *, struct md_fd_origins *,
        const int *, unsigned, const struct md_fd_return_publication *, struct md_resource_wakeup *);
/* Owner-loop progress only. ADMIT requests one atomic channel installation;
 * READY means the packet is queued for a single nonblocking task-local receive. */
int md_fd_return_progress(struct md_fd_return *, struct md_resource_wakeup *);
int md_fd_return_install(struct md_fd_return *, int listener, uint64_t notification);
int md_fd_return_observed(struct md_fd_return *, const struct md_fd_channel_observation *);
/* Scalar result FD, vector success (zero), or errno. Vector native output errors
 * survive even when some rights were installed and their origins published.
 * Publication comes from a kernel-written receipt or retained table observation,
 * not from the task's reported syscall value or descriptor number. */
int md_fd_return_finish(struct md_fd_return *, long received, uint64_t token);
/* Only after the caller is stopped outside recvmsg; table observation requires
 * the pre-reap PTRACE_EVENT_EXIT stop on terminal cancellation. Publish
 * any installed FD, discard any still-queued rights, and release both turns. */
int md_fd_return_cancel(struct md_fd_return *);
#endif
