#ifndef MD_FD_RETURN_H
#define MD_FD_RETURN_H
#include "fd_delivery.h"

/* One retained result, ordered by destination table and shared channel. The
 * caller keeps source and the mapped receipt alive through finish/cancel.
 * No application FD is retained after this operation. */
struct md_fd_channel;
struct md_fd_return {
    struct md_fd_order files;
    struct md_resource_order channel_order;
    struct md_fd_channel *channel;
    struct md_fd_delivery delivery;
    struct md_fd_origin_update update;
    int source, endpoint, number, offered, admission, checking;
    uint64_t request;
};
enum { MD_FD_RETURN_WAIT, MD_FD_RETURN_READY, MD_FD_RETURN_ADMIT, MD_FD_RETURN_CHECK };
struct md_fd_channel_observation;
int md_fd_return_begin(struct md_fd_return *, struct md_fd_origins *, int source,
        struct md_fs_anchor *, unsigned flags, struct md_fd_receipt *, struct md_resource_wakeup *);
/* Owner-loop progress only. ADMIT requests one atomic channel installation;
 * READY means the packet is queued for a single nonblocking task-local receive. */
int md_fd_return_progress(struct md_fd_return *, struct md_resource_wakeup *);
int md_fd_return_install(struct md_fd_return *, int listener, uint64_t notification);
int md_fd_return_observed(struct md_fd_return *, const struct md_fd_channel_observation *);
/* Result FD or negative errno. Publication comes from kernel-written receipt,
 * not from the task's reported syscall value or descriptor number. */
int md_fd_return_finish(struct md_fd_return *, long received, uint64_t token);
/* Only after the caller is stopped outside recvmsg or has terminated. Publish
 * any installed FD, discard any still-queued rights, and release both turns. */
int md_fd_return_cancel(struct md_fd_return *);
#endif
