#ifndef MD_FS_WORKER_H
#define MD_FS_WORKER_H
#include "inode_store.h"
struct md_filesystem;
struct md_fs_attachment;
struct md_image_catalogue;
struct md_fs_worker;
struct md_task_registry;
struct md_mount_namespace;
struct md_fd_exchanges;
struct md_ofd_orders;
struct md_ipc_inherited;
struct md_fs_work {
    struct md_fs_work *next;
    /* Worker callback never blocks on the requesting task. A nonzero error
     * retires accepted work during shutdown, with no filesystem access. */
    void (*run)(struct md_fs_work *, struct md_filesystem *, int error);
    int (*complete)(struct md_fs_work *);
};
/* Supervisor-owned token, retained until end or worker_stop returns. Begin is
 * only a request: state==1 proves the worker has stopped all namespace work,
 * including broker memory writes. Completion uses the existing worker FD.
 * Other supervisors/services are independent. No nested or implicit pause. */
struct md_fs_worker_pause { struct md_fs_worker *owner; int acknowledged; };
int md_fs_worker_pause_begin(struct md_fs_worker *, struct md_fs_worker_pause *);
int md_fs_worker_pause_state(const struct md_fs_worker_pause *);
int md_fs_worker_pause_end(struct md_fs_worker_pause *);
/* One worker owns the namespace, image catalogue and both request transports.
 * Published work transfers to the supervisor. Queue locks never cover IO. */
int md_fs_worker_start(const char *store, const char *endpoint, const char *admit, struct md_task_registry *, struct md_fd_exchanges *,
        const struct md_fs_attachment *, unsigned attachment_count, int statistics,
        const struct md_ipc_inherited *, struct md_fs_worker **out);
int md_fs_worker_fd(struct md_fs_worker *);
/* Borrowed nonblocking eventfd for cross-owner readiness, valid until stop. */
int md_fs_worker_wake_fd(struct md_fs_worker *);
/* Borrowed until worker_stop; initialized before startup acknowledges readiness. */
struct md_mount_namespace *md_fs_worker_mounts(struct md_fs_worker *);
struct md_ofd_orders *md_fs_worker_cursors(struct md_fs_worker *);
void md_fs_worker_wake(struct md_fs_worker *);
/* Caller-owned intrusive records containing trusted host-side state, never
 * guest pointers to dereference. Submit once per ownership cycle; publication
 * returns access to complete(). The owner retains storage through completion
 * or stop()'s join. Stop retires pending run callbacks but does not dispatch
 * completions; terminal cleanup releases owner records after that join. */
int md_fs_worker_submit(struct md_fs_worker *, struct md_fs_work *);
/* Supervisor-only: dispatch each completion to its explicit owner, including
 * remaining completions after an earlier callback failed. */
int md_fs_worker_dispatch(struct md_fs_worker *);
void md_fs_worker_publish(struct md_fs_worker *, struct md_fs_work *);
void md_fs_worker_notifications(struct md_fs_worker *, int, void *,
        int (*)(void *, struct md_filesystem *, short));
int md_fs_worker_error(struct md_fs_worker *);
int md_fs_worker_stop(struct md_fs_worker *);
#endif
