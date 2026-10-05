#ifndef MD_FS_ENGINE_H
#define MD_FS_ENGINE_H
#include "fs_operation.h"
#include "inode_store.h"
#include "mount_namespace.h"
#include "task_registry.h"
struct md_image_catalogue;
struct md_fd_exchanges;
/* The worker borrows its store/images and retains an initial mount view.
 * Authenticated task requests borrow their own retained view for dispatch. */
struct md_filesystem {
    struct md_inode_store *store;
    struct md_image_catalogue *images;
    struct md_mount_namespace *mounts;
    struct md_view_object *native_root;
    struct md_task_registry *tasks;
    struct md_fd_exchanges *exchanges;
    struct md_ipc_credentials *ipc;
    const char *ipc_store;
};
/* Request-local authentication, independent of transport. Keep this context
 * until delivery/cancellation finishes; the borrowed filesystem outlives it.
 * No registry lookup is repeated at execution or publication. */
struct md_fs_context {
    struct md_filesystem *filesystem;
    struct md_task_snapshot task;
    int actor, peer, authenticated, has_identity;
};
int md_fs_context_begin(struct md_filesystem *, int actor, int peer, struct md_fs_context *);
void md_fs_context_end(struct md_fs_context *);
void md_fs_context_execute(struct md_fs_context *,
        const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
/* One namespace owner, independent of transport. Input descriptors are borrowed;
 * a successful open transfers result.fd. No guest pointers enter this API.
 * Synchronous internal callers capture and release a context within this call. */
void md_fs_execute(struct md_filesystem *,
        const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
void md_fs_stat_info(const struct stat *, struct md_fs_info *);
#endif
