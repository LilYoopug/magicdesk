#ifndef MD_FS_ENGINE_H
#define MD_FS_ENGINE_H
#include "fs_operation.h"
#include "inode_store.h"
#include "mount_namespace.h"
struct md_image_catalogue;
/* The worker borrows its store/images and retains an initial mount view.
 * Authenticated task requests borrow their own retained view for dispatch. */
struct md_filesystem {
    struct md_inode_store *store;
    struct md_image_catalogue *images;
    struct md_mount_namespace *mounts;
    struct md_view_object *native_root;
    struct md_task_registry *tasks;
    struct md_ipc_credentials *ipc;
    const char *ipc_store;
};
/* One namespace owner, independent of transport. Input descriptors are borrowed;
 * a successful open transfers result.fd. No guest pointers enter this API. */
void md_fs_execute(struct md_filesystem *,
        const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
void md_fs_stat_info(const struct stat *, struct md_fs_info *);
#endif
