#ifndef MD_FS_ENGINE_H
#define MD_FS_ENGINE_H
#include "fs_operation.h"
#include "inode_store.h"
#include "mount_namespace.h"
#include "task_registry.h"
struct md_image_catalogue;
struct md_fd_exchanges;
struct md_ofd_orders;
struct md_fs_storage_cache;
struct md_fs_statistics { struct md_cost operation[MD_FS_LAST + 1]; };
/* The worker borrows its store/images and retains an initial mount view.
 * Authenticated task requests borrow their own retained view for dispatch. */
struct md_filesystem {
    struct md_inode_store *store;
    struct md_fs_storage_cache *storage;
    struct md_inode_store *selected_store;
    struct md_image_catalogue *images;
    struct md_mount_namespace *mounts;
    struct md_view_object *native_root;
    struct md_view_mount *inode_mount;
    struct md_task_registry *tasks;
    struct md_fd_exchanges *exchanges;
    struct md_ofd_orders *cursors;
    struct md_ipc_credentials *ipc;
    const char *ipc_store;
    struct md_fs_statistics *statistics;
    const struct md_task_snapshot *actor;
};
/* Worker-only lazy authority admission, shared by guest IPC and private peer
 * setup. No connection/database ownership crosses into the supervisor. */
int md_fs_ipc_authority(struct md_filesystem *, struct md_ipc_credentials **);
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
/* Worker-created snapshots use the same retained path provenance as opens.
 * A failed capture closes result.fd; the returned anchor is caller-owned. */
void md_fs_context_capture_result(struct md_fs_context *, struct md_fs_result *, struct md_fs_anchor **);
/* One namespace owner, independent of transport. Input descriptors are borrowed;
 * a successful open transfers result.fd. No guest pointers enter this API.
 * Synchronous internal callers capture and release a context within this call. */
void md_fs_execute(struct md_filesystem *,
        const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
void md_fs_stat_info(const struct stat *, struct md_fs_info *);
void md_fs_statfs_result(int fd, unsigned policy, const struct md_inode_lifetime *,
        struct md_fs_result *, const struct md_fs_output *);
/* Compound operations reuse the already selected worker identity and mount view. */
void md_fs_view_execute(struct md_filesystem *, const struct md_fs_request *,
        struct md_fs_result *, const struct md_fs_output *);
void md_fs_xattr(struct md_filesystem *, const struct md_fs_request *,
        struct md_fs_result *, const struct md_fs_output *);
#endif
