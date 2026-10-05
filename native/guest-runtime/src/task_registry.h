#ifndef MD_TASK_REGISTRY_H
#define MD_TASK_REGISTRY_H
#include "guest_identity.h"
#include "guest_domain.h"
#include "mount_namespace.h"
#include "fd_origins.h"

struct md_task_registry;
struct md_task_resources;
struct md_task_snapshot {
    struct md_identity identity;
    struct md_fs_location root;
    struct md_mount_namespace *mounts;
    struct md_fd_origins *files;
    struct md_fs_anchor *cwd;
};
struct md_task_registry *md_task_registry_create(void);
void md_task_registry_destroy(struct md_task_registry *);
int md_task_registry_publish(struct md_task_registry *, pid_t tid, pid_t tgid,
        const struct md_identity *, const struct md_task_resources *);
void md_task_registry_forget(struct md_task_registry *, pid_t tid);
/* peer==0 is a kernel-notification/internal caller. RPC callers must own the
 * TID's thread group; the supervisor may request on behalf of its tracee. */
/* A successful read retains identity groups, mount view, file-table handle and
 * cwd anchor until release. The file table is a live handle, not frozen entries.
 * No registry lock is held while the filesystem resolves the request. */
int md_task_registry_read(struct md_task_registry *, pid_t tid, pid_t peer, struct md_task_snapshot *);
void md_task_snapshot_release(struct md_task_snapshot *);
int md_task_registry_set_root(struct md_task_registry *, pid_t tid, pid_t peer, const struct md_fs_location *);
#endif
