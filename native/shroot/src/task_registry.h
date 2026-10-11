#ifndef MD_TASK_REGISTRY_H
#define MD_TASK_REGISTRY_H
#include "guest_identity.h"
#include "guest_domain.h"
#include "mount_namespace.h"
#include "fd_origins.h"

struct md_task_registry;
struct md_task_resources;
struct md_task_snapshot {
    pid_t tid, tgid;
    struct md_identity identity;
    struct md_guest_domain *fs;
    struct md_fs_location root;
    struct md_mount_namespace *mounts;
    struct md_fd_origins *files;
    struct md_fs_anchor *cwd;
    struct md_pid_identity *pid;
    struct md_pid_identity *pid_group;
    struct md_cgroup_member *cgroup;
    struct md_cgroup_namespace *cgroup_namespace;
    struct md_network_namespace *network;
    struct md_ipc_namespace *ipc;
    struct md_landlock_policy *landlock;
};
struct md_task_registry *md_task_registry_create(void);
void md_task_registry_destroy(struct md_task_registry *);
int md_task_registry_publish(struct md_task_registry *, pid_t tid, pid_t tgid,
        const struct md_identity *, const struct md_task_resources *);
void md_task_registry_forget(struct md_task_registry *, pid_t tid);
/* The supervisor is the sole writer. Exit drops live resources but preserves
 * proc observations in the existing entry until wait/reaping. No exit allocation. */
void md_task_registry_retire(struct md_task_registry *,pid_t,const struct md_identity *);
struct md_task_retired_view {
    const struct md_identity *identity;
    struct md_pid_identity *pid;
    struct md_cgroup_member *cgroup;
};
/* Borrowed on the writer thread, only until its next registry mutation. */
struct md_task_retired_view md_task_registry_retired(const struct md_task_registry *,pid_t);
int md_task_registry_has_retired(const struct md_task_registry *);
void md_task_registry_reap(struct md_task_registry *,pid_t);
void md_task_registry_collect(struct md_task_registry *,int (*gone)(pid_t));
/* peer==0 is a kernel-notification/internal caller. RPC callers must own the
 * TID's thread group; the supervisor may request on behalf of its tracee. */
/* A successful read retains identity groups, filesystem owner, mount view, file-table handle and
 * cwd anchor until release. The file table is a live handle, not frozen entries.
 * No registry lock is held while the filesystem resolves the request. */
int md_task_registry_read(struct md_task_registry *, pid_t tid, pid_t peer, struct md_task_snapshot *);
/* As read, but distinguishes a retired guest (-ESTALE) from an external PID
 * (-ESRCH). A native fast path must not expose the host state of a retired guest. */
int md_task_registry_probe(struct md_task_registry *,pid_t tid,pid_t peer,struct md_task_snapshot *);
void md_task_snapshot_release(struct md_task_snapshot *);
#endif
