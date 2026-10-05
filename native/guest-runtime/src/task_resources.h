#ifndef MD_TASK_RESOURCES_H
#define MD_TASK_RESOURCES_H
#include "guest_domain.h"
#include "mount_namespace.h"
#include "sysv_ipc.h"

/* Only resources with guest-owned state belong here. Linux owns the real FD
 * table, cwd/umask and open descriptions; duplicating them in the supervisor
 * would require intercepting otherwise-native close/read/write operations. */
struct md_task_resources {
    struct md_guest_domain *fs;
    struct md_mount_namespace *mounts;
    struct md_ipc_undo *sem_undo;
};
struct md_resource_change {
    struct md_task_resources next;
};

int md_resources_init(struct md_task_resources *, struct md_mount_namespace *);
int md_resources_fork(const struct md_task_resources *, unsigned long flags,
        struct md_task_resources *);
int md_resources_release(struct md_ipc *, struct md_task_resources *);
/* Prepare before letting the kernel change ownership. Commit only on its
 * successful syscall-exit stop; failure/exit discards the unused candidate. */
int md_resources_unshare_prepare(const struct md_task_resources *, unsigned long flags,
        struct md_resource_change *);
int md_resources_unshare_finish(struct md_ipc *, struct md_task_resources *,
        struct md_resource_change *, long result);
int md_resources_clone_supported(unsigned long flags);
#endif
