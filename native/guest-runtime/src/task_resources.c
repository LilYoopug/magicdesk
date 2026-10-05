#define _GNU_SOURCE
#include "task_resources.h"
#include <errno.h>
#include <sched.h>
#include <linux/sched.h>

int md_resources_init(struct md_task_resources *r, struct md_mount_namespace *mounts) {
    *r = (struct md_task_resources){.fs=md_domain_new(), .sem_undo=md_ipc_undo_new(),
        .mounts=md_mount_namespace_retain(mounts), .files=md_fd_origins_new()};
    if (r->fs && r->sem_undo && r->files) return 0;
    md_resources_release(NULL, r); return -ENOMEM;
}
int md_resources_release(struct md_ipc *ipc, struct md_task_resources *r) {
    md_domain_release(r->fs);
    md_mount_namespace_release(r->mounts);
    md_fd_origins_release(r->files);
    int error = md_ipc_undo_release(ipc, r->sem_undo);
    *r = (struct md_task_resources){0};
    return error;
}
int md_resources_fork(const struct md_task_resources *r, unsigned long flags,
        struct md_task_resources *out) {
    *out = (struct md_task_resources){.fs=md_domain_fork(r->fs, !!(flags & CLONE_FS))};
    if (!out->fs) return -ENOMEM;
    if (r->files) {
        out->files=md_fd_origins_fork(r->files,!!(flags & CLONE_FILES));
        if (!out->files) { md_resources_release(NULL,out); return -ENOMEM; }
    }
    out->sem_undo = md_ipc_undo_fork(r->sem_undo, !!(flags & CLONE_SYSVSEM));
    if (out->sem_undo) { out->mounts=md_mount_namespace_retain(r->mounts); return 0; }
    md_resources_release(NULL,out); return -ENOMEM;
}
int md_resources_exec(struct md_task_resources *r) {
    if (!r->files) return 0;
    struct md_fd_origins *next=md_fd_origins_unshare_prepare(r->files);
    if (!next) return -ENOMEM;
    md_fd_origins_exec(next);
    struct md_fd_origins *old=r->files; r->files=next; md_fd_origins_release(old);
    return 0;
}
int md_resources_clone_supported(unsigned long flags) {
    return !(flags & (CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS
        | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP));
}
int md_resources_unshare_prepare(const struct md_task_resources *r, unsigned long flags,
        struct md_resource_change *change) {
    /* VM/SIGHAND/THREAD checks remain kernel-owned, including the requirement
     * that the caller is alone. Namespace flags are not successful no-ops. */
    unsigned long supported = CLONE_FS | CLONE_FILES | CLONE_SYSVSEM
        | CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;
    *change = (struct md_resource_change){0};
    unsigned long namespaces = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS
        | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP | CLONE_NEWTIME;
    if (flags & ~(supported | namespaces)) return -EINVAL;
    if (flags & namespaces) return -ENOTSUP;
    struct md_task_resources next = {0};
    if (flags & CLONE_FS) {
        next.fs = md_domain_unshare_prepare(r->fs);
        if (!next.fs) return -ENOMEM;
    }
    if (flags & CLONE_SYSVSEM) {
        next.sem_undo = md_ipc_undo_new();
        if (!next.sem_undo) { md_domain_release(next.fs); return -ENOMEM; }
    }
    if ((flags & CLONE_FILES) && r->files) {
        next.files=md_fd_origins_unshare_prepare(r->files);
        if (!next.files) { md_resources_release(NULL,&next); return -ENOMEM; }
    }
    *change = (struct md_resource_change){.next=next};
    return 0;
}
int md_resources_unshare_finish(struct md_ipc *ipc, struct md_task_resources *r,
        struct md_resource_change *change, long result) {
    if (!result) {
        if (change->next.fs) {
            struct md_guest_domain *old = r->fs;
            r->fs = change->next.fs; change->next.fs = old;
        }
        if (change->next.sem_undo) {
            struct md_ipc_undo *old = r->sem_undo;
            r->sem_undo = change->next.sem_undo; change->next.sem_undo = old;
        }
        if (change->next.files) {
            struct md_fd_origins *old=r->files;
            r->files=change->next.files; change->next.files=old;
        }
    }
    int error = md_resources_release(ipc, &change->next);
    *change = (struct md_resource_change){0};
    return error;
}
