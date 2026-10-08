#define _GNU_SOURCE
#include "task_resources.h"
#include "proc_namespace.h"
#include <errno.h>
#include <sched.h>
#include <linux/sched.h>

int md_resources_init(struct md_task_resources *r, struct md_mount_namespace *mounts) {
    *r = (struct md_task_resources){.fs=md_domain_new(), .sem_undo=md_ipc_undo_new(),
        .mounts=md_mount_namespace_retain(mounts), .files=md_fd_origins_new(), .uts=md_uts_namespace_new(),
        .ipc=md_ipc_namespace_new(NULL,0)};
    if (r->fs && r->sem_undo && r->files && r->uts && r->ipc) { md_domain_bind_mounts(r->fs,mounts); return 0; }
    md_resources_release(r); return -ENOMEM;
}
int md_resources_release(struct md_task_resources *r) {
    md_domain_release(r->fs);
    md_mount_namespace_release(r->mounts);
    md_fd_origins_release(r->files);
    md_uts_namespace_release(r->uts);
    md_pid_identity_release(r->pid);
    md_pid_identity_release(r->pid_group);
    md_pid_namespace_release(r->pid_children);
    int error = md_ipc_undo_release(md_ipc_namespace_active(r->ipc), r->sem_undo);
    md_ipc_namespace_release(r->ipc);
    *r = (struct md_task_resources){0};
    return error;
}
int md_resources_fork(const struct md_task_resources *r, unsigned long flags,
        struct md_task_resources *out) {
    *out = (struct md_task_resources){.fs=md_domain_fork(r->fs, !!(flags & CLONE_FS))};
    if (!out->fs) return -ENOMEM;
    if (r->files) {
        out->files=md_fd_origins_fork(r->files,!!(flags & CLONE_FILES));
        if (!out->files) { md_resources_release(out); return -ENOMEM; }
    }
    out->sem_undo = md_ipc_undo_fork(r->sem_undo, !!(flags & CLONE_SYSVSEM));
    if (out->sem_undo) {
        out->mounts=md_mount_namespace_retain(r->mounts);
        out->uts=md_uts_namespace_retain(r->uts);
        out->ipc=md_ipc_namespace_retain(r->ipc);
        out->pid=md_pid_identity_retain(r->pid);
        out->pid_group=md_pid_identity_retain(r->pid_group);
        out->pid_children=md_pid_namespace_retain(r->pid_children);
        return 0;
    }
    md_resources_release(out); return -ENOMEM;
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
    return !(flags & (CLONE_NEWNET
        | CLONE_NEWCGROUP))
        && (!(flags&CLONE_NEWUSER) || !(flags&(CLONE_FS|CLONE_THREAD)))
        && (!(flags&CLONE_NEWPID) || !(flags&(CLONE_THREAD|CLONE_PARENT)))
        && (flags & (CLONE_NEWNS | CLONE_FS)) != (CLONE_NEWNS | CLONE_FS)
        && (flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) != (CLONE_NEWIPC | CLONE_SYSVSEM);
}
int md_resources_unshare_prepare(const struct md_task_resources *r, unsigned long flags,
        const struct md_identity *identity, struct md_resource_change *change) {
    /* VM/SIGHAND/THREAD checks remain kernel-owned, including the requirement
     * that the caller is alone. Namespace flags are not successful no-ops. */
    unsigned long supported = CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_NEWNS
        | CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID;
    *change = (struct md_resource_change){0};
    unsigned long namespaces = CLONE_NEWNET
        | CLONE_NEWCGROUP | CLONE_NEWTIME;
    if (flags & ~(supported | namespaces)) return -EINVAL;
    if (flags & namespaces) return -ENOTSUP;
    if ((flags & CLONE_NEWNS) && !r->mounts) return -ENOTSUP;
    unsigned long creating=flags&(CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID);
    if (creating && !identity) return -EINVAL;
    if (creating && !(flags&CLONE_NEWUSER) && !md_identity_capable(identity,CAP_SYS_ADMIN)) return -EPERM;
    struct md_user_namespace *owner=identity ? identity->user_namespace : NULL;
    if (flags&CLONE_NEWUSER) {
        if (md_domain_restricted(r->fs) || (!r->mounts && md_domain_scoped(r->fs))) return -EPERM;
        change->identity=md_identity_copy(identity); change->identity_pending=1;
        int error=md_identity_enter_user_namespace(&change->identity);
        if (error) { md_resources_unshare_finish(NULL,NULL,change,error); return error; }
        owner=change->identity.user_namespace;
        change->check_root=r->mounts!=NULL;
        flags|=CLONE_FS;
    }
    struct md_task_resources next = {0};
    int error=-ENOMEM;
    if (flags&CLONE_NEWPID) {
        if (r->pid_children!=md_pid_identity_namespace(r->pid)) { error=-EINVAL; goto failed; }
        next.pid_children=md_pid_namespace_new(r->pid_children,owner);
        if (!next.pid_children) { error=-errno; goto failed; }
        change->pid_children_pending=1;
    }
    if ((flags & CLONE_FS) && !(flags & CLONE_NEWNS) && !change->check_root) {
        next.fs = md_domain_unshare_prepare(r->fs);
        if (!next.fs) goto failed;
    }
    if (flags & (CLONE_SYSVSEM|CLONE_NEWIPC)) {
        next.sem_undo = md_ipc_undo_new();
        if (!next.sem_undo) goto failed;
    }
    if ((flags & CLONE_FILES) && r->files) {
        next.files=md_fd_origins_unshare_prepare(r->files);
        if (!next.files) goto failed;
    }
    if (flags & CLONE_NEWUTS) {
        next.uts=md_uts_namespace_copy(r->uts,owner);
        if (!next.uts) goto failed;
    }
    if (flags & CLONE_NEWIPC) {
        next.ipc=md_ipc_namespace_copy(r->ipc,owner);
        if (!next.ipc) goto failed;
    }
    change->next=next; change->copy_mounts=!!(flags&CLONE_NEWNS); change->namespaces=creating;
    return 0;
failed:
    md_resources_release(&next);
    md_resources_unshare_finish(NULL,NULL,change,error);
    return error;
}
int md_resources_unshare_finish(struct md_task_resources *r,
        struct md_identity *identity, struct md_resource_change *change, long result) {
    int invalid=!result && (!r || (change->identity_pending && !identity)
        || (change->copy_mounts && (!change->next.mounts || !change->next.fs))
        || (change->join_mounts && (!change->next.mounts || !change->next.fs))
        || (change->check_root && !change->next.fs));
    if (!result && !invalid) {
        if (change->pid_children_pending) {
            struct md_pid_namespace *old=r->pid_children;
            r->pid_children=change->next.pid_children; change->next.pid_children=old;
        }
        if (change->identity_pending) {
            struct md_identity old=*identity; *identity=change->identity; change->identity=old;
        }
        if (change->next.uts) {
            struct md_uts_namespace *old=r->uts;
            r->uts=change->next.uts; change->next.uts=old;
        }
        if (change->next.mounts) {
            struct md_mount_namespace *old=r->mounts;
            r->mounts=change->next.mounts; change->next.mounts=old;
        }
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
        if (change->next.ipc) {
            struct md_ipc_namespace *old=r->ipc;
            r->ipc=change->next.ipc; change->next.ipc=old;
        } else if (change->next.sem_undo) {
            change->next.ipc=md_ipc_namespace_retain(r->ipc);
        }
    }
    int error = md_resources_release(&change->next);
    if (change->identity_pending) md_identity_release(&change->identity);
    md_mount_namespace_release(change->join_mounts);
    *change = (struct md_resource_change){0};
    return invalid ? -EINVAL : error;
}
int md_resources_setns_prepare(const struct md_task_resources *r, const struct md_identity *id,
        const struct md_namespace_reference *target, unsigned type, struct md_resource_change *change) {
    *change=(struct md_resource_change){0};
    if (!target || !id || (type && type!=md_namespace_reference_type(target))) return -EINVAL;
    if (target->kind==MD_NAMESPACE_USER) {
        if (md_domain_shared(r->fs)) return -EINVAL;
        change->identity=md_identity_copy(id); change->identity_pending=1;
        int error=md_identity_join_user_namespace(&change->identity,target->value.user);
        if (error) md_resources_unshare_finish(NULL,NULL,change,error);
        return error;
    }
    const struct md_user_namespace *owner=md_namespace_reference_owner(target);
    if (!md_identity_capable(id,CAP_SYS_ADMIN) || !md_identity_capable_in(id,owner,CAP_SYS_ADMIN)) return -EPERM;
    switch (target->kind) {
    case MD_NAMESPACE_MOUNT:
        if (!md_identity_capable(id,CAP_SYS_CHROOT)) return -EPERM;
        if (md_domain_shared(r->fs)) return -EINVAL;
        change->join_mounts=md_mount_namespace_retain(target->value.mount); break;
    case MD_NAMESPACE_UTS:
        change->next.uts=md_uts_namespace_retain(target->value.uts); break;
    case MD_NAMESPACE_IPC:
        change->next.sem_undo=md_ipc_undo_new();
        if (!change->next.sem_undo) return -ENOMEM;
        change->next.ipc=md_ipc_namespace_retain(target->value.ipc); break;
    case MD_NAMESPACE_PID: case MD_NAMESPACE_PID_CHILDREN:
        if (!md_pid_namespace_contains(md_pid_identity_namespace(r->pid),target->value.pid)) return -EINVAL;
        change->next.pid_children=md_pid_namespace_retain(target->value.pid);
        change->pid_children_pending=1; break;
    default: return -EINVAL;
    }
    return 0;
}
