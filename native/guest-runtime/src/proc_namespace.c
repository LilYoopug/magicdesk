#define _GNU_SOURCE
#include "proc_namespace.h"
#include "task_resources.h"
#include <errno.h>
#include <sched.h>
#include <unistd.h>

struct md_namespace_reference md_namespace_reference_capture(enum md_namespace_kind kind,
        const struct md_task_resources *r, struct md_user_namespace *user) {
    struct md_namespace_reference ref={.kind=kind};
    switch (kind) {
    case MD_NAMESPACE_USER: ref.value.user=md_user_namespace_retain(user); break;
    case MD_NAMESPACE_MOUNT: ref.value.mount=md_mount_namespace_retain(r->mounts); break;
    case MD_NAMESPACE_UTS: ref.value.uts=md_uts_namespace_retain(r->uts); break;
    case MD_NAMESPACE_IPC: ref.value.ipc=md_ipc_namespace_retain(r->ipc); break;
    case MD_NAMESPACE_PID: ref.value.pid=md_pid_namespace_retain(md_pid_identity_namespace(r->pid)); break;
    case MD_NAMESPACE_PID_CHILDREN: ref.value.pid=md_pid_namespace_retain(r->pid_children); ref.kind=MD_NAMESPACE_PID; break;
    case MD_NAMESPACE_NETWORK: ref.value.network=md_network_namespace_retain(r->network); break;
    }
    return ref;
}
struct md_namespace_reference md_namespace_reference_copy(const struct md_namespace_reference *ref) {
    struct md_namespace_reference next=*ref;
    switch (ref->kind) {
    case MD_NAMESPACE_USER: md_user_namespace_retain(next.value.user); break;
    case MD_NAMESPACE_MOUNT: md_mount_namespace_retain(next.value.mount); break;
    case MD_NAMESPACE_UTS: md_uts_namespace_retain(next.value.uts); break;
    case MD_NAMESPACE_IPC: md_ipc_namespace_retain(next.value.ipc); break;
    case MD_NAMESPACE_PID: case MD_NAMESPACE_PID_CHILDREN: md_pid_namespace_retain(next.value.pid); break;
    case MD_NAMESPACE_NETWORK: md_network_namespace_retain(next.value.network); break;
    }
    return next;
}
void md_namespace_reference_release(struct md_namespace_reference *ref) {
    switch (ref->kind) {
    case MD_NAMESPACE_USER: md_user_namespace_release(ref->value.user); break;
    case MD_NAMESPACE_MOUNT: md_mount_namespace_release(ref->value.mount); break;
    case MD_NAMESPACE_UTS: md_uts_namespace_release(ref->value.uts); break;
    case MD_NAMESPACE_IPC: md_ipc_namespace_release(ref->value.ipc); break;
    case MD_NAMESPACE_PID: case MD_NAMESPACE_PID_CHILDREN: md_pid_namespace_release(ref->value.pid); break;
    case MD_NAMESPACE_NETWORK: md_network_namespace_release(ref->value.network); break;
    }
    *ref=(struct md_namespace_reference){0};
}
void md_namespace_reference_stat(const struct md_namespace_reference *ref, struct stat *out) {
    uint64_t inode=0;
    switch (ref->kind) {
    case MD_NAMESPACE_USER: inode=md_user_namespace_inode(ref->value.user); break;
    case MD_NAMESPACE_MOUNT: inode=md_mount_namespace_inode(ref->value.mount); break;
    case MD_NAMESPACE_UTS: inode=md_uts_namespace_inode(ref->value.uts); break;
    case MD_NAMESPACE_IPC: inode=md_ipc_namespace_inode(ref->value.ipc); break;
    case MD_NAMESPACE_PID: case MD_NAMESPACE_PID_CHILDREN: inode=md_pid_namespace_inode(ref->value.pid); break;
    case MD_NAMESPACE_NETWORK: inode=md_network_namespace_inode(ref->value.network); break;
    }
    *out=(struct stat){.st_dev=UINT32_C(0xfffe0000)+(unsigned)ref->kind,
        .st_ino=inode,.st_mode=S_IFREG|0444,.st_nlink=1,.st_blksize=getpagesize()};
}
unsigned long md_namespace_reference_type(const struct md_namespace_reference *ref) {
    static const unsigned long types[]={CLONE_NEWUSER,CLONE_NEWNS,CLONE_NEWUTS,CLONE_NEWIPC,CLONE_NEWPID,CLONE_NEWPID,CLONE_NEWNET};
    return types[ref->kind];
}
const struct md_user_namespace *md_namespace_reference_owner(const struct md_namespace_reference *ref) {
    switch (ref->kind) {
    case MD_NAMESPACE_USER: return md_user_namespace_parent(ref->value.user);
    case MD_NAMESPACE_MOUNT: return md_mount_namespace_owner(ref->value.mount);
    case MD_NAMESPACE_UTS: return md_uts_namespace_owner(ref->value.uts);
    case MD_NAMESPACE_IPC: return md_ipc_namespace_owner(ref->value.ipc);
    case MD_NAMESPACE_PID: case MD_NAMESPACE_PID_CHILDREN: return md_pid_namespace_owner(ref->value.pid);
    case MD_NAMESPACE_NETWORK: return md_network_namespace_owner(ref->value.network);
    }
    return NULL;
}
int md_namespace_reference_related(const struct md_namespace_reference *ref,
        const struct md_user_namespace *caller, const struct md_pid_namespace *pid,
        int parent, struct md_namespace_reference *out) {
    if (parent && ref->kind!=MD_NAMESPACE_USER && ref->kind!=MD_NAMESPACE_PID) return -EINVAL;
    if (ref->kind==MD_NAMESPACE_USER && !ref->value.user) return -EPERM;
    const struct md_user_namespace *owner=md_namespace_reference_owner(ref);
    if (!md_user_namespace_contains(caller,owner)) return -EPERM;
    if (parent && ref->kind==MD_NAMESPACE_PID) {
        if (!ref->value.pid || !md_pid_namespace_contains(pid,md_pid_namespace_parent(ref->value.pid))) return -EPERM;
        *out=(struct md_namespace_reference){.kind=MD_NAMESPACE_PID,
            .value.pid=md_pid_namespace_retain(md_pid_namespace_parent(ref->value.pid))};
        return 0;
    }
    *out=(struct md_namespace_reference){.kind=MD_NAMESPACE_USER,
        .value.user=md_user_namespace_retain((struct md_user_namespace *)owner)};
    return 0;
}
