#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

void md_mount_source_close(struct md_mount_source *s) {
    if (s->fd>=0) close(s->fd);
    md_inode_lifetime_release(s->storage);
    md_pid_namespace_release(s->pid);
    md_devpts_release(s->devpts);
    md_cgroup_release(s->cgroup);
    *s=(struct md_mount_source){.fd=-1};
}
int md_mount_source_create(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_mount_source *out) {
    if (q->mode==MD_FS_MOUNT_TMPFS) return md_fs_mount_temporary(fs,q,out);
    if (q->mode==MD_FS_MOUNT_OVERLAY) return md_fs_mount_overlay(fs,q,out);
    int devpts=q->mode==MD_FS_MOUNT_DEVPTS;
    int cgroup=q->mode==MD_FS_MOUNT_CGROUP || q->mode==MD_FS_MOUNT_CGROUP2;
    if (!devpts && !cgroup && q->mode!=MD_FS_MOUNT_PROC) return -ENODEV;
    if (q->flags&~MD_FS_MOUNT_FLAGS) return -ENOTSUP;
    if (q->mode==MD_FS_MOUNT_CGROUP) {
        if (!q->value_size || strcmp(q->value,"devices")) return -ENOTSUP;
    } else if (!devpts && q->value_size && (q->value_size!=1 || *(const char *)q->value)) return -ENOTSUP;
    struct md_pid_namespace *pid=fs->actor ? md_pid_identity_namespace(fs->actor->pid) : NULL;
    if (!devpts && !cgroup && !md_identity_capable_in(fs->store->identity,md_pid_namespace_owner(pid),CAP_SYS_ADMIN)) return -EPERM;
    if (cgroup && (!fs->actor || !fs->actor->cgroup)) return -EOPNOTSUPP;
    if (cgroup && !md_identity_capable_in(fs->store->identity,
            md_cgroup_namespace_owner(fs->actor->cgroup_namespace),CAP_SYS_ADMIN)) return -EPERM;
    struct md_mount_source s={.fd=-1,
        .backing=devpts ? MD_MOUNT_DEVPTS : cgroup ? MD_MOUNT_CGROUP : MD_MOUNT_PROC,
        .policy=md_fs_mount_flags(q->flags)|MD_MOUNT_NOSUID|MD_MOUNT_NOEXEC|(devpts ? 0 : MD_MOUNT_NODEV)};
    if (devpts || cgroup) {
        int parent=md_fs_private_mounts_parent(fs->store);
        if (parent<0) return parent;
        if (devpts) s.devpts=md_devpts_new(parent,q->value_size ? q->value : NULL,fs->store->identity);
        else s.cgroup=md_cgroup_mount(fs->actor->cgroup,parent,q->mode==MD_FS_MOUNT_CGROUP,fs->store->identity);
        int error=errno; close(parent); errno=error;
        if ((devpts && !s.devpts) || (cgroup && !s.cgroup)) return -errno;
    } else s.pid=md_pid_namespace_retain(pid);
    s.fd=devpts ? openat(md_devpts_root(s.devpts),".",O_PATH|O_DIRECTORY|O_CLOEXEC)
        : cgroup ? md_cgroup_open_root(s.cgroup,fs->actor->cgroup_namespace)
        : open("/proc",O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (s.fd<0) { int r=-errno; md_mount_source_close(&s); return r; }
    *out=s; return 0;
}
