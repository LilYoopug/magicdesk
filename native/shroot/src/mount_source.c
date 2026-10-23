#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "procfs_view.h"
#include "fuse_view.h"
#include "render_device.h"
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
    md_sysfs_release(s->sysfs);
    md_provider_tree_release(s->provider);
    md_ipc_namespace_release(s->ipc);
    *s=(struct md_mount_source){.fd=-1};
}
static int sysfs_source(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_mount_source *out) {
    if (q->flags&~MD_FS_MOUNT_FLAGS) return -EOPNOTSUPP;
    if (q->value_size && (q->value_size!=1 || *(const char *)q->value)) return -EOPNOTSUPP;
    struct md_network_namespace *network=fs->actor ? fs->actor->network : NULL;
    if (!network) return -EOPNOTSUPP;
    if (!md_identity_capable_in(fs->store->identity,md_network_namespace_owner(network),CAP_SYS_ADMIN)) return -EPERM;
    int parent=md_fs_private_mounts_parent(fs->store);
    if (parent<0) return parent;
    struct md_mount_source s={.fd=-1,.backing=MD_MOUNT_SYSFS,
        .policy=md_fs_mount_flags(q->flags)|MD_MOUNT_NOSUID|MD_MOUNT_NODEV|MD_MOUNT_NOEXEC};
    s.sysfs=md_sysfs_new(parent,network,fs->store->identity);
    int error=errno; close(parent); errno=error;
    if (!s.sysfs) return -errno;
    if (fs->render_device.ops) {
        int r=md_render_device_sysfs(fs->render_device,md_sysfs_root(s.sysfs));
        if (r) { md_mount_source_close(&s); return r; }
    }
    s.provider=md_provider_tree_retain(md_sysfs_provider(s.sysfs));
    int policy=md_mount_policy_set(md_provider_tree_super_policy(s.provider),q->flags&MS_RDONLY ? MD_MOUNT_READONLY : 0);
    if (policy) { md_mount_source_close(&s); return policy; }
    s.fd=openat(md_sysfs_root(s.sysfs),".",O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (s.fd<0) { int r=-errno; md_mount_source_close(&s); return r; }
    *out=s; return 0;
}
static int mqueue_source(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_mount_source *out) {
    if (q->flags&~MD_FS_MOUNT_FLAGS) return -EOPNOTSUPP;
    if (q->value_size && (q->value_size!=1 || *(const char *)q->value)) return -EOPNOTSUPP;
    struct md_ipc_namespace *ipc=fs->actor ? fs->actor->ipc : NULL;
    if (!ipc) return -EOPNOTSUPP;
    if (!md_identity_capable_in(fs->store->identity,md_ipc_namespace_owner(ipc),CAP_SYS_ADMIN)) return -EPERM;
    int parent=md_fs_private_mounts_parent(fs->store);
    if (parent<0) return parent;
    struct md_mqueue_view *view=md_ipc_namespace_queues(ipc,parent);
    int error=errno; close(parent); errno=error;
    if (!view) return -errno;
    int fd=openat(md_mqueue_root(view),".",O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) return -errno;
    *out=(struct md_mount_source){.fd=fd,.backing=MD_MOUNT_MQUEUE,
        .policy=md_fs_mount_flags(q->flags)|MD_MOUNT_NOSUID|MD_MOUNT_NODEV|MD_MOUNT_NOEXEC,
        .ipc=md_ipc_namespace_retain(ipc)};
    return 0;
}
int md_mount_source_create(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_mount_source *out) {
    if (q->mode==MD_FS_MOUNT_TMPFS) return md_fs_mount_temporary(fs,q,out);
    if (q->mode==MD_FS_MOUNT_OVERLAY) return md_fs_mount_overlay(fs,q,out);
    if (q->mode==MD_FS_MOUNT_SYSFS) return sysfs_source(fs,q,out);
    if (q->mode==MD_FS_MOUNT_MQUEUE) return mqueue_source(fs,q,out);
    if (q->mode==MD_FS_MOUNT_FUSE) return md_fuse_view_source(fs,q,out);
    int devpts=q->mode==MD_FS_MOUNT_DEVPTS;
    int cgroup=q->mode==MD_FS_MOUNT_CGROUP || q->mode==MD_FS_MOUNT_CGROUP2;
    if (!devpts && !cgroup && q->mode!=MD_FS_MOUNT_PROC) return -ENODEV;
    if (q->flags&~MD_FS_MOUNT_FLAGS) return -ENOTSUP;
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
        else s.cgroup=md_cgroup_mount(fs->actor->cgroup,parent,q->mode==MD_FS_MOUNT_CGROUP,fs->store->identity,
            fs->actor->cgroup_namespace,q->value_size ? q->value : NULL);
        int error=errno; close(parent); errno=error;
        if ((devpts && !s.devpts) || (cgroup && !s.cgroup)) return -errno;
    } else {
        s.pid=md_pid_namespace_retain(pid);
        int parent=md_fs_private_mounts_parent(fs->store);
        if (parent<0) { md_mount_source_close(&s); return parent; }
        s.provider=md_procfs_new(parent,q->value_size ? q->value : NULL,fs->store->identity);
        int error=errno; close(parent);
        if (!s.provider) { md_mount_source_close(&s); return -error; }
        md_provider_tree_set_owner(s.provider,md_pid_namespace_owner(pid));
        int r=md_mount_policy_set(md_provider_tree_super_policy(s.provider),q->flags&MS_RDONLY ? MD_MOUNT_READONLY : 0);
        if (r) { md_mount_source_close(&s); return r; }
    }
    s.fd=devpts ? openat(md_devpts_root(s.devpts),".",O_PATH|O_DIRECTORY|O_CLOEXEC)
        : cgroup ? md_cgroup_open_root(s.cgroup,fs->actor->cgroup_namespace)
        : openat(md_provider_tree_root(s.provider),".",O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (s.fd<0) { int r=-errno; md_mount_source_close(&s); return r; }
    *out=s; return 0;
}
