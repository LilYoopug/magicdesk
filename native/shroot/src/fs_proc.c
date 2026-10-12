#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_control.h"
#include "inode_internal.h"
#include "network_namespace.h"
#include "proc_paths.h"
#include "proc_sysctl.h"
#include "procfs_view.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <unistd.h>

int md_fs_proc_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || mount->backing!=MD_MOUNT_PROC || fd<0 || !fs->actor) return 0;
    char path[PATH_MAX];
    int r=md_procfs_path(mount,fd,path,sizeof(path));
    if (r) { out->error=r; return 1; }
    struct md_proc_path ref=md_proc_path_for(path,0,0);
    enum md_proc_file_kind kind=(enum md_proc_file_kind)(ref.kind-MD_PROC_UID_MAP);
    int sysctl=md_proc_file_sysctl(kind);
    if (q->operation==MD_FS_STATFS) {
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        if (!out->error) ((struct md_fs_statfs *)output->data)->type=PROC_SUPER_MAGIC;
        return 1;
    }
    if (q->operation!=MD_FS_PATH && q->operation!=MD_FS_OBJECT_ID) {
        unsigned minimum=q->operation==MD_FS_STAT || q->operation==MD_FS_FSTAT
            || ((q->operation==MD_FS_OPEN || q->operation==MD_FS_REOPEN) && (q->flags&O_PATH)) ? 2 : 1;
        r=md_procfs_check(fs,mount,path,minimum);
        if (r) { out->error=r; return 1; }
    }
    if (!sysctl && (q->operation==MD_FS_STAT || q->operation==MD_FS_FSTAT)
            && mount->provider) {
        int private=md_provider_tree_private(mount->provider,fd);
        if (private<0) { out->error=private; return 1; }
        if (private) {
            struct stat st;
            r=stat(path,&st) ? -errno : 0;
            if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
            else out->error=r;
            return 1;
        }
    }
    if (!sysctl && (!md_proc_network_sysctl(ref.kind)
            || !md_network_namespace_managed(fs->actor->network))) return 0;
    if (q->operation==MD_FS_PATH || q->operation==MD_FS_OBJECT_ID) return 0;
    /* Metadata/access do not need an open description or its carrier memfd. */
    if (sysctl && (q->operation==MD_FS_STAT || q->operation==MD_FS_FSTAT)) {
        struct stat st;
        r=md_proc_sysctl_stat(kind,&st);
        if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        else out->error=r;
        return 1;
    }
    if (sysctl && q->operation==MD_FS_ACCESS) {
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS)) r=-EINVAL;
        else if ((q->mode&W_OK) && md_view_readonly(mount)) r=-EROFS;
        else r=md_proc_sysctl_access(kind,fs->store->identity,q->mode,!!(q->flags&MD_AT_EACCESS));
        if (r) out->error=r;
        return 1;
    }
    struct md_fs_anchor *origin=NULL;
    if (q->operation==MD_FS_OPEN || q->operation==MD_FS_REOPEN)
        r=md_view_anchor_duplicate(fs,view,mount,fd,&origin);
    struct md_control_file file={0};
    if (!r) {
        file=sysctl ? md_proc_sysctl_new(kind,origin,fs->actor->uts) : md_network_sysctl_new(fs->actor->network,
            (enum md_network_parameter)(ref.kind-MD_PROC_NET_UNPRIVILEGED_PORT),origin);
        if (!file.ops) r=-errno;
    }
    const struct md_identity *id=fs->store->identity;
    if (!r) switch (q->operation) {
    case MD_FS_STAT: case MD_FS_FSTAT: {
        struct stat st;
        r=file.ops->stat(file.context,&st);
        if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        break;
    }
    case MD_FS_ACCESS: {
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS)) { r=-EINVAL; break; }
        if ((q->mode&W_OK) && md_view_readonly(mount)) { r=-EROFS; break; }
        struct md_identity actor=md_identity_access(id,!!(q->flags&MD_AT_EACCESS));
        r=file.ops->access(file.context,&actor,q->mode); break;
    }
    case MD_FS_STATFS:
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        break;
    case MD_FS_OPEN: case MD_FS_REOPEN: {
        if (q->flags&O_DIRECTORY) { r=-ENOTDIR; break; }
        if (q->flags&~(O_ACCMODE|O_CLOEXEC|O_APPEND|O_TRUNC|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW|O_PATH|O_CREAT|O_EXCL|O_LARGEFILE)) {
            r=-EOPNOTSUPP; break;
        }
        if (q->operation==MD_FS_REOPEN && (q->mode&MD_FS_REOPEN_MUTABLE)) { r=-EOPNOTSUPP; break; }
        if (!output || !output->control) { out->requires_control=1; r=-EOPNOTSUPP; break; }
        /* The descriptor host owns all data semantics; never reopen the
         * Android sysctl for read/write merely to supply a carrier. */
        int carrier;
        if (file.ops->descriptor) carrier=file.ops->descriptor(file.context,(int)q->flags);
        else { carrier=open("/dev/null",O_CLOEXEC|(q->flags&~(O_CREAT|O_EXCL|O_TRUNC))); if (carrier<0) carrier=-errno; }
        r=md_fs_control_publish(carrier,file,origin,id,(int)q->flags,out,output);
        break;
    }
    case MD_FS_READLINK: r=-EINVAL; break;
    case MD_FS_GETDENTS: r=-ENOTDIR; break;
    case MD_FS_GETCAP: case MD_FS_GETACL: r=-ENODATA; break;
    default: r=-EOPNOTSUPP; break;
    }
    md_control_file_release(file); md_fs_anchor_release(origin);
    if (r) out->error=r;
    return 1;
}
