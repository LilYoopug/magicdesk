#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "network_namespace.h"
#include "proc_paths.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int md_fs_proc_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || mount->backing!=MD_MOUNT_PROC || fd<0 || !fs->actor
            || !md_network_namespace_managed(fs->actor->network)) return 0;
    char path[PATH_MAX];
    int r=md_view_fdpath(fd,path,sizeof(path));
    if (r) { out->error=r; return 1; }
    struct md_proc_path ref=md_proc_path_for(path,0,0);
    if (!md_proc_network_sysctl(ref.kind)) return 0;
    if (q->operation==MD_FS_PATH || q->operation==MD_FS_OBJECT_ID) return 0;
    struct md_fs_anchor *origin=NULL;
    if (q->operation==MD_FS_OPEN || q->operation==MD_FS_REOPEN) {
        struct stat st;
        if (fstat(fd,&st)) r=-errno;
        int copy=r ? -1 : fcntl(fd,F_DUPFD_CLOEXEC,3);
        if (!r && copy<0) r=-errno;
        if (!r) {
            origin=md_view_anchor_new(md_inode_store_lifetime(fs->store),view,mount,copy,st.st_dev,st.st_ino);
            if (!origin) { r=-errno; close(copy); }
        }
    }
    struct md_control_file file={0};
    if (!r) {
        file=md_network_sysctl_new(fs->actor->network,
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
        struct md_identity actor=*id;
        if (!(q->flags&MD_AT_EACCESS)) { actor.uid.fs=actor.uid.real; actor.gid.fs=actor.gid.real; }
        r=file.ops->access(file.context,&actor,q->mode); break;
    }
    case MD_FS_STATFS:
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        break;
    case MD_FS_OPEN: case MD_FS_REOPEN: {
        if (q->flags&O_DIRECTORY) { r=-ENOTDIR; break; }
        if (q->flags&~(O_ACCMODE|O_CLOEXEC|O_APPEND|O_TRUNC|O_NONBLOCK|O_NOFOLLOW|O_PATH|O_CREAT|O_EXCL|O_LARGEFILE)) {
            r=-EOPNOTSUPP; break;
        }
        if (q->operation==MD_FS_REOPEN && (q->mode&MD_FS_REOPEN_MUTABLE)) { r=-EOPNOTSUPP; break; }
        if (!output || !output->control) { out->requires_control=1; r=-EOPNOTSUPP; break; }
        r=output->control(output->control_context,file.ops,file.context,id,(int)q->flags);
        if (!r) {
            /* The descriptor host owns all data semantics; never reopen the
             * Android sysctl for read/write merely to supply a carrier. */
            out->fd=open("/dev/null",O_CLOEXEC|(q->flags&~(O_CREAT|O_EXCL|O_TRUNC)));
            if (out->fd<0) r=-errno;
        }
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
