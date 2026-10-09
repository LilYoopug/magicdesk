#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "file_permissions.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int md_fs_cgroup_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,int parent,const char *name,
        const struct md_fs_request *q,struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || !mount->cgroup) return 0;
    struct md_cgroup_view *groups=mount->cgroup;
    const struct md_identity *id=fs->store->identity;
    int r=0;
    switch (q->operation) {
    case MD_FS_STAT: case MD_FS_FSTAT: {
        struct stat st; r=md_cgroup_stat(groups,fd,&st);
        if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        break;
    }
    case MD_FS_ACCESS: {
        struct stat st;
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS)) r=-EINVAL;
        else if ((q->mode&W_OK) && md_view_readonly(mount)) r=-EROFS;
        else r=md_cgroup_stat(groups,fd,&st);
        if (!r) {
            struct md_identity actor=*id;
            if (!(q->flags&MD_AT_EACCESS)) { actor.uid.fs=actor.uid.real; actor.gid.fs=actor.gid.real; }
            r=md_file_permissions(&st,q->mode,&actor);
        }
        break;
    }
    case MD_FS_STATFS:
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        if (!out->error) {
            struct md_fs_statfs *st=output->data;
            st->type=md_cgroup_filesystem(groups);
            st->blocks=st->free_blocks=st->available_blocks=st->files=st->free_files=0;
        }
        break;
    case MD_FS_OPEN: case MD_FS_REOPEN: {
        if (fd<0) { r=-ENOENT; break; }
        if (q->flags&~(O_ACCMODE|O_CLOEXEC|O_APPEND|O_TRUNC|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY|O_PATH|O_CREAT|O_EXCL|O_LARGEFILE)) {
            r=-EOPNOTSUPP; break;
        }
        if ((q->flags&O_ACCMODE)==O_ACCMODE) { r=-EINVAL; break; }
        if (!(q->flags&O_PATH) && (q->flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) { r=-EEXIST; break; }
        if (!(q->flags&O_PATH) && (q->flags&(O_ACCMODE|O_TRUNC)) && md_view_readonly(mount)) { r=-EROFS; break; }
        struct stat st;
        if (fstat(fd,&st)) { r=-errno; break; }
        int copy=fcntl(fd,F_DUPFD_CLOEXEC,3);
        if (copy<0) { r=-errno; break; }
        struct md_fs_anchor *origin=md_view_anchor_new(md_inode_store_lifetime(fs->store),view,mount,copy,st.st_dev,st.st_ino);
        if (!origin) { r=-errno; close(copy); break; }
        const struct md_control_file_ops *ops=NULL; void *context=NULL;
        r=md_cgroup_open(groups,fd,(int)q->flags,id,origin,&ops,&context);
        if (!r && ops && (!output || !output->control)) { out->requires_control=1; r=-EOPNOTSUPP; }
        if (!r) {
            r=md_reopen_file(fd,(int)(q->flags&~(O_CREAT|O_EXCL|O_TRUNC))|O_CLOEXEC,&out->open_completion);
            if (r>=0) {
                out->fd=r; r=ops ? output->control(output->control_context,ops,context,id,(int)q->flags) : 0;
                if (r) { close(out->fd); out->fd=-1; }
                else if (output && output->origin) *output->origin=md_fs_anchor_retain(origin);
            }
        }
        if (ops) ops->release(context);
        md_fs_anchor_release(origin); break;
    }
    case MD_FS_MKDIR:
        r=md_view_readonly(mount) ? -EROFS : md_cgroup_mkdir(groups,parent,name,id); break;
    case MD_FS_UNLINK:
        r=md_view_readonly(mount) ? -EROFS : q->flags==AT_REMOVEDIR
            ? md_cgroup_rmdir(groups,parent,name,id) : -EPERM; break;
    case MD_FS_CREATE: case MD_FS_MKNOD: case MD_FS_SYMLINK: case MD_FS_LINK:
    case MD_FS_RENAME: case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
    case MD_FS_OPEN_IMAGE: case MD_FS_SOCKET_BIND: case MD_FS_SOCKET_ADDRESS:
    case MD_FS_SETCAP: case MD_FS_REMOVECAP: case MD_FS_SETACL: case MD_FS_REMOVEACL:
        r=-EOPNOTSUPP; break;
    default: return 0;
    }
    if (r) out->error=r;
    return 1;
}
