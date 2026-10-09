#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "file_permissions.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <unistd.h>

enum { MD_MQUEUE_MAGIC=0x19800202 };

int md_fs_mqueue_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || mount->backing!=MD_MOUNT_MQUEUE) return 0;
    struct md_mqueue_view *queues=md_ipc_namespace_queues(mount->ipc_namespace,-1);
    if (!queues) { out->error=-ESTALE; return 1; }
    const struct md_identity *id=fs->store->identity;
    int r=0;
    switch (q->operation) {
    case MD_FS_STAT: case MD_FS_FSTAT: {
        struct stat st; r=md_mqueue_stat(queues,fd,&st);
        if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        break;
    }
    case MD_FS_STATFS:
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        if (!out->error) {
            struct md_fs_statfs *st=output->data; st->type=MD_MQUEUE_MAGIC;
            st->blocks=st->free_blocks=st->available_blocks=st->files=st->free_files=0;
        }
        break;
    case MD_FS_ACCESS: {
        struct stat st;
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS)) r=-EINVAL;
        else if ((q->mode&W_OK) && md_view_readonly(mount)) r=-EROFS;
        else r=md_mqueue_stat(queues,fd,&st);
        if (!r) {
            struct md_identity actor=*id;
            if (!(q->flags&MD_AT_EACCESS)) { actor.uid.fs=actor.uid.real; actor.gid.fs=actor.gid.real; }
            r=md_file_permissions(&st,q->mode,&actor);
        }
        break;
    }
    case MD_FS_OPEN: case MD_FS_REOPEN: {
        if (fd<0) { r=(q->flags&O_CREAT) ? -EOPNOTSUPP : -ENOENT; break; }
        if (q->flags&~(O_CLOEXEC|O_DIRECTORY|O_PATH|O_NOFOLLOW|O_NONBLOCK|O_LARGEFILE|O_ACCMODE|O_CREAT|O_EXCL|O_TRUNC)) {
            r=-EOPNOTSUPP; break;
        }
        if (!(q->flags&O_PATH) && (q->flags&(O_ACCMODE|O_CREAT|O_TRUNC))) { r=-EISDIR; break; }
        struct stat st; r=md_mqueue_stat(queues,fd,&st);
        if (!r && !(q->flags&O_PATH)) r=md_file_permissions(&st,R_OK,id);
        if (!r) r=md_reopen_file(fd,(int)q->flags|O_CLOEXEC,&out->open_completion);
        if (r>=0) { out->fd=r; r=0; md_view_capture(fs,view,mount,out,output); }
        break;
    }
    case MD_FS_CHMOD:
        r=md_view_readonly(mount) ? -EROFS : md_mqueue_chmod(queues,fd,q->mode,id); break;
    case MD_FS_CHOWN:
        r=md_view_readonly(mount) ? -EROFS : md_mqueue_chown(queues,fd,q->attributes.uid,q->attributes.gid,id); break;
    case MD_FS_CREATE: case MD_FS_MKDIR: case MD_FS_MKNOD: case MD_FS_SYMLINK:
    case MD_FS_LINK: case MD_FS_UNLINK: case MD_FS_RENAME: case MD_FS_UTIMENS:
    case MD_FS_SETCAP: case MD_FS_REMOVECAP: case MD_FS_SETACL: case MD_FS_REMOVEACL:
        r=md_view_readonly(mount) ? -EROFS : -EOPNOTSUPP; break;
    case MD_FS_OPEN_IMAGE: case MD_FS_SOCKET_BIND: case MD_FS_SOCKET_ADDRESS:
        r=-EOPNOTSUPP; break;
    case MD_FS_GETCAP: case MD_FS_GETACL: r=-ENODATA; break;
    case MD_FS_XATTR_OBJECT:
        r=md_view_readonly(mount) && (q->mode==MD_FS_XATTR_SET || q->mode==MD_FS_XATTR_REMOVE)
            ? -EROFS : -EOPNOTSUPP; break;
    default: return 0;
    }
    if (r) out->error=r;
    return 1;
}
