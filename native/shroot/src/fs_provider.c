#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int md_fs_provider_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || !mount->provider) return 0;
    switch (q->operation) {
    case MD_FS_CREATE: case MD_FS_MKDIR: case MD_FS_MKNOD: case MD_FS_SYMLINK:
    case MD_FS_UNLINK: case MD_FS_LINK: case MD_FS_RENAME: case MD_FS_CHMOD:
    case MD_FS_CHOWN: case MD_FS_UTIMENS: case MD_FS_SETCAP: case MD_FS_REMOVECAP:
    case MD_FS_SETACL: case MD_FS_REMOVEACL: case MD_FS_SOCKET_BIND:
        out->error=-EROFS; return 1;
    default: break;
    }
    if (q->operation==MD_FS_STATFS) {
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        unsigned long type=md_provider_tree_filesystem(mount->provider);
        if (!out->error && type) ((struct md_fs_statfs *)output->data)->type=type;
        return 1;
    }
    struct md_control_file file={0};
    int managed=md_provider_tree_control(mount->provider,fd,&file);
    if (managed<0) { out->error=managed; return 1; }
    if (!managed) {
        int private=md_provider_tree_private(mount->provider,fd);
        if (private<0) { out->error=private; return 1; }
        if (private && (q->operation==MD_FS_OPEN || q->operation==MD_FS_REOPEN)
                && !(q->flags&O_PATH) && (q->flags&(O_ACCMODE|O_TRUNC))) {
            out->error=-EROFS; return 1;
        }
        return 0;
    }
    int result=0,handled=1;
    const struct md_identity *id=fs->store->identity;
    switch (q->operation) {
    case MD_FS_STAT: case MD_FS_FSTAT: {
        struct stat st; result=file.ops->stat(file.context,&st);
        if (!result) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        break;
    }
    case MD_FS_ACCESS:
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS) || q->mode&~7U) result=-EINVAL;
        else result=file.ops->access(file.context,id,q->mode);
        break;
    case MD_FS_OPEN: case MD_FS_REOPEN: {
        unsigned flags=q->flags;
        if (!(flags&O_PATH) && (md_mount_policy_flags(&mount->policy)&MD_MOUNT_NODEV)) { result=-EACCES; break; }
        if (!(flags&O_PATH) && (flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) { result=-EEXIST; break; }
        if (flags&(O_DIRECTORY|O_TRUNC) || (flags&O_ACCMODE)==O_ACCMODE) { result=-EINVAL; break; }
        if (!(flags&O_PATH) && (flags&O_ACCMODE) && md_view_readonly(mount)) { result=-EROFS; break; }
        if (!output || !output->control) { out->requires_control=1; result=-EOPNOTSUPP; break; }
        int copy=fcntl(fd,F_DUPFD_CLOEXEC,3);
        if (copy<0) { result=-errno; break; }
        struct stat st;
        if (fstat(fd,&st)) { result=-errno; close(copy); break; }
        struct md_fs_anchor *origin=md_view_anchor_new(md_inode_store_lifetime(fs->store),view,mount,copy,st.st_dev,st.st_ino);
        if (!origin) { result=-errno; close(copy); break; }
        int carrier=fcntl(fd,F_DUPFD_CLOEXEC,3);
        if (carrier<0) result=-errno;
        else {
            result=output->control(output->control_context,file.ops,file.context,id,(int)flags);
            if (result) close(carrier);
            else { out->fd=carrier; if (output->origin) *output->origin=md_fs_anchor_retain(origin); }
        }
        md_fs_anchor_release(origin); break;
    }
    case MD_FS_GETCAP: case MD_FS_GETACL: result=-ENODATA; break;
    case MD_FS_XATTR_OBJECT:
        result=q->mode==MD_FS_XATTR_LIST ? 0 : q->mode==MD_FS_XATTR_GET ? -ENODATA : -EROFS;
        break;
    case MD_FS_PATH: case MD_FS_OBJECT_ID: handled=0; break;
    default: result=-EOPNOTSUPP; break;
    }
    md_control_file_release(file);
    if (result) out->error=result;
    return handled;
}
