#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int md_fs_mount_file_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || !mount->file.ops) return 0;
    struct md_control_file file=mount->file;
    const struct md_identity *id=fs->store->identity;
    int r=0;
    switch (q->operation) {
    case MD_FS_STAT: case MD_FS_FSTAT: {
        struct stat st; r=file.ops->stat(file.context,&st);
        if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        break;
    }
    case MD_FS_STATFS:
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        if (!out->error) {
            struct md_fs_statfs *st=output->data;
            st->type=file.ops->filesystem;
            st->blocks=st->free_blocks=st->available_blocks=st->files=st->free_files=0;
        }
        break;
    case MD_FS_ACCESS:
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS)) r=-EINVAL;
        else {
            struct md_identity actor=*id;
            if (!(q->flags&MD_AT_EACCESS)) { actor.uid.fs=actor.uid.real; actor.gid.fs=actor.gid.real; }
            r=file.ops->access(file.context,&actor,q->mode);
        }
        break;
    case MD_FS_OPEN: case MD_FS_REOPEN: {
        if (!(q->flags&O_PATH) && (q->flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) { r=-EEXIST; break; }
        if (q->flags&O_DIRECTORY) { r=-ENOTDIR; break; }
        if (!output || !output->control) { out->requires_control=1; r=-EOPNOTSUPP; break; }
        struct stat st;
        if (fstat(fd,&st)) { r=-errno; break; }
        int pin=fcntl(fd,F_DUPFD_CLOEXEC,3);
        if (pin<0) { r=-errno; break; }
        struct md_fs_anchor *origin=md_view_anchor_new(md_inode_store_lifetime(fs->store),view,mount,pin,st.st_dev,st.st_ino);
        if (!origin) { r=-errno; close(pin); break; }
        void *context=file.ops->at(file.context,origin);
        if (!context) r=-errno;
        else {
            r=output->control(output->control_context,file.ops,context,id,(int)q->flags);
            if (!r) {
                int opened=file.ops->descriptor(context,(int)q->flags);
                if (opened<0) r=opened;
                else {
                    out->fd=opened;
                    if (output->origin) *output->origin=md_fs_anchor_retain(origin);
                }
            }
            file.ops->release(context);
        }
        md_fs_anchor_release(origin); break;
    }
    case MD_FS_READLINK: r=-EINVAL; break;
    case MD_FS_GETDENTS: r=-ENOTDIR; break;
    case MD_FS_SEEKDIR: r=-ESPIPE; break;
    case MD_FS_OPEN_IMAGE: r=-EACCES; break;
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
    case MD_FS_SETCAP: case MD_FS_REMOVECAP: case MD_FS_SETACL: case MD_FS_REMOVEACL:
    case MD_FS_XATTR_OBJECT: r=-EOPNOTSUPP; break;
    case MD_FS_GETCAP: case MD_FS_GETACL: r=-ENODATA; break;
    case MD_FS_SOCKET_BIND: case MD_FS_SOCKET_ADDRESS: r=-ENOTSOCK; break;
    default: return 0;
    }
    if (r) out->error=r;
    return 1;
}
