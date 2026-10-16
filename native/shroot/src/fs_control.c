#define _GNU_SOURCE
#include "fs_control.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "file_permissions.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int md_fs_control_publish(int carrier,struct md_control_file file,struct md_fs_anchor *origin,
        const struct md_identity *identity,int flags,struct md_fs_result *out,const struct md_fs_output *output) {
    if (carrier<0) return carrier;
    int error=0;
    if (file.ops) {
        if (!output || !output->control) { out->requires_control=1; error=-EOPNOTSUPP; }
        else error=output->control(output->control_context,file.ops,file.context,identity,flags);
    }
    if (error) close(carrier);
    else {
        out->fd=carrier;
        if (output && output->origin) *output->origin=md_fs_anchor_retain(origin);
    }
    return error;
}
static int control_open(struct md_filesystem *fs,struct md_mount_namespace *view,struct md_view_mount *mount,
        int fd,int flags,md_fs_control_opener open,void *context,struct md_fs_result *out,const struct md_fs_output *output) {
    struct md_fs_anchor *origin=NULL;
    int error=md_view_anchor_duplicate(fs,view,mount,fd,&origin);
    if (error) return error;
    struct md_control_file file={0};
    const struct md_identity *identity=fs->store->identity;
    error=open(context,fd,flags,identity,origin,&file);
    if (!error && file.ops && (!output || !output->control)) { out->requires_control=1; error=-EOPNOTSUPP; }
    if (!error) {
        int native_flags=flags&~(O_CREAT|O_EXCL|O_TRUNC);
        if (file.ops) native_flags&=~O_NOATIME;
        int carrier=md_reopen_file(fd,native_flags|O_CLOEXEC,&out->open_completion);
        error=md_fs_control_publish(carrier,file,origin,identity,flags,out,output);
    }
    md_control_file_release(file);
    md_fs_anchor_release(origin);
    return error;
}
int md_fs_control_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_control_source *source,
        const struct md_fs_request *q,struct md_fs_result *out,const struct md_fs_output *output) {
    int r=0;
    switch (q->operation) {
    case MD_FS_SYNC: r=q->mode==MD_INODE_SYNC_FILESYSTEM ? 0 : -EINVAL; break;
    case MD_FS_STAT: case MD_FS_FSTAT: {
        struct stat st; r=source->stat(source->context,fd,&st);
        if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        break;
    }
    case MD_FS_ACCESS: {
        struct stat st;
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS)) r=-EINVAL;
        else if ((q->mode&W_OK) && md_view_readonly(mount)) r=-EROFS;
        else r=source->stat(source->context,fd,&st);
        if (!r) {
            struct md_identity actor=md_identity_access(fs->store->identity,!!(q->flags&MD_AT_EACCESS));
            r=md_file_permissions(&st,q->mode,&actor);
        }
        break;
    }
    case MD_FS_STATFS:
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        if (!out->error) {
            struct md_fs_statfs *st=output->data; st->type=source->filesystem;
            st->blocks=st->free_blocks=st->available_blocks=st->files=st->free_files=0;
        }
        break;
    case MD_FS_OPEN: case MD_FS_REOPEN:
        if (fd<0) { r=-ENOENT; break; }
        if (q->flags&~(O_ACCMODE|O_CLOEXEC|O_APPEND|O_TRUNC|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW|O_DIRECTORY|O_PATH|O_CREAT|O_EXCL|O_LARGEFILE|O_NOATIME)) {
            r=-EOPNOTSUPP; break;
        }
        if ((q->flags&O_ACCMODE)==O_ACCMODE) { r=-EINVAL; break; }
        if (!(q->flags&O_PATH) && (q->flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) { r=-EEXIST; break; }
        if (!(q->flags&O_PATH) && (q->flags&(O_ACCMODE|O_TRUNC)) && md_view_readonly(mount)) { r=-EROFS; break; }
        r=control_open(fs,view,mount,fd,(int)q->flags,source->open,source->context,out,output);
        break;
    default: return 0;
    }
    if (r) out->error=r;
    return 1;
}
