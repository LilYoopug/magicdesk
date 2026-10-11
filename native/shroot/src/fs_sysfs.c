#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_control.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <unistd.h>

static int prepare_open(void *context,int fd,int flags,const struct md_identity *id,
        struct md_fs_anchor *origin,struct md_control_file *file) {
    return md_sysfs_open(context,fd,flags,id,origin,&file->ops,&file->context);
}
static int metadata(void *context,int fd,struct stat *out) { return md_sysfs_stat(context,fd,out); }

int md_fs_sysfs_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || !mount->sysfs) return 0;
    struct md_sysfs *sysfs=mount->sysfs;
    if (q->operation==MD_FS_REOPEN && fd>=0 && (q->mode&MD_FS_REOPEN_MUTABLE)) {
        out->error=md_view_readonly(mount) ? -EROFS : -EOPNOTSUPP; return 1;
    }
    const struct md_fs_control_source source={sysfs,metadata,prepare_open,SYSFS_MAGIC};
    if (md_fs_control_operation(fs,view,mount,fd,&source,q,out,output)) return 1;
    int r=0;
    switch (q->operation) {
    case MD_FS_MKDIR: case MD_FS_CREATE: case MD_FS_MKNOD: case MD_FS_SYMLINK:
        r=fd>=0 ? -EEXIST : md_view_readonly(mount) ? -EROFS : -EOPNOTSUPP; break;
    case MD_FS_UNLINK: case MD_FS_LINK: case MD_FS_RENAME: case MD_FS_CHMOD:
    case MD_FS_CHOWN: case MD_FS_UTIMENS: case MD_FS_SETCAP: case MD_FS_REMOVECAP:
    case MD_FS_SETACL: case MD_FS_REMOVEACL:
        r=md_view_readonly(mount) ? -EROFS : -EOPNOTSUPP; break;
    case MD_FS_OPEN_IMAGE: case MD_FS_SOCKET_BIND: case MD_FS_SOCKET_ADDRESS:
        r=-EOPNOTSUPP; break;
    case MD_FS_GETCAP: case MD_FS_GETACL: r=-ENODATA; break;
    case MD_FS_XATTR_OBJECT:
        r=(q->mode==MD_FS_XATTR_SET || q->mode==MD_FS_XATTR_REMOVE)
            ? md_view_readonly(mount) ? -EROFS : -EOPNOTSUPP : -ENOTSUP; break;
    default: return 0;
    }
    if (r) out->error=r;
    return 1;
}
