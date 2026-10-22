#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_control.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

struct selected_cgroup { struct md_cgroup_view *view; struct md_cgroup_namespace *namespace; };
static int prepare_open(void *context,int fd,int flags,const struct md_identity *id,
        struct md_fs_anchor *origin,struct md_control_file *file) {
    struct selected_cgroup *selected=context;
    return md_cgroup_open(selected->view,fd,flags,id,selected->namespace,origin,&file->ops,&file->context);
}
static int metadata(void *context,int fd,struct stat *out) {
    return md_cgroup_stat(((struct selected_cgroup *)context)->view,fd,out);
}

int md_fs_cgroup_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,int parent,const char *name,
        const struct md_fs_request *q,struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || !mount->cgroup) return 0;
    struct md_cgroup_view *groups=mount->cgroup;
    struct selected_cgroup selected={groups,fs->actor ? fs->actor->cgroup_namespace : NULL};
    const struct md_fs_control_source source={&selected,metadata,prepare_open,md_cgroup_filesystem(groups)};
    if (md_fs_control_operation(fs,view,mount,fd,&source,q,out,output)) return 1;
    const struct md_identity *id=fs->store->identity;
    int r=0;
    switch (q->operation) {
    case MD_FS_MKDIR:
        r=md_view_readonly(mount) ? -EROFS : md_cgroup_mkdir(groups,parent,name,id); break;
    case MD_FS_UNLINK:
        r=md_view_readonly(mount) ? -EROFS : q->flags==AT_REMOVEDIR
            ? md_cgroup_rmdir(groups,parent,name,id) : -EPERM; break;
    case MD_FS_CHMOD:
        r=md_view_readonly(mount) ? -EROFS : md_cgroup_chmod(groups,fd,q->mode,id); break;
    case MD_FS_CHOWN:
        r=md_view_readonly(mount) ? -EROFS : md_cgroup_chown(groups,fd,q->attributes.uid,q->attributes.gid,id); break;
    case MD_FS_CREATE: case MD_FS_MKNOD: case MD_FS_SYMLINK: case MD_FS_LINK:
    case MD_FS_RENAME: case MD_FS_UTIMENS:
    case MD_FS_OPEN_IMAGE: case MD_FS_SOCKET_BIND: case MD_FS_SOCKET_ADDRESS:
    case MD_FS_SETCAP: case MD_FS_REMOVECAP: case MD_FS_SETACL: case MD_FS_REMOVEACL:
        r=-EOPNOTSUPP; break;
    default: return 0;
    }
    if (r) out->error=r;
    return 1;
}
