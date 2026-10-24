#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_control.h"
#include "host_fs_view.h"
#include "render_device.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <unistd.h>
#include <string.h>

int md_fs_sysfs_prepare(struct md_filesystem *fs,struct md_provider_tree **out) {
    *out=NULL;
    int initial=!md_mount_namespace_attached(fs->mounts) && !md_mount_namespace_managed_paths(fs->mounts);
    int parent=md_fs_private_mounts_parent(fs->store);
    if (parent<0) return parent;
    struct md_provider_tree *tree=md_host_fs_new(parent,MD_HOST_FS_SYS);
    int error=tree ? 0 : -errno;
    close(parent);
    if (!error && fs->render_device.ops) error=md_render_device_sysfs(fs->render_device,md_provider_tree_root(tree));
    if (!error) error=md_fs_provider_mount(fs,tree,"/sys");
    if (!error && initial) {
        /* /sys never used proc/dev's native passthrough. Preparing only
         * this provider must not disable that existing launch contract. */
        atomic_store_explicit(&fs->mounts->managed_paths,0,memory_order_release);
    }
    if (error) md_provider_tree_release(tree);
    else *out=tree;
    return error;
}

struct selected_node { struct md_sysfs *view; struct md_sysfs_node value; };
static int prepare_open(void *context,int fd,int flags,const struct md_identity *id,
        struct md_fs_anchor *origin,struct md_control_file *file) {
    (void)fd;
    struct selected_node *node=context;
    return md_sysfs_node_open(node->view,&node->value,flags,id,origin,&file->ops,&file->context);
}
static int metadata(void *context,int fd,struct stat *out) {
    (void)fd;
    struct selected_node *node=context;
    *out=node->value.stat; return 0;
}

int md_fs_sysfs_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || !mount->sysfs) return 0;
    struct selected_node node={.view=mount->sysfs};
    if (fd>=0) {
        int error=md_sysfs_node(mount->sysfs,fd,&node.value);
        if (error==-EXDEV) return 0;
        if (error) { out->error=error; return 1; }
    }
    if (q->operation==MD_FS_REOPEN && fd>=0 && (q->mode&MD_FS_REOPEN_MUTABLE)) {
        out->error=md_view_readonly(mount) ? -EROFS : -EOPNOTSUPP; return 1;
    }
    const struct md_fs_control_source source={&node,metadata,prepare_open,SYSFS_MAGIC};
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
