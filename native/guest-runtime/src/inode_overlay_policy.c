#include "inode_internal.h"
#include "inode_overlay.h"
#include "fs_operation.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int md_inode_overlay_stash(struct md_inode_store *s, const struct md_identity *id) {
    if (!s || !id || s->lifetime->filesystem_kind!=MD_FILESYSTEM_OVERLAY
            || s->lifetime->overlay_identity) return -EINVAL;
    struct md_identity *copy=malloc(sizeof(*copy));
    if (!copy) return -ENOMEM;
    *copy=md_identity_copy(id);
    md_user_namespace_release(s->lifetime->owner);
    s->lifetime->owner=md_user_namespace_retain(id->user_namespace);
    s->lifetime->overlay_identity=copy;
    return 0;
}
int mdi_overlay_permission(struct md_inode_store *s, const struct mdi_node *node, int mode) {
    const struct md_identity *id=s->lifetime->overlay_identity;
    if (!id || !mode) return 0;
    struct md_inode_store *underlying=s;
    struct mdi_node real;
    int found=mdi_overlay_upper(s,node,&underlying,&real);
    if (found<0) return found;
    if (!found) {
        real=*node;
        if ((mode&W_OK) && (node->kind==S_IFREG || node->kind==S_IFDIR || node->kind==S_IFLNK))
            mode=(mode&~W_OK)|R_OK;
    }
    return mdi_permission_as(underlying,&real,mode,id);
}
int mdi_overlay_setattr(struct md_inode_store *s, const struct mdi_node *node,
        const struct md_fs_request *q) {
    const struct md_identity *id=s->lifetime->overlay_identity;
    if (!id) return 0;
    struct md_inode_store *underlying=s;
    struct mdi_node real;
    int found=mdi_overlay_upper(s,node,&underlying,&real);
    if (found<0) return found;
    return mdi_setattr_permission(underlying,found ? &real : node,q,id);
}
int mdi_overlay_xattr(struct md_inode_store *s, const struct mdi_node *node,
        const char *name, int mode) {
    const struct md_identity *id=s->lifetime->overlay_identity;
    if (!id) return 0;
    struct md_inode_store *underlying=s;
    struct mdi_node real;
    int found=mdi_overlay_upper(s,node,&underlying,&real);
    if (found<0) return found;
    return mdi_xattr_permission_as(underlying,found ? &real : node,name,mode,id);
}
