#ifndef MD_INODE_OVERLAY_H
#define MD_INODE_OVERLAY_H
#include "inode_store.h"
struct md_identity;

/* An unpublished merged index retains lower data through ordinary source
 * custody. Layers are admitted bottom-to-top, with no file-body copying.
 * Source trees must not be changed while the resulting overlay is mounted. */
int md_inode_overlay_layer(struct md_inode_store *index, struct md_inode_store *source,
        int directory, int user_xattr);
/* Reserves distinct upper/work directories and adds the upper namespace to an
 * unpublished view. Failure requires retiring that view, never publishing it. */
int md_inode_overlay_prepare_upper(struct md_inode_store *, struct md_inode_store *,
        int upper_directory, int work_directory, int user_xattr);
/* Finalizes an unpublished view and enables transactional upper publication. */
int md_inode_overlay_activate(struct md_inode_store *);
/* Call once before publishing a mount. Retained independently of the caller. */
int md_inode_overlay_stash(struct md_inode_store *, const struct md_identity *);
struct mdi_node;
int mdi_overlay_writer_open(struct md_inode_store *);
void mdi_overlay_writer_close(struct md_inode_store *);
int mdi_overlay_flush(struct md_inode_store *);
int mdi_overlay_touch(struct md_inode_store *, const struct mdi_node *);
int mdi_overlay_rename_directory(struct md_inode_store *, const struct mdi_node *);
int mdi_overlay_permission(struct md_inode_store *, const struct mdi_node *, int);
int mdi_overlay_setattr(struct md_inode_store *, const struct mdi_node *, const struct md_fs_request *);
int mdi_overlay_xattr(struct md_inode_store *, const struct mdi_node *, const char *, int);
/* Borrows the writer's underlying store under the current transaction. */
int mdi_overlay_upper(struct md_inode_store *, const struct mdi_node *, struct md_inode_store **,
    struct mdi_node *);
#endif
