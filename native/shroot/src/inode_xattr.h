#ifndef MD_INODE_XATTR_H
#define MD_INODE_XATTR_H
#include <stddef.h>
#include <sys/types.h>
struct md_inode_store;
struct mdi_node;
/* These helpers borrow the caller's inode transaction. Control attributes are
 * namespace metadata; a NULL value is a tombstone masking a native attribute. */
int mdi_overlay_attribute(const char *);
int mdi_overlay_private_attribute(const char *);
int mdi_overlay_attribute_set(struct md_inode_store *, const struct mdi_node *, const char *, const void *, size_t);
int mdi_overlay_attributes_copy(struct md_inode_store *target, const struct mdi_node *, struct md_inode_store *source, const struct mdi_node *);
ssize_t mdi_xattr_get(struct md_inode_store *, const struct mdi_node *, const char *, void *, size_t);
ssize_t mdi_xattr_names(struct md_inode_store *, const struct mdi_node *, void *, size_t, int internal);
#endif
