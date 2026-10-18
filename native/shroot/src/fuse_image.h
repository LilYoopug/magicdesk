#ifndef MD_FUSE_IMAGE_H
#define MD_FUSE_IMAGE_H
#include "fuse_session.h"
struct md_fuse_image;
int md_fuse_image_same(const struct fuse_attr *,const struct fuse_attr *);
/* Executable acquisition owns an immutable image, not a page-cache substitute.
 * Ordinary file reads and shared mappings never use this snapshot. */
int md_fuse_image_new(struct md_fuse_session *,const struct md_identity *,uint32_t,
    uint64_t node,uint64_t handle,const struct fuse_attr *,struct md_fuse_image **);
int md_fuse_image_ready(struct md_fuse_image *);
/* Transfers one sealed readable FD when complete; otherwise negative errno. */
int md_fuse_image_advance(struct md_fuse_image *,struct md_resource_wakeup *);
void md_fuse_image_destroy(struct md_fuse_image *);
#endif
