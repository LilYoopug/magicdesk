#ifndef MD_FUSE_MAPPING_H
#define MD_FUSE_MAPPING_H
#include <stddef.h>
#include <stdint.h>
struct md_fuse_mapping;
/* The FUSE view lock serializes publication and confirmed mutations. Only
 * read-only descriptions leave this owner; no writeback capability is claimed. */
int md_fuse_mapping_publish(struct md_fuse_mapping **,int directory,int image);
int md_fuse_mapping_write(struct md_fuse_mapping *,const void *,size_t,int64_t);
int md_fuse_mapping_resize(struct md_fuse_mapping *,int64_t);
void md_fuse_mapping_destroy(struct md_fuse_mapping *);
#endif
