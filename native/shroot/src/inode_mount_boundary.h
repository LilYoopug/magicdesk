#ifndef MD_INODE_MOUNT_BOUNDARY_H
#define MD_INODE_MOUNT_BOUNDARY_H
#include <stdint.h>
/* The mount owner supplies an exact lookup behind a cheap rejection filter.
 * Native backing identity also covers leaves without a catalogue object. */
struct mdi_mount_boundary {
    uint64_t filter;
    void *context;
    int (*contains)(void *,uint64_t device,uint64_t inode);
    int crossed;
};
static inline uint64_t md_inode_mount_bit(uint64_t device,uint64_t inode) {
    uint64_t hash=inode^(device*UINT64_C(0x9e3779b97f4a7c15));
    hash^=hash>>33;
    return UINT64_C(1)<<(hash&63U);
}
static inline int md_inode_mount_contains(struct mdi_mount_boundary *b,uint64_t device,uint64_t inode) {
    if (!(b->filter&md_inode_mount_bit(device,inode)) || !b->contains(b->context,device,inode)) return 0;
    b->crossed=1; return 1;
}
#endif
