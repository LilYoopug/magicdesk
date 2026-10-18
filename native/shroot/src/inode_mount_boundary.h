#ifndef MD_INODE_MOUNT_BOUNDARY_H
#define MD_INODE_MOUNT_BOUNDARY_H
#include <stdint.h>
#include <string.h>
enum { MD_INODE_INITIAL_BOUNDARIES=4 };
/* Immutable after cold launch admission. A small rejection filter keeps the
 * ordinary path independent of the number of implicit provider mounts. */
struct md_inode_mount_boundaries {
    uint64_t filter;
    unsigned count;
    char objects[MD_INODE_INITIAL_BOUNDARIES][33];
};
static inline uint64_t md_inode_mount_bit(const char *id) {
    return UINT64_C(1)<<(((unsigned char)id[0]*17U+(unsigned char)id[1])&63U);
}
static inline int md_inode_mount_contains(const struct md_inode_mount_boundaries *b,const char *id) {
    if (!(b->filter&md_inode_mount_bit(id))) return 0;
    for (unsigned i=0;i<b->count;++i) if (!strcmp(b->objects[i],id)) return 1;
    return 0;
}
#endif
