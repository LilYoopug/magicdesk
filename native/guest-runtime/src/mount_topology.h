#ifndef MD_MOUNT_TOPOLOGY_H
#define MD_MOUNT_TOPOLOGY_H
#include "fs_mounts.h"

/* Stable slot numbers are identities, not traversal order. Zero denotes the
 * base mount; other parents are one-based slot numbers. No allocation occurs. */
int md_mount_topology_order(unsigned count, const unsigned *parents, unsigned *order);
struct md_fs_mounts;
int md_view_topology_order(const struct md_fs_mounts *, unsigned *order);
#endif
