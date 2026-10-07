#ifndef MD_MOUNT_TOPOLOGY_H
#define MD_MOUNT_TOPOLOGY_H
#include "fs_mounts.h"

/* Zero is a terminal parent; other values are one-based node numbers.
 * Namespace node zero is the base, other nodes are one-based attachment slots.
 * The output includes every node, including the base and retired slots. */
int md_mount_topology_order(unsigned count, const unsigned *parents, unsigned *order);
struct md_fs_mounts;
struct md_mount_namespace;
int md_view_topology_order(const struct md_mount_namespace *, unsigned *order);
#endif
