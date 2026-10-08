#ifndef MD_MOUNT_INSTANCE_H
#define MD_MOUNT_INSTANCE_H
#include "mount_policy.h"
#include <stdatomic.h>
#include <stdint.h>
#include <sys/stat.h>

struct md_inode_lifetime;
enum md_mount_backing { MD_MOUNT_NATIVE, MD_MOUNT_INODE };
/* Stable mount identity, independently of its placement or worker connection. */
struct md_view_mount {
    int source, target;
    struct md_mount_policy policy;
    unsigned id;
    uint64_t generation;
    enum md_mount_backing backing;
    struct md_inode_lifetime *storage;
    int detached, locked;
    atomic_uint anchors;
    struct md_view_mount *parent;
    struct stat native, guest;
};
#endif
