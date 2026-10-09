#ifndef MD_MOUNT_INSTANCE_H
#define MD_MOUNT_INSTANCE_H
#include "mount_policy.h"
#include "control_file.h"
#include <stdatomic.h>
#include <stdint.h>
#include <sys/stat.h>

struct md_inode_lifetime;
enum md_mount_backing { MD_MOUNT_NATIVE, MD_MOUNT_INODE, MD_MOUNT_PROC, MD_MOUNT_DEVPTS, MD_MOUNT_CGROUP, MD_MOUNT_SYSFS, MD_MOUNT_MQUEUE };
/* Stable mount identity, independently of its placement or worker connection. */
struct md_view_mount {
    int source, target;
    struct md_mount_policy policy;
    unsigned id;
    uint64_t generation;
    enum md_mount_backing backing;
    struct md_inode_lifetime *storage;
    struct md_pid_namespace *pid_namespace;
    struct md_devpts *devpts;
    struct md_cgroup_view *cgroup;
    struct md_sysfs *sysfs;
    struct md_ipc_namespace *ipc_namespace;
    struct md_control_file file;
    int detached, locked;
    /* Implicit launch providers retained by a root moved through pivot_root. */
    int root_providers;
    atomic_uint anchors;
    struct md_view_mount *parent;
    struct stat native, guest;
};
#endif
