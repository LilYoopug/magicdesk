#ifndef MD_MOUNT_SOURCE_H
#define MD_MOUNT_SOURCE_H
#include "mount_instance.h"
struct md_filesystem;
struct md_fs_request;
/* An unplaced filesystem owns its root and provider, not a mount namespace.
 * Both mount ABIs attach this same prepared source through the mount engine. */
struct md_mount_source {
    int fd;
    unsigned policy;
    enum md_mount_backing backing;
    struct md_inode_lifetime *storage;
    struct md_pid_namespace *pid;
    struct md_devpts *devpts;
    struct md_cgroup_view *cgroup;
    struct md_sysfs *sysfs;
    struct md_provider_tree *provider;
    struct md_ipc_namespace *ipc;
};
void md_mount_source_close(struct md_mount_source *);
int md_mount_source_create(struct md_filesystem *,const struct md_fs_request *,struct md_mount_source *);
#endif
