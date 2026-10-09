#ifndef MD_SYSFS_VIEW_H
#define MD_SYSFS_VIEW_H
#include "network_namespace.h"
#include "control_file.h"

struct md_sysfs;
/* A mount retains its network view, not the caller's current namespace. */
struct md_sysfs *md_sysfs_new(int parent,struct md_network_namespace *,const struct md_identity *);
struct md_sysfs *md_sysfs_retain(struct md_sysfs *);
void md_sysfs_release(struct md_sysfs *);
int md_sysfs_root(const struct md_sysfs *);
int md_sysfs_stat(const struct md_sysfs *,int fd,struct stat *);
int md_sysfs_open(struct md_sysfs *,int fd,int flags,const struct md_identity *,
    struct md_fs_anchor *,const struct md_control_file_ops **,void **);
#endif
