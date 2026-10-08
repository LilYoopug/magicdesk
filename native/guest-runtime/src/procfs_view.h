#ifndef MD_PROCFS_VIEW_H
#define MD_PROCFS_VIEW_H
#include <stddef.h>
#include <sys/types.h>
struct md_filesystem;
struct md_view_mount;
/* Mount-scoped proc traversal. Native directory descriptors retain the process
 * dentry while the mount retains the namespace that names it. */
int md_procfs_step(struct md_filesystem *,struct md_view_mount *,int directory,
    const char *name,const char *tail,int follow);
ssize_t md_procfs_readlink(struct md_filesystem *,const struct md_view_mount *,int,void *,size_t);
ssize_t md_procfs_getdents(const struct md_view_mount *,int,void *,size_t);
#endif
