#ifndef MD_PROCFS_VIEW_H
#define MD_PROCFS_VIEW_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
struct md_filesystem;
struct md_view_mount;
struct md_provider_tree;
struct md_identity;
struct md_provider_tree *md_procfs_new(int parent,const char *options,const struct md_identity *);
int md_procfs_options(const struct md_view_mount *,const struct md_identity *,char *,size_t);
int md_procfs_check(struct md_filesystem *,const struct md_view_mount *,const char *path,unsigned minimum);
int md_procfs_path(const struct md_view_mount *,int,char *,size_t);
/* Mount-scoped proc traversal. Native directory descriptors retain the process
 * dentry while the mount retains the namespace that names it. */
int md_procfs_step(struct md_filesystem *,struct md_view_mount *,int directory,
    const char *name,const char *tail,int follow_final,uint64_t resolve);
ssize_t md_procfs_readlink(struct md_filesystem *,const struct md_view_mount *,int,void *,size_t);
ssize_t md_procfs_getdents(struct md_filesystem *,const struct md_view_mount *,int,void *,size_t);
#endif
