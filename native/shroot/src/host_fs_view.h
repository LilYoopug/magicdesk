#ifndef MD_HOST_FS_VIEW_H
#define MD_HOST_FS_VIEW_H
struct md_provider_tree;
struct stat;
enum md_host_fs_view { MD_HOST_FS_NONE, MD_HOST_FS_SYS, MD_HOST_FS_DEV, MD_HOST_FS_DEVICES };
struct md_provider_tree *md_host_fs_new(int parent,enum md_host_fs_view);
struct md_provider_tree *md_host_fs_import(int upper,enum md_host_fs_view);
enum md_host_fs_view md_host_fs_kind(const struct md_provider_tree *);
/* 1 for projected private directories, 0 for native/typed nodes, or -errno. */
int md_host_fs_stat(struct md_provider_tree *,int fd,struct stat *);
#endif
