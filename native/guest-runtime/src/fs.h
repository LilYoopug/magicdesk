#ifndef MD_FS_H
#define MD_FS_H
#include <linux/limits.h>
#include "proc_paths.h"
struct md_process_image;
struct md_socket_routes;
struct md_fs {
    char root[PATH_MAX];
    char endpoint[108];
    const struct md_process_image *image;
    const struct md_socket_routes *connections;
    int managed_paths;
};
static inline int md_fs_host_path(const struct md_fs *fs, const char *path) {
    return !fs->managed_paths && md_host_path(path);
}
enum md_path_follow { MD_PATH_NOFOLLOW, MD_PATH_FOLLOW, MD_PATH_ENTRY };
int md_fs_guest(const struct md_fs *, const char *, char *);
int md_fs_resolve(const struct md_fs *, int, const char *, int, char *);
#endif
