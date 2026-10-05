#ifndef MD_FS_MOUNT_INTERNAL_H
#define MD_FS_MOUNT_INTERNAL_H
#include "fs_mounts.h"
#include <limits.h>
#include <stdatomic.h>

enum { MD_VIEW_BUCKETS = 4096, MD_VIEW_OBJECT_LIMIT = 65536 };
/* A mount owns its source and covered dentry. Its parent is a mount, not an
 * inode: walking out of a mounted root must return to that particular view. */
struct md_view_mount {
    int source, target, readonly;
    unsigned id;
    struct md_view_mount *parent;
    struct stat native, guest;
};
struct md_view_object {
    struct md_view_object *next, *id_next;
    struct stat identity;
    int fd;
    /* The object key is (mount, native device, native inode), not inode alone. */
    struct md_view_mount *mount;
    char id[33];
};
struct md_fs_mounts {
    unsigned count, objects;
    struct md_view_mount mounts[MD_FS_MOUNTS_MAX];
    struct md_view_object *table[MD_VIEW_BUCKETS];
    struct md_view_object *by_id[MD_VIEW_BUCKETS];
};
struct md_mount_namespace {
    atomic_uint refs;
    unsigned root_id, shm_id;
    struct md_fs_mounts *tree;
    struct md_mount_identity *native_ids;
};
struct md_view_location {
    int parent, fd, boundary;
    struct md_mount_namespace *view;
    struct md_view_mount *mount;
    char name[NAME_MAX+1];
};
struct md_fs_anchor {
    atomic_uint refs;
    struct md_inode_store *store;
    struct md_mount_namespace *view;
    struct md_view_mount *mount;
    int fd;
    dev_t device;
    ino_t inode;
};
int md_view_same(const struct stat *, const struct stat *);
int md_view_record(struct md_filesystem *, int fd, struct md_view_mount *, struct md_view_object **);
int md_view_identity(struct md_filesystem *, int fd, struct md_view_object **);
int md_view_path(struct md_filesystem *, int fd, struct md_view_mount *, char *, size_t);
struct md_view_object *md_view_object(struct md_filesystem *, const char *id);
int md_view_walk(struct md_filesystem *, int base, const struct md_fs_anchor *, const char *path, int follow, int missing,
        uint64_t resolve, struct md_view_location *);
void md_view_location_close(struct md_view_location *);
int md_view_fdpath(int fd, char *, size_t);
int md_mount_id_allocate(unsigned *);
int md_view_anchor_check(struct md_filesystem *, int fd, const struct md_fs_anchor *);
void md_view_capture(struct md_filesystem *, struct md_mount_namespace *, struct md_view_mount *,
        struct md_fs_result *, const struct md_fs_output *);
#endif
