#ifndef MD_FS_STORAGE_H
#define MD_FS_STORAGE_H
#include "fs_engine.h"
struct md_view_mount;
struct md_fs_storage_connections;
/* Worker-owned connections, separate from mount placement and retained backing
 * custody. Borrowed filesystem contexts share this owner, never copy its list. */
struct md_fs_storage_cache { struct md_fs_storage_connections *connections; };
int md_fs_storage_get(struct md_filesystem *, const struct md_view_mount *, struct md_inode_store **);
void md_fs_storage_close(struct md_fs_storage_cache *);
/* Scoped request policy on a selected connection. No store state travels with
 * mount copies or FD origins; the worker restores policy before its next call. */
struct md_fs_storage_scope {
    struct md_inode_store *store;
    const struct md_identity *identity;
    const char *root;
    struct md_inode_boundary *boundary;
    unsigned mask;
};
int md_fs_storage_enter(struct md_filesystem *, const struct md_view_mount *,
        struct md_fs_storage_scope *);
void md_fs_storage_leave(struct md_fs_storage_scope *);
#endif
