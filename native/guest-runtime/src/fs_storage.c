#define _GNU_SOURCE
#include "fs_storage.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

struct md_fs_storage_connections {
    struct md_fs_storage_connections *next;
    struct md_inode_store *store;
};
int md_fs_storage_get(struct md_filesystem *fs, const struct md_view_mount *mount,
        struct md_inode_store **out) {
    if (!fs || !fs->store || !out || !md_view_inode(mount)) return -EINVAL;
    struct md_inode_lifetime *storage=mount ? mount->storage : NULL;
    if (!storage || md_inode_lifetime_same(storage,md_inode_store_lifetime(fs->store))) {
        *out=fs->store; return 0;
    }
    if (!fs->storage) return -ENOTSUP;
    for (struct md_fs_storage_connections *p=fs->storage->connections; p; p=p->next)
        if (md_inode_lifetime_same(storage,md_inode_store_lifetime(p->store))) {
            *out=p->store; return 0;
        }
    struct md_fs_storage_connections *p=calloc(1,sizeof(*p));
    if (!p) return -ENOMEM;
    int r=md_inode_store_reconnect(storage,&p->store);
    if (r) { free(p); return r; }
    p->next=fs->storage->connections; fs->storage->connections=p;
    *out=p->store; return 0;
}
void md_fs_storage_close(struct md_fs_storage_cache *cache) {
    if (!cache) return;
    while (cache->connections) {
        struct md_fs_storage_connections *p=cache->connections;
        cache->connections=p->next; md_inode_store_close(p->store); free(p);
    }
}
int md_fs_storage_enter(struct md_filesystem *fs, const struct md_view_mount *mount,
        struct md_fs_storage_scope *scope) {
    *scope=(struct md_fs_storage_scope){0};
    struct md_inode_store *store;
    int r=md_fs_storage_get(fs,mount,&store);
    if (r) return r;
    *scope=(struct md_fs_storage_scope){.store=store,.identity=store->identity,
        .root=store->root_id,.boundary=store->boundary,.mask=store->creation_mask};
    store->identity=fs->store->identity; store->creation_mask=fs->store->creation_mask;
    /* Only the initial filesystem owns Android proc/dev boundary routing.
     * Mounted filesystems contain their own ordinary names at these paths. */
    store->boundary=store==fs->store ? fs->store->boundary : NULL;
    store->root_id=store==fs->store ? fs->store->root_id : NULL;
    return 0;
}
void md_fs_storage_leave(struct md_fs_storage_scope *scope) {
    if (!scope->store) return;
    scope->store->identity=scope->identity; scope->store->root_id=scope->root;
    scope->store->boundary=scope->boundary; scope->store->creation_mask=scope->mask;
}
