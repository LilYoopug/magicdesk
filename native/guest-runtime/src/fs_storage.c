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
    unsigned users;
};
static void release(struct md_fs_storage_cache *cache, struct md_fs_storage_connections **at) {
    struct md_fs_storage_connections *p=*at;
    *at=p->next; --cache->count;
    md_inode_store_close(p->store); free(p);
}
void md_fs_storage_prune(struct md_fs_storage_cache *cache) {
    if (!cache) return;
    for (struct md_fs_storage_connections **at=&cache->connections; *at;) {
        struct md_fs_storage_connections *p=*at;
        if (!p->users && atomic_load_explicit(&p->store->lifetime->refs,memory_order_acquire)==1)
            release(cache,at);
        else at=&p->next;
    }
}
int md_fs_storage_get(struct md_filesystem *fs, const struct md_view_mount *mount,
        struct md_inode_store **out) {
    if (!fs || !fs->store || !out || !md_view_inode(mount)) return -EINVAL;
    struct md_inode_lifetime *storage=mount ? mount->storage : NULL;
    if (!storage || md_inode_lifetime_same(storage,md_inode_store_lifetime(fs->store))) {
        *out=fs->store; return 0;
    }
    if (!fs->storage) return -ENOTSUP;
    for (struct md_fs_storage_connections **at=&fs->storage->connections; *at; at=&(*at)->next) {
        struct md_fs_storage_connections *p=*at;
        if (md_inode_lifetime_same(storage,md_inode_store_lifetime(p->store))) {
            *at=p->next; p->next=fs->storage->connections; fs->storage->connections=p;
            *out=p->store; return 0;
        }
    }
    md_fs_storage_prune(fs->storage);
    if (fs->storage->count==MD_FS_STORAGE_CACHE_LIMIT) {
        struct md_fs_storage_connections **oldest=NULL;
        for (struct md_fs_storage_connections **at=&fs->storage->connections; *at; at=&(*at)->next)
            if (!(*at)->users) oldest=at;
        if (!oldest) return -EMFILE;
        release(fs->storage,oldest);
    }
    struct md_fs_storage_connections *p=calloc(1,sizeof(*p));
    if (!p) return -ENOMEM;
    int r=md_inode_store_reconnect(storage,&p->store);
    if (r) { free(p); return r; }
    p->next=fs->storage->connections; fs->storage->connections=p;
    ++fs->storage->count;
    *out=p->store; return 0;
}
void md_fs_storage_close(struct md_fs_storage_cache *cache) {
    if (!cache) return;
    while (cache->connections) release(cache,&cache->connections);
}
int md_fs_storage_enter(struct md_filesystem *fs, const struct md_view_mount *mount,
        struct md_fs_storage_scope *scope) {
    *scope=(struct md_fs_storage_scope){0};
    struct md_inode_store *store;
    int r=md_fs_storage_get(fs,mount,&store);
    if (r) return r;
    *scope=(struct md_fs_storage_scope){.store=store,.identity=store->identity,
        .root=store->root_id,.boundary=store->boundary,.mask=store->creation_mask,
        .landlock=store->landlock,.landlock_execute=store->landlock_execute};
    if (store!=fs->store) {
        scope->connection=fs->storage->connections;
        ++scope->connection->users;
    }
    store->identity=fs->store->identity; store->creation_mask=fs->store->creation_mask;
    store->landlock=fs->store->landlock;
    store->landlock_execute=fs->store->landlock_execute;
    /* Implicit providers belong to the selected root, not every bind alias of
     * its inode. A future root still exposes real dentries for mount setup. */
    store->boundary=store==fs->store && (!mount || !fs->mounts || mount==&fs->mounts->base
        || mount==md_view_root_mount(fs)) ? fs->store->boundary : NULL;
    store->root_id=store==fs->store ? fs->store->root_id : NULL;
    return 0;
}
void md_fs_storage_leave(struct md_fs_storage_scope *scope) {
    if (!scope->store) return;
    scope->store->identity=scope->identity; scope->store->root_id=scope->root;
    scope->store->boundary=scope->boundary; scope->store->creation_mask=scope->mask;
    scope->store->landlock=scope->landlock;
    scope->store->landlock_execute=scope->landlock_execute;
    if (scope->connection) --scope->connection->users;
    scope->store=NULL; scope->connection=NULL;
}
