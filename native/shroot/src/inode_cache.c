#include "inode_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum { CACHE_WAYS=4, CACHE_SETS=32, CACHE_SLOTS=CACHE_WAYS*CACHE_SETS };
struct mdi_cache_entry {
    uint64_t hash, device, inode, used;
    enum mdi_query query;
    int valid, result;
    char id[33], name[NAME_MAX+1], scope[33];
    union { struct mdi_node node; struct mdi_path_name name; } value;
};
struct mdi_read_cache {
    sqlite3_int64 version, changes;
    uint64_t clock;
    struct mdi_cache_entry entries[CACHE_SLOTS];
};
void mdi_cache_invalidate(struct md_inode_store *s) {
    s->cache_checked=0;
    if (s->read_cache) memset(s->read_cache,0,sizeof(*s->read_cache));
}
void mdi_cache_snapshot(struct md_inode_store *s, sqlite3_int64 version) {
    s->cache_checked=-1;
    if (!s->read_cache && !(s->read_cache=calloc(1,sizeof(*s->read_cache)))) return;
    /* The active transaction owns this SQLite snapshot. Version detects other
     * connections; total_changes also detects this connection's writes. */
    sqlite3_int64 changes=sqlite3_total_changes64(s->db);
    if (s->read_cache->version!=version || s->read_cache->changes!=changes) {
        mdi_cache_invalidate(s);
        s->read_cache->version=version; s->read_cache->changes=changes;
    }
    s->cache_checked=1;
}
static uint64_t hash_bytes(uint64_t hash, const void *data, size_t length) {
    const unsigned char *bytes=data;
    for (size_t i=0;i<length;++i) hash=(hash^bytes[i])*UINT64_C(1099511628211);
    return hash;
}
static uint64_t key_hash(const struct md_inode_store *s, const struct mdi_cache_key *key) {
    uint64_t hash=hash_bytes(UINT64_C(14695981039346656037),&key->query,sizeof(key->query));
    hash=hash_bytes(hash,&key->device,sizeof(key->device));
    hash=hash_bytes(hash,&key->inode,sizeof(key->inode));
    hash=hash_bytes(hash,s->lifetime->scope,32);
    if (key->id) hash=hash_bytes(hash,key->id,strlen(key->id));
    if (key->name) hash=hash_bytes(hash,key->name,strlen(key->name));
    return hash;
}
static struct mdi_cache_entry *get(struct md_inode_store *s, const struct mdi_cache_key *key) {
    if (!s->locked || s->write_transaction || s->cache_checked!=1) return NULL;
    uint64_t hash=key_hash(s,key);
    struct mdi_cache_entry *set=&s->read_cache->entries[(hash%CACHE_SETS)*CACHE_WAYS];
    for (unsigned i=0;i<CACHE_WAYS;++i) {
        struct mdi_cache_entry *entry=&set[i];
        if (!entry->valid || entry->hash!=hash || entry->query!=key->query
            || entry->device!=key->device || entry->inode!=key->inode
            || strcmp(entry->scope,s->lifetime->scope)
            || strcmp(entry->id,key->id ? key->id : "")
            || strcmp(entry->name,key->name ? key->name : "")) continue;
        if (s->statistics) ++s->statistics->metadata_cache_hits;
        entry->used=++s->read_cache->clock;
        return entry;
    }
    if (s->statistics) ++s->statistics->metadata_cache_misses;
    return NULL;
}
static struct mdi_cache_entry *put(struct md_inode_store *s, const struct mdi_cache_key *key, int result) {
    if (s->cache_checked!=1 || s->write_transaction || (result && result!=-ENOENT)) return NULL;
    if ((key->id && strlen(key->id)>32) || (key->name && strlen(key->name)>NAME_MAX)) return NULL;
    uint64_t hash=key_hash(s,key);
    struct mdi_cache_entry *set=&s->read_cache->entries[(hash%CACHE_SETS)*CACHE_WAYS], *entry=set;
    for (unsigned i=1;i<CACHE_WAYS;++i)
        if (set[i].used<entry->used) entry=&set[i];
    *entry=(struct mdi_cache_entry){.hash=hash,.device=key->device,.inode=key->inode,
        .query=key->query,.result=result,.valid=1,.used=++s->read_cache->clock};
    strcpy(entry->scope,s->lifetime->scope);
    if (key->id) strcpy(entry->id,key->id);
    if (key->name) strcpy(entry->name,key->name);
    return entry;
}
int mdi_cache_get(struct md_inode_store *s, const struct mdi_cache_key *key,
        struct mdi_node *node, int *result) {
    struct mdi_cache_entry *entry=get(s,key);
    if (!entry) return 0;
    *result=entry->result;
    if (!*result) *node=entry->value.node;
    return 1;
}
void mdi_cache_put(struct md_inode_store *s, const struct mdi_cache_key *key,
        const struct mdi_node *node, int result) {
    struct mdi_cache_entry *entry=put(s,key,result);
    if (entry && !result) entry->value.node=*node;
}
int mdi_cache_name_get(struct md_inode_store *s, const struct mdi_cache_key *key,
        struct mdi_path_name *name) {
    struct mdi_cache_entry *entry=get(s,key);
    if (!entry) return 0;
    *name=entry->value.name; return 1;
}
void mdi_cache_name_put(struct md_inode_store *s, const struct mdi_cache_key *key,
        const struct mdi_path_name *name) {
    struct mdi_cache_entry *entry=put(s,key,0);
    if (entry) entry->value.name=*name;
}
