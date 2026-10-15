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
    sqlite3_int64 version;
    uint64_t clock;
    int dirty;
    struct mdi_cache_entry entries[CACHE_SLOTS];
};
void mdi_cache_invalidate(struct md_inode_store *s) {
    s->cache_checked=0;
    if (s->read_cache) memset(s->read_cache,0,sizeof(*s->read_cache));
}
static int equals(sqlite3_value *value,const char *text) {
    int size=sqlite3_value_bytes(value);
    return size==(int)strlen(text) && !memcmp(sqlite3_value_blob(value),text,(size_t)size);
}
/* Observe rows, including trigger writes, rather than duplicating mutation
 * knowledge in open/link/rename/ACL/copy-up callers. This hook does not run SQL
 * or allocate cache entries. Failed transactions discard all speculative rows. */
static void changed_row(struct md_inode_store *s,sqlite3 *db,const char *table,int old) {
    int object=!strcmp(table,"objects"), names=!strcmp(table,"names"),
        backing=!strcmp(table,"backings"), path=!strcmp(table,"file_paths");
    if (!object && !names && !backing && !path) return;
    s->read_cache->dirty=1;
    sqlite3_value *id=NULL,*parent=NULL,*name=NULL,*device=NULL,*inode=NULL;
    int (*value)(sqlite3 *,int,sqlite3_value **)=old ? sqlite3_preupdate_old : sqlite3_preupdate_new;
    int r=value(db,names ? 3 : backing ? 1 : 0,&id);
    if (!r && names) r=value(db,1,&parent);
    if (!r && names) r=value(db,2,&name);
    if (!r && backing) r=value(db,2,&device);
    if (!r && backing) r=value(db,3,&inode);
    if (r) { mdi_cache_invalidate(s); return; }
    for (unsigned i=0;i<CACHE_SLOTS;++i) {
        struct mdi_cache_entry *e=&s->read_cache->entries[i];
        if (!e->valid) continue;
        int node_query=e->query==MDI_NODE || e->query==MDI_LOOKUP || e->query==MDI_FD;
        int affected=object && ((node_query && !e->result && equals(id,e->value.node.id))
            || (e->query!=MDI_FD && equals(id,e->id)));
        if (names) affected=(e->query==MDI_LOOKUP && equals(parent,e->id) && equals(name,e->name))
            || ((e->query==MDI_DIRECTORY_NAME || e->query==MDI_FILE_PATH) && equals(id,e->id));
        if (backing) affected=e->query==MDI_FD && e->device==(uint64_t)sqlite3_value_int64(device)
            && e->inode==(uint64_t)sqlite3_value_int64(inode);
        if (path) affected=e->query==MDI_FILE_PATH && equals(id,e->id);
        if (affected) { e->valid=0; e->used=0; }
    }
}
static void changed(void *context,sqlite3 *db,int operation,const char *database,
        const char *table,sqlite3_int64 before,sqlite3_int64 after) {
    (void)before; (void)after;
    struct md_inode_store *s=context;
    if (!s->read_cache || strcmp(database,"main")) return;
    if (operation!=SQLITE_INSERT) changed_row(s,db,table,1);
    if (operation!=SQLITE_DELETE) changed_row(s,db,table,0);
}
static void rolled_back(void *context) {
    struct md_inode_store *s=context;
    if (s->read_cache && s->read_cache->dirty) mdi_cache_invalidate(s);
}
void mdi_cache_snapshot(struct md_inode_store *s, sqlite3_int64 version) {
    s->cache_checked=-1;
    if (!s->read_cache) {
        if (!(s->read_cache=calloc(1,sizeof(*s->read_cache)))) return;
        sqlite3_preupdate_hook(s->db,changed,s);
        sqlite3_rollback_hook(s->db,rolled_back,s);
    }
    /* External writers retire the snapshot; local row hooks invalidate only
     * dependent records. Native attributes and authorization are never cached. */
    if (s->read_cache->version!=version) {
        mdi_cache_invalidate(s);
        s->read_cache->version=version;
    }
    s->read_cache->dirty=0;
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
static int matches(const struct mdi_cache_entry *entry, const struct md_inode_store *s,
        const struct mdi_cache_key *key, uint64_t hash) {
    return entry->valid && entry->hash==hash && entry->query==key->query
        && entry->device==key->device && entry->inode==key->inode
        && !strcmp(entry->scope,s->lifetime->scope)
        && !strcmp(entry->id,key->id ? key->id : "")
        && !strcmp(entry->name,key->name ? key->name : "");
}
static struct mdi_cache_entry *get(struct md_inode_store *s, const struct mdi_cache_key *key) {
    if (!s->locked || s->cache_checked!=1) return NULL;
    uint64_t hash=key_hash(s,key);
    struct mdi_cache_entry *set=&s->read_cache->entries[(hash%CACHE_SETS)*CACHE_WAYS];
    for (unsigned i=0;i<CACHE_WAYS;++i) {
        struct mdi_cache_entry *entry=&set[i];
        if (!matches(entry,s,key,hash)) continue;
        if (s->statistics) ++s->statistics->metadata_cache_hits;
        entry->used=++s->read_cache->clock;
        return entry;
    }
    if (s->statistics) ++s->statistics->metadata_cache_misses;
    return NULL;
}
static struct mdi_cache_entry *put(struct md_inode_store *s, const struct mdi_cache_key *key, int result) {
    if (!s->locked || s->cache_checked!=1 || (result && result!=-ENOENT)) return NULL;
    if ((key->id && strlen(key->id)>32) || (key->name && strlen(key->name)>NAME_MAX)) return NULL;
    uint64_t hash=key_hash(s,key);
    struct mdi_cache_entry *set=&s->read_cache->entries[(hash%CACHE_SETS)*CACHE_WAYS], *entry=set;
    for (unsigned i=0;i<CACHE_WAYS;++i) {
        if (matches(&set[i],s,key,hash)) { entry=&set[i]; break; }
        if (set[i].used<entry->used) entry=&set[i];
    }
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
    if (!result && node->native) return;
    struct mdi_cache_entry *entry=put(s,key,result);
    if (!entry || result) return;
    entry->value.node=*node;
    /* A resolved object also identifies its current backing. Prime the same
     * versioned descriptor lookup; fstat still verifies the actual description
     * and obtains native attributes. Never alias a node from another view. */
    if ((key->query==MDI_NODE || key->query==MDI_LOOKUP)
            && !strcmp(node->scope,s->lifetime->scope)) {
        const struct mdi_cache_key backing={.query=MDI_FD,.device=node->device,.inode=node->inode};
        entry=put(s,&backing,0);
        if (entry) entry->value.node=*node;
    }
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
