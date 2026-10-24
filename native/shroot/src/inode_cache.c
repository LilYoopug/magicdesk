#include "inode_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum { CACHE_WAYS=4, CACHE_SETS=1024, CACHE_FD_SETS=256,
    CACHE_SLOTS=CACHE_WAYS*CACHE_SETS, DEPENDENCIES=4096 };
struct mdi_cache_entry {
    uint64_t hash, device, inode, used, epoch;
    struct mdi_dependency dependencies[3];
    unsigned dependency_count;
    enum mdi_query query;
    int valid, result;
    char id[33], name[NAME_MAX+1], scope[33];
    union { struct mdi_node node; struct mdi_path_name name; uint64_t number; } value;
};
struct mdi_read_cache {
    sqlite3_int64 version;
    uint64_t clock, epoch;
    uint64_t dependencies[DEPENDENCIES];
    int dirty;
    unsigned recent[MDI_QUERY_COUNT];
    struct mdi_cache_entry entries[CACHE_SLOTS];
};
void mdi_cache_invalidate(struct md_inode_store *s) {
    s->cache_checked=0;
    if (s->read_cache) {
        ++s->read_cache->epoch;
        memset(s->read_cache->recent,0,sizeof(s->read_cache->recent));
    }
}
uint64_t mdi_cache_epoch(const struct md_inode_store *s) {
    return s->cache_checked==1 && s->read_cache ? s->read_cache->epoch : 0;
}
static uint64_t hash_bytes(uint64_t,const void *,size_t);
static unsigned dependency(enum mdi_dependency_kind kind,const void *id,size_t length,
        const void *name,size_t size) {
    uint64_t hash=hash_bytes(UINT64_C(14695981039346656037),&kind,sizeof(kind));
    hash=hash_bytes(hash,id,length);
    return hash_bytes(hash,name,size)%DEPENDENCIES;
}
static void changed_key(struct mdi_read_cache *cache,enum mdi_dependency_kind kind,
        sqlite3_value *id,sqlite3_value *name) {
    ++cache->dependencies[dependency(kind,sqlite3_value_blob(id),sqlite3_value_bytes(id),
        name ? sqlite3_value_blob(name) : NULL,name ? sqlite3_value_bytes(name) : 0)];
}
/* Observe rows, including trigger writes, rather than duplicating mutation
 * knowledge in open/link/rename/ACL/copy-up callers. This hook does not run SQL
 * or allocate cache entries. Failed transactions discard all speculative rows. */
static void changed_row(struct md_inode_store *s,sqlite3 *db,const char *table,int old) {
    int object=!strcmp(table,"objects"), names=!strcmp(table,"names"),
        backing=!strcmp(table,"backings"), path=!strcmp(table,"file_paths"), dentry=!strcmp(table,"dentry_paths");
    if (!object && !names && !backing && !path && !dentry) return;
    s->read_cache->dirty=1;
    sqlite3_value *id=NULL,*parent=NULL,*name=NULL,*device=NULL,*inode=NULL;
    int (*value)(sqlite3 *,int,sqlite3_value **)=old ? sqlite3_preupdate_old : sqlite3_preupdate_new;
    int r=value(db,names ? 3 : backing ? 1 : dentry ? 2 : 0,&id);
    if (!r && (names || dentry)) r=value(db,dentry ? 3 : 1,&parent);
    if (!r && (names || dentry)) r=value(db,dentry ? 4 : 2,&name);
    if (!r && backing) r=value(db,2,&device);
    if (!r && backing) r=value(db,3,&inode);
    if (r) { mdi_cache_invalidate(s); return; }
    /* Version buckets conservatively retire collisions. Invalidation costs
     * O(changed row), independent of cache capacity, including trigger writes. */
    if (object) changed_key(s->read_cache,MDI_DEP_OBJECT,id,NULL);
    if (names || dentry) changed_key(s->read_cache,MDI_DEP_ENTRY,parent,name);
    if (names) {
        changed_key(s->read_cache,MDI_DEP_CHILDREN,parent,NULL);
        changed_key(s->read_cache,MDI_DEP_PATH,id,NULL);
    }
    if (path) changed_key(s->read_cache,MDI_DEP_PATH,id,NULL);
    if (backing) {
        uint64_t physical[]={(uint64_t)sqlite3_value_int64(device),(uint64_t)sqlite3_value_int64(inode)};
        ++s->read_cache->dependencies[dependency(MDI_DEP_BACKING,physical,sizeof(physical),NULL,0)];
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
        s->read_cache->epoch=1;
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
    /* Connection-local bucket selection only; full keys decide identity. Mix
     * words rather than serializing a multiply for every byte of each ID. */
    while (length>=sizeof(uint64_t)) {
        uint64_t word; memcpy(&word,bytes,sizeof(word));
        hash=(hash^word)*UINT64_C(0x9e3779b185ebca87);
        hash^=hash>>32;
        bytes+=sizeof(word); length-=sizeof(word);
    }
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
    return hash^(hash>>32);
}
static struct mdi_cache_entry *cache_set(struct mdi_read_cache *cache,enum mdi_query query,uint64_t hash) {
    unsigned set=query==MDI_FD ? (hash%CACHE_FD_SETS)
        : CACHE_FD_SETS+(hash%(CACHE_SETS-CACHE_FD_SETS));
    return &cache->entries[set*CACHE_WAYS];
}
static int dependencies_current(const struct mdi_read_cache *cache,const struct mdi_dependency *deps,unsigned count) {
    for (unsigned i=0;i<count;++i) {
        const struct mdi_dependency *d=&deps[i];
        if (d->version!=cache->dependencies[d->slot]) return 0;
    }
    return 1;
}
int mdi_cache_dependencies_current(const struct md_inode_store *s,const struct mdi_dependency *deps,unsigned count) {
    return s->cache_checked==1 && s->read_cache && dependencies_current(s->read_cache,deps,count);
}
struct mdi_dependency mdi_cache_dependency(struct md_inode_store *s,enum mdi_dependency_kind kind,
        const void *id,size_t length,const void *name,size_t size) {
    unsigned slot=dependency(kind,id,length,name,size);
    return (struct mdi_dependency){slot,s->read_cache->dependencies[slot]};
}
static int current(const struct mdi_read_cache *cache,const struct mdi_cache_entry *entry) {
    return entry->valid && entry->epoch==cache->epoch
        && dependencies_current(cache,entry->dependencies,entry->dependency_count);
}
static void depends(struct mdi_read_cache *cache,struct mdi_cache_entry *entry,
        enum mdi_dependency_kind kind,const void *id,size_t length,const void *name,size_t size) {
    unsigned slot=dependency(kind,id,length,name,size);
    for (unsigned i=0;i<entry->dependency_count;++i) if (entry->dependencies[i].slot==slot) return;
    entry->dependencies[entry->dependency_count++]=(struct mdi_dependency){slot,cache->dependencies[slot]};
}
static int matches_key(const struct mdi_cache_entry *entry, const struct md_inode_store *s,
        const struct mdi_cache_key *key) {
    return current(s->read_cache,entry) && entry->query==key->query
        && entry->device==key->device && entry->inode==key->inode
        && !strcmp(entry->scope,s->lifetime->scope)
        && !strcmp(entry->id,key->id ? key->id : "")
        && !strcmp(entry->name,key->name ? key->name : "");
}
static int matches(const struct mdi_cache_entry *entry,const struct md_inode_store *s,
        const struct mdi_cache_key *key,uint64_t hash) {
    return entry->hash==hash && matches_key(entry,s,key);
}
static struct mdi_cache_entry *get(struct md_inode_store *s, const struct mdi_cache_key *key) {
    if (!s->locked || s->cache_checked!=1) return NULL;
    /* A hot exact key avoids hashing/scanning, not validation. Row hooks,
     * rollback and foreign generations invalidate the same cache entries. */
    unsigned recent=s->read_cache->recent[key->query];
    if (recent) {
        struct mdi_cache_entry *entry=&s->read_cache->entries[recent-1];
        if (matches_key(entry,s,key)) {
            if (s->statistics) ++s->statistics->metadata_cache_hits;
            entry->used=++s->read_cache->clock;
            return entry;
        }
    }
    uint64_t hash=key_hash(s,key);
    struct mdi_cache_entry *set=cache_set(s->read_cache,key->query,hash);
    for (unsigned i=0;i<CACHE_WAYS;++i) {
        struct mdi_cache_entry *entry=&set[i];
        if (!matches(entry,s,key,hash)) continue;
        if (s->statistics) ++s->statistics->metadata_cache_hits;
        entry->used=++s->read_cache->clock;
        s->read_cache->recent[key->query]=(unsigned)(entry-s->read_cache->entries)+1;
        return entry;
    }
    if (s->statistics) ++s->statistics->metadata_cache_misses;
    return NULL;
}
static struct mdi_cache_entry *put(struct md_inode_store *s, const struct mdi_cache_key *key, int result) {
    if (!s->locked || s->cache_checked!=1 || (result && result!=-ENOENT)) return NULL;
    if ((key->id && strlen(key->id)>32) || (key->name && strlen(key->name)>NAME_MAX)) return NULL;
    uint64_t hash=key_hash(s,key);
    struct mdi_cache_entry *set=cache_set(s->read_cache,key->query,hash), *entry=set;
    for (unsigned i=0;i<CACHE_WAYS;++i) {
        if (matches(&set[i],s,key,hash)) { entry=&set[i]; break; }
        if (!current(s->read_cache,&set[i]) || (current(s->read_cache,entry) && set[i].used<entry->used)) entry=&set[i];
    }
    *entry=(struct mdi_cache_entry){.hash=hash,.device=key->device,.inode=key->inode,
        .query=key->query,.result=result,.valid=1,.used=++s->read_cache->clock,.epoch=s->read_cache->epoch};
    strcpy(entry->scope,s->lifetime->scope);
    if (key->id) strcpy(entry->id,key->id);
    if (key->name) strcpy(entry->name,key->name);
    /* Parent attributes do not change a name lookup's result. Its caller
     * admits the current parent separately; names/cascades own membership. */
    if (key->id && key->query!=MDI_LOOKUP && key->query!=MDI_DENTRY_CAPTURE && key->query!=MDI_EMPTY)
        depends(s->read_cache,entry,MDI_DEP_OBJECT,key->id,strlen(key->id),NULL,0);
    if (key->query==MDI_FD) {
        uint64_t physical[]={key->device,key->inode};
        depends(s->read_cache,entry,MDI_DEP_BACKING,physical,sizeof(physical),NULL,0);
    } else if (key->query==MDI_LOOKUP || key->query==MDI_DENTRY_CAPTURE)
        depends(s->read_cache,entry,MDI_DEP_ENTRY,entry->id,strlen(entry->id),entry->name,strlen(entry->name));
    else if (key->query==MDI_EMPTY) depends(s->read_cache,entry,MDI_DEP_CHILDREN,entry->id,strlen(entry->id),NULL,0);
    else if (key->query==MDI_DIRECTORY_NAME || key->query==MDI_FILE_PATH)
        depends(s->read_cache,entry,MDI_DEP_PATH,entry->id,strlen(entry->id),NULL,0);
    s->read_cache->recent[key->query]=(unsigned)(entry-s->read_cache->entries)+1;
    return entry;
}
int mdi_cache_get(struct md_inode_store *s, const struct mdi_cache_key *key,
        struct mdi_node *node, int *result) {
    struct mdi_cache_entry *entry=get(s,key);
    if (!entry) return 0;
    *result=entry->result;
    if (!*result && node) *node=entry->value.node;
    return 1;
}
void mdi_cache_put(struct md_inode_store *s, const struct mdi_cache_key *key,
        const struct mdi_node *node, int result) {
    if (!result && node && node->native) return;
    struct mdi_cache_entry *entry=put(s,key,result);
    if (!entry || result || !node) return;
    entry->value.node=*node;
    depends(s->read_cache,entry,MDI_DEP_OBJECT,node->id,strlen(node->id),NULL,0);
    /* A resolved object also identifies its current backing. Prime the same
     * versioned descriptor lookup; fstat still verifies the actual description
     * and obtains native attributes. Never alias a node from another view. */
    if ((key->query==MDI_NODE || key->query==MDI_LOOKUP)
            && !strcmp(node->scope,s->lifetime->scope)) {
        const struct mdi_cache_key backing={.query=MDI_FD,.device=node->device,.inode=node->inode};
        entry=put(s,&backing,0);
        if (entry) {
            entry->value.node=*node;
            depends(s->read_cache,entry,MDI_DEP_OBJECT,node->id,strlen(node->id),NULL,0);
        }
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
int mdi_cache_number_get(struct md_inode_store *s, const struct mdi_cache_key *key, uint64_t *number) {
    struct mdi_cache_entry *entry=get(s,key);
    if (!entry) return 0;
    *number=entry->value.number; return 1;
}
void mdi_cache_number_put(struct md_inode_store *s, const struct mdi_cache_key *key, uint64_t number) {
    struct mdi_cache_entry *entry=put(s,key,0);
    if (entry) entry->value.number=number;
}
