#include "inode_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { PREFIX_SETS=64, PREFIX_WAYS=2 };
struct prefix_node {
    struct mdi_node node;
    struct mdi_dependency dependencies[2];
};
struct prefix {
    uint64_t hash, epoch, used;
    size_t length;
    unsigned count;
    char root[33];
    struct prefix_node nodes[];
};
struct mdi_path_cache {
    uint64_t clock;
    struct prefix *entries[PREFIX_SETS][PREFIX_WAYS];
};
static uint64_t hash_byte(uint64_t hash,unsigned char byte) {
    return (hash^byte)*UINT64_C(1099511628211);
}
static uint64_t start_hash(struct md_inode_store *s,const struct mdi_node *start) {
    uint64_t hash=UINT64_C(14695981039346656037);
    for (unsigned i=0;i<32;++i) hash=hash_byte(hash,(unsigned char)mdi_root(s)[i]);
    for (unsigned i=0;i<32;++i) hash=hash_byte(hash,(unsigned char)start->id[i]);
    return hash;
}
static char *text(struct prefix *p) { return (char *)(p->nodes+p->count); }
static int current(struct md_inode_store *s,const struct prefix *p) {
    if (p->epoch!=mdi_cache_epoch(s)) return 0;
    for (unsigned i=0;i<p->count;++i)
        if (!mdi_cache_dependencies_current(s,p->nodes[i].dependencies,i ? 2 : 1)) return 0;
    return 1;
}
int mdi_path_prefix_get(struct md_inode_store *s,const char *path,
        struct mdi_path_prefix *proof,size_t *consumed) {
    *consumed=0;
    if (!mdi_cache_epoch(s) || !s->path_cache) return 0;
    const struct mdi_node *start=&proof->nodes[0];
    uint64_t hash=start_hash(s,start);
    struct prefix *best=NULL;
    for (size_t i=0;path[i];++i) {
        /* Prefixes end before a slash and always leave an unresolved entry. */
        if (path[i]=='/' && i && path[i-1]!='/' && path[i+1]) {
            struct prefix **set=s->path_cache->entries[hash%PREFIX_SETS];
            for (unsigned j=0;j<PREFIX_WAYS;++j) {
                struct prefix *p=set[j];
                if (p && p->hash==hash && p->length==i
                        && !strcmp(p->root,mdi_root(s)) && !strcmp(p->nodes[0].node.id,start->id)
                        && p->nodes[0].node.device==start->device && p->nodes[0].node.inode==start->inode
                        && !memcmp(text(p),path,i) && current(s,p)) best=p;
            }
        }
        hash=hash_byte(hash,(unsigned char)path[i]);
    }
    if (!best) return 0;
    /* Revalidate each ancestor with the CURRENT credentials and mount view.
     * The store admission owns catalogue coherence; only physical directory
     * checks can be reused within its gate. No authorization result is saved. */
    const char *cursor=path;
    for (unsigned i=0;i+1<best->count;++i) {
        while (*cursor=='/') ++cursor;
        const char *end=cursor; while (*end && *end!='/') ++end;
        char name[NAME_MAX+1]; size_t length=(size_t)(end-cursor);
        memcpy(name,cursor,length); name[length]=0;
        int r=mdi_access(s,&best->nodes[i].node,X_OK);
        if (!r) r=mdi_host_boundary(s,best->nodes[i].node.id,name,end,0);
        if (r) return r;
        if (s->mount_boundary && md_inode_mount_contains(s->mount_boundary,
                best->nodes[i+1].node.device,best->nodes[i+1].node.inode)) return -EXDEV;
        cursor=end;
    }
    proof->count=best->count;
    for (unsigned i=0;i<best->count;++i) proof->nodes[i]=best->nodes[i].node;
    *consumed=best->length;
    best->used=++s->path_cache->clock;
    if (s->statistics) ++s->statistics->path_prefix_hits;
    return 0;
}
void mdi_path_prefix_put(struct md_inode_store *s,const char *path,size_t length,
        const struct mdi_path_prefix *proof) {
    uint64_t epoch=mdi_cache_epoch(s);
    if (!epoch || proof->count<2 || !length) return;
    if (!s->path_cache && !(s->path_cache=calloc(1,sizeof(*s->path_cache)))) return;
    uint64_t hash=start_hash(s,&proof->nodes[0]);
    for (size_t i=0;i<length;++i) hash=hash_byte(hash,(unsigned char)path[i]);
    struct prefix **set=s->path_cache->entries[hash%PREFIX_SETS],**slot=&set[0];
    for (unsigned i=0;i<PREFIX_WAYS;++i) {
        struct prefix *p=set[i];
        if (p && p->hash==hash && p->length==length
                && !strcmp(p->root,mdi_root(s)) && !strcmp(p->nodes[0].node.id,proof->nodes[0].id)
                && !memcmp(text(p),path,length) && current(s,p)) return;
        if (!p || p->epoch!=epoch || (*slot && p->used<(*slot)->used)) slot=&set[i];
    }
    struct prefix *p=malloc(sizeof(*p)+proof->count*sizeof(*p->nodes)+length+1);
    if (!p) return;
    *p=(struct prefix){.hash=hash,.epoch=epoch,.used=++s->path_cache->clock,
        .length=length,.count=proof->count};
    strcpy(p->root,mdi_root(s));
    const char *cursor=path;
    for (unsigned i=0;i<proof->count;++i) {
        struct prefix_node *node=&p->nodes[i];
        node->node=proof->nodes[i];
        node->dependencies[0]=mdi_cache_dependency(s,MDI_DEP_OBJECT,node->node.id,32,NULL,0);
        if (!i) continue;
        while (*cursor=='/') ++cursor;
        const char *end=cursor; while (*end && *end!='/') ++end;
        node->dependencies[1]=mdi_cache_dependency(s,MDI_DEP_ENTRY,proof->nodes[i-1].id,32,cursor,(size_t)(end-cursor));
        cursor=end;
    }
    memcpy(text(p),path,length); text(p)[length]=0;
    free(*slot); *slot=p;
}
void mdi_path_cache_destroy(struct md_inode_store *s) {
    if (!s->path_cache) return;
    for (unsigned i=0;i<PREFIX_SETS;++i) for (unsigned j=0;j<PREFIX_WAYS;++j)
        free(s->path_cache->entries[i][j]);
    free(s->path_cache); s->path_cache=NULL;
}
