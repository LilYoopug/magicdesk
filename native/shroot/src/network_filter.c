#include "network_filter.h"
#include <errno.h>
#include <linux/netfilter/nf_tables.h>
#include <stdlib.h>
#include <string.h>

uint32_t md_network_filter_generation(const struct md_network_filter *f) { return f ? f->generation : 1; }
uint32_t md_network_filter_next_generation(const struct md_network_filter *f) {
    uint32_t next=md_network_filter_generation(f)+1;
    return next ? next : 1;
}
struct md_network_filter *md_network_filter_copy(const struct md_network_filter *from) {
    struct md_network_filter *f=calloc(1,sizeof(*f));
    if (!f) return NULL;
    f->generation=md_network_filter_generation(from);
    f->next_handle=from ? from->next_handle : 1;
    if (from && from->count) {
        f->tables=malloc(from->count*sizeof(*f->tables));
        if (!f->tables) { free(f); return NULL; }
        f->count=f->capacity=from->count;
        memcpy(f->tables,from->tables,f->count*sizeof(*f->tables));
    }
    if (from) {
        if (md_filter_reserve((void **)&f->chains,&f->chain_capacity,from->chain_count,sizeof(*f->chains),256)
                || md_filter_reserve((void **)&f->rules,&f->rule_capacity,from->rule_count,sizeof(*f->rules),1024)
                || md_filter_reserve((void **)&f->sets,&f->set_capacity,from->set_count,sizeof(*f->sets),256)) goto failed;
        f->chain_count=from->chain_count;
        if (from->chain_count) memcpy(f->chains,from->chains,from->chain_count*sizeof(*f->chains));
        for (size_t i=0;i<from->rule_count;++i) {
            struct md_filter_rule r=from->rules[i];
            r.wire=NULL;
            if (r.wire_size) {
                r.wire=malloc(r.wire_size);
                if (!r.wire) goto failed;
                memcpy(r.wire,from->rules[i].wire,r.wire_size);
            }
            f->rules[f->rule_count++]=r;
        }
        for (size_t i=0;i<from->set_count;++i) {
            struct md_filter_set s=from->sets[i];
            s.elements=NULL; s.capacity=0;
            if (md_filter_reserve((void **)&s.elements,&s.capacity,s.count,sizeof(*s.elements),1024)) goto failed;
            if (s.count) memcpy(s.elements,from->sets[i].elements,s.count*sizeof(*s.elements));
            f->sets[f->set_count++]=s;
        }
    }
    return f;
failed:
    md_network_filter_free(f); return NULL;
}
void md_network_filter_free(struct md_network_filter *f) {
    if (f) {
        for (size_t i=0;i<f->rule_count;++i) free(f->rules[i].wire);
        for (size_t i=0;i<f->set_count;++i) free(f->sets[i].elements);
        free(f->rules); free(f->chains); free(f->sets); free(f->tables); free(f);
    }
}
struct md_network_filter_table *md_network_filter_find(struct md_network_filter *f,unsigned family,
        const char *name,uint64_t handle) {
    if (f) for (size_t i=0;i<f->count;++i)
        if (f->tables[i].family==family && (name ? !strcmp(name,f->tables[i].name) : f->tables[i].handle==handle))
            return &f->tables[i];
    return NULL;
}
int md_network_filter_add(struct md_network_filter *f,unsigned family,const char *name,const void *userdata,size_t size) {
    if (!name || !*name || strlen(name)>=sizeof(f->tables[0].name) || size>sizeof(f->tables[0].userdata)) return -EINVAL;
    if (md_network_filter_find(f,family,name,0)) return -EEXIST;
    if (f->count==256 || f->next_handle==UINT64_MAX) return -ENOSPC;
    if (f->count==f->capacity) {
        size_t capacity=f->capacity ? f->capacity*2 : 4;
        if (capacity>256) capacity=256;
        void *tables=realloc(f->tables,capacity*sizeof(*f->tables));
        if (!tables) return -ENOMEM;
        f->tables=tables; f->capacity=capacity;
    }
    struct md_network_filter_table *t=&f->tables[f->count++];
    *t=(struct md_network_filter_table){.family=family,.handle=f->next_handle++,.userdata_size=size};
    memcpy(t->name,name,strlen(name)+1);
    if (size) memcpy(t->userdata,userdata,size);
    return 0;
}
void md_network_filter_delete(struct md_network_filter *f,unsigned family,const char *name,uint64_t handle) {
    if (!f) return;
    for (size_t i=0;i<f->count;) {
        struct md_network_filter_table *t=&f->tables[i];
        if ((!family || t->family==family) && (!name || !strcmp(t->name,name)) && (!handle || t->handle==handle)) {
            for (size_t j=0;j<f->chain_count;)
                if (f->chains[j].table==t->handle) md_filter_chain_delete(f,j); else ++j;
            for (size_t j=0;j<f->set_count;)
                if (f->sets[j].table==t->handle) md_filter_set_delete(f,j); else ++j;
            memmove(t,t+1,(f->count-i-1)*sizeof(*t)); --f->count;
        } else ++i;
    }
}
int md_filter_reserve(void **data,size_t *capacity,size_t count,size_t size,size_t limit) {
    if (count>limit) return -ENOSPC;
    if (count<=*capacity) return 0;
    size_t next=*capacity ? *capacity*2 : 4;
    if (next<count) next=count;
    if (next>limit) next=limit;
    void *memory=realloc(*data,next*size);
    if (!memory) return -ENOMEM;
    *data=memory; *capacity=next; return 0;
}
struct md_filter_chain *md_filter_chain_find(struct md_network_filter *f,uint64_t table,const char *name,uint64_t handle,uint32_t id) {
    if (f) for (size_t i=0;i<f->chain_count;++i) {
        struct md_filter_chain *c=&f->chains[i];
        if ((!table || c->table==table) && (name ? !strcmp(name,c->name) : handle ? handle==c->handle : id && id==c->id)) return c;
    }
    return NULL;
}
struct md_filter_set *md_filter_set_find(struct md_network_filter *f,uint64_t table,const char *name,uint64_t handle,uint32_t id) {
    if (f) for (size_t i=0;i<f->set_count;++i) {
        struct md_filter_set *s=&f->sets[i];
        if ((!table || s->table==table) && (name ? !strcmp(name,s->name) : handle ? handle==s->handle : id && id==s->id)) return s;
    }
    return NULL;
}
void md_filter_rule_delete(struct md_network_filter *f,size_t index) {
    free(f->rules[index].wire);
    memmove(f->rules+index,f->rules+index+1,(f->rule_count-index-1)*sizeof(*f->rules)); --f->rule_count;
}
size_t md_filter_set_position(const struct md_filter_set *s,const void *key,unsigned end) {
    size_t low=0,high=s->count;
    while (low<high) {
        size_t mid=low+(high-low)/2;
        int order=memcmp(s->elements[mid].key,key,s->key_size);
        /* At a shared boundary the old interval ends before the new starts. */
        if (order<0 || (!order && s->elements[mid].end>end)) low=mid+1;
        else high=mid;
    }
    return low;
}
const struct md_filter_element *md_filter_set_lookup(const struct md_filter_set *s,const void *key) {
    size_t at=md_filter_set_position(s,key,0);
    if (at<s->count && !s->elements[at].end && !memcmp(s->elements[at].key,key,s->key_size)) return s->elements+at;
    return (s->flags&NFT_SET_INTERVAL) && at && !s->elements[at-1].end ? s->elements+at-1 : NULL;
}
void md_filter_chain_delete(struct md_network_filter *f,size_t index) {
    uint64_t handle=f->chains[index].handle;
    for (size_t i=0;i<f->rule_count;)
        if (f->rules[i].chain==handle) md_filter_rule_delete(f,i); else ++i;
    memmove(f->chains+index,f->chains+index+1,(f->chain_count-index-1)*sizeof(*f->chains)); --f->chain_count;
}
void md_filter_set_delete(struct md_network_filter *f,size_t index) {
    free(f->sets[index].elements);
    memmove(f->sets+index,f->sets+index+1,(f->set_count-index-1)*sizeof(*f->sets)); --f->set_count;
}
size_t md_filter_verdict_count(const struct md_network_filter *f,const struct md_filter_expression *e) {
    if (e->code==MD_FILTER_VERDICT) return 1;
    if (e->code==MD_FILTER_VERDICT_MAP)
        for (size_t i=0;i<f->set_count;++i) if (f->sets[i].handle==e->target) return f->sets[i].count;
    return 0;
}
struct md_filter_verdict md_filter_verdict_at(const struct md_network_filter *f,const struct md_filter_expression *e,size_t at) {
    if (e->code==MD_FILTER_VERDICT) return (struct md_filter_verdict){e->operation,e->target};
    for (size_t i=0;i<f->set_count;++i) if (f->sets[i].handle==e->target)
        return f->sets[i].elements[at].end ? (struct md_filter_verdict){NFT_CONTINUE,0} : f->sets[i].elements[at].verdict;
    return (struct md_filter_verdict){0};
}
void md_filter_account(struct md_filter_accounting *a,size_t bytes) {
    for (size_t i=0;i<a->count;++i) { ++a->cells[i]->packets; a->cells[i]->bytes+=bytes; }
}
