#include "bpf_map.h"
#include "bpf_handle.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum { BUCKETS=256, MAP_LIMIT=4096, MEMORY_LIMIT=64*1024*1024 };
struct entry { struct entry *next; unsigned char data[]; };
struct md_bpf_maps {
    atomic_uint refs;
    pthread_mutex_t lock;
    struct md_bpf_map *first;
    uint32_t next;
    unsigned count;
    size_t reserved;
};
struct md_bpf_map {
    struct md_bpf_map *next;
    struct md_bpf_maps *owner;
    struct bpf_map_info info;
    unsigned refs,count;
    size_t reserved;
    struct entry *buckets[BUCKETS];
};
struct md_bpf_maps *md_bpf_maps_new(void) {
    struct md_bpf_maps *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    int r=pthread_mutex_init(&p->lock,NULL);
    if (r) { free(p); errno=r; return NULL; }
    atomic_init(&p->refs,1); return p;
}
struct md_bpf_maps *md_bpf_maps_retain(struct md_bpf_maps *p) {
    if (p) atomic_fetch_add(&p->refs,1); return p;
}
void md_bpf_maps_release(struct md_bpf_maps *p) {
    if (!p || atomic_fetch_sub(&p->refs,1)!=1) return;
    pthread_mutex_destroy(&p->lock); free(p);
}
struct md_bpf_map *md_bpf_map_new(struct md_bpf_maps *owner,const struct bpf_map_info *info) {
    if (!info->type) { errno=EINVAL; return NULL; }
    if (info->type!=BPF_MAP_TYPE_HASH || (info->map_flags&~BPF_F_NO_PREALLOC)) { errno=EOPNOTSUPP; return NULL; }
    if (!info->key_size || !info->value_size || !info->max_entries) { errno=EINVAL; return NULL; }
    if (info->key_size>MD_BPF_MAP_KEY_MAX || info->value_size>MD_BPF_MAP_VALUE_MAX
            || info->max_entries>65536) { errno=E2BIG; return NULL; }
    if (strnlen(info->name,sizeof(info->name))==sizeof(info->name)) { errno=EINVAL; return NULL; }
    for (const char *s=info->name;*s;++s)
        if (!((*s>='a' && *s<='z') || (*s>='A' && *s<='Z') || (*s>='0' && *s<='9')
                || *s=='_' || *s=='.')) { errno=EINVAL; return NULL; }
    struct md_bpf_map *m=calloc(1,sizeof(*m));
    if (!m) return NULL;
    m->owner=owner; m->refs=1; m->info=*info;
    m->reserved=sizeof(*m)+(sizeof(struct entry)+info->key_size+info->value_size)*(size_t)info->max_entries;
    pthread_mutex_lock(&owner->lock);
    int r=0;
    if (owner->count==MAP_LIMIT || owner->next==UINT32_MAX) r=ENOSPC;
    else if (m->reserved>MEMORY_LIMIT-owner->reserved) r=ENOMEM;
    else {
        m->info.id=++owner->next; m->next=owner->first; owner->first=m;
        ++owner->count; owner->reserved+=m->reserved; md_bpf_maps_retain(owner);
    }
    pthread_mutex_unlock(&owner->lock);
    if (r) { free(m); errno=r; return NULL; } return m;
}
struct md_bpf_map *md_bpf_map_retain(struct md_bpf_map *m) {
    if (m) { pthread_mutex_lock(&m->owner->lock); ++m->refs; pthread_mutex_unlock(&m->owner->lock); }
    return m;
}
void md_bpf_map_release(struct md_bpf_map *m) {
    if (!m) return;
    struct md_bpf_maps *owner=m->owner;
    pthread_mutex_lock(&owner->lock);
    int last=!--m->refs;
    if (last) {
        struct md_bpf_map **at=&owner->first;
        while (*at!=m) at=&(*at)->next;
        *at=m->next; --owner->count; owner->reserved-=m->reserved;
    }
    pthread_mutex_unlock(&owner->lock);
    if (last) {
        for (unsigned i=0;i<BUCKETS;++i) while (m->buckets[i]) {
            struct entry *e=m->buckets[i]; m->buckets[i]=e->next; free(e);
        }
        free(m); md_bpf_maps_release(owner);
    }
}
struct md_bpf_map *md_bpf_map_find(struct md_bpf_maps *owner,uint32_t id) {
    if (!owner) return NULL;
    pthread_mutex_lock(&owner->lock);
    struct md_bpf_map *m=owner->first;
    while (m && m->info.id!=id) m=m->next;
    if (m) ++m->refs;
    pthread_mutex_unlock(&owner->lock); return m;
}
void md_bpf_map_info(const struct md_bpf_map *m,struct bpf_map_info *info) { *info=m->info; }
static unsigned bucket(const void *key,unsigned size) {
    const unsigned char *p=key; uint32_t hash=2166136261U;
    for (unsigned i=0;i<size;++i) hash=(hash^p[i])*16777619U;
    return hash%BUCKETS;
}
int md_bpf_map_element(struct md_bpf_map *m,unsigned command,const void *key,const void *value,uint64_t flags,void *out) {
    if (command!=BPF_MAP_LOOKUP_ELEM && command!=BPF_MAP_UPDATE_ELEM
            && command!=BPF_MAP_DELETE_ELEM && command!=BPF_MAP_GET_NEXT_KEY) return -EINVAL;
    if (flags && (command!=BPF_MAP_UPDATE_ELEM || flags>BPF_EXIST)) return -EINVAL;
    unsigned index=key ? bucket(key,m->info.key_size) : 0;
    pthread_mutex_lock(&m->owner->lock);
    struct entry **at=&m->buckets[index];
    while (key && *at && memcmp((*at)->data,key,m->info.key_size)) at=&(*at)->next;
    struct entry *e=key ? *at : NULL;
    int r=0;
    if (command==BPF_MAP_GET_NEXT_KEY) {
        if (!e) index=0;
        else e=e->next,++index;
        while (!e && index<BUCKETS) e=m->buckets[index++];
        if (e) memcpy(out,e->data,m->info.key_size); else r=-ENOENT;
    } else if (!key) r=-EFAULT;
    else if (command==BPF_MAP_LOOKUP_ELEM) {
        if (e) memcpy(out,e->data+m->info.key_size,m->info.value_size); else r=-ENOENT;
    } else if (command==BPF_MAP_DELETE_ELEM) {
        if (e) { *at=e->next; free(e); --m->count; } else r=-ENOENT;
    } else if (e && flags==BPF_NOEXIST) r=-EEXIST;
    else if (!e && flags==BPF_EXIST) r=-ENOENT;
    else {
        if (!e) {
            if (m->count==m->info.max_entries) r=-E2BIG;
            else if (!(e=malloc(sizeof(*e)+m->info.key_size+m->info.value_size))) r=-ENOMEM;
            else { e->next=NULL; memcpy(e->data,key,m->info.key_size); *at=e; ++m->count; }
        }
        if (!r) memcpy(e->data+m->info.key_size,value,m->info.value_size);
    }
    pthread_mutex_unlock(&m->owner->lock); return r;
}
static void *retain(void *m) { return md_bpf_map_retain(m); }
static void release(void *m) { md_bpf_map_release(m); }
static const struct md_bpf_handle_type handle_type={retain,release};
struct md_bpf_map *md_bpf_map_control(struct md_control_file file) { return md_bpf_handle_object(file,&handle_type); }
int md_bpf_map_open(struct md_bpf_map *m,const struct md_identity *id,const struct md_control_file_ops **ops,void **context) {
    return md_bpf_handle_open(&handle_type,m,id,ops,context);
}
