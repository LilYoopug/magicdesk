#include "fd_origins.h"
#include "fd_channel.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>

enum { BUCKETS=61 };
struct md_fd_origin_entry {
    struct md_fd_origin_entry *next;
    struct md_fs_anchor *origin;
    struct md_fd_channel *channel;
    int fd;
    unsigned flags;
    int uncertain;
};
struct md_fd_origins {
    atomic_uint refs;
    unsigned owners;
    pthread_mutex_t lock;
    struct md_fd_origin_entry **buckets;
    struct md_resource_queue order;
};
static void dispose(struct md_fd_origin_entry *entry) {
    while (entry) {
        struct md_fd_origin_entry *next=entry->next;
        md_fs_anchor_release(entry->origin); md_fd_channel_release(entry->channel); free(entry); entry=next;
    }
}
struct md_fd_origins *md_fd_origins_new(void) {
    struct md_fd_origins *t=calloc(1,sizeof(*t));
    if (!t) return NULL;
    if (pthread_mutex_init(&t->lock,NULL)) { free(t); return NULL; }
    if (md_resource_queue_init(&t->order)) { pthread_mutex_destroy(&t->lock); free(t); return NULL; }
    atomic_init(&t->refs,1); t->owners=1;
    return t;
}
struct md_fd_origins *md_fd_origins_pin(struct md_fd_origins *t) {
    if (t) atomic_fetch_add_explicit(&t->refs,1,memory_order_relaxed);
    return t;
}
void md_fd_origins_unpin(struct md_fd_origins *t) {
    if (!t || atomic_fetch_sub_explicit(&t->refs,1,memory_order_acq_rel)!=1) return;
    if (t->buckets) for (unsigned i=0;i<BUCKETS;++i) dispose(t->buckets[i]);
    free(t->buckets); md_resource_queue_destroy(&t->order); pthread_mutex_destroy(&t->lock); free(t);
}
void md_fd_origins_release(struct md_fd_origins *t) {
    if (t) { --t->owners; md_fd_origins_unpin(t); }
}
struct md_fd_origins *md_fd_origins_fork(struct md_fd_origins *t, int shared) {
    if (!t) return NULL;
    if (shared) { ++t->owners; return md_fd_origins_pin(t); }
    struct md_fd_origins *copy=md_fd_origins_new();
    if (!copy) return NULL;
    int error=0;
    pthread_mutex_lock(&t->lock);
    if (t->buckets) for (unsigned i=0;i<BUCKETS && !error;++i) {
        for (struct md_fd_origin_entry *p=t->buckets[i];p;p=p->next) {
            if (!copy->buckets) copy->buckets=calloc(BUCKETS,sizeof(*copy->buckets));
            struct md_fd_origin_entry *entry=copy->buckets ? malloc(sizeof(*entry)) : NULL;
            if (!entry) { error=-ENOMEM; break; }
            *entry=*p; entry->origin=md_fs_anchor_retain(p->origin);
            entry->channel=md_fd_channel_retain(p->channel);
            entry->next=copy->buckets[i]; copy->buckets[i]=entry;
        }
    }
    pthread_mutex_unlock(&t->lock);
    if (error) { md_fd_origins_release(copy); return NULL; }
    return copy;
}
struct md_fd_origins *md_fd_origins_unshare_prepare(struct md_fd_origins *t) {
    return md_fd_origins_fork(t,t && t->owners==1);
}
static struct md_fd_origin_entry **slot(struct md_fd_origins *t, int fd) {
    struct md_fd_origin_entry **p=&t->buckets[(unsigned)fd%BUCKETS];
    while (*p && (*p)->fd!=fd) p=&(*p)->next;
    return p;
}
struct md_fs_anchor *md_fd_origins_get(struct md_fd_origins *t, int fd, unsigned *flags) {
    if (flags) *flags=0;
    if (!t || fd<0) return NULL;
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *entry=t->buckets ? *slot(t,fd) : NULL;
    struct md_fs_anchor *origin=entry ? md_fs_anchor_retain(entry->origin) : NULL;
    if (entry && flags) *flags=entry->flags;
    pthread_mutex_unlock(&t->lock); return origin;
}
int md_fd_origins_capture(struct md_fd_origins *t, const int *fds, unsigned count,
        struct md_fs_anchor **origins) {
    if (!t || (count && (!fds || !origins))) return -EINVAL;
    for (unsigned i=0;i<count;++i) if (fds[i]<-1) return -EINVAL;
    pthread_mutex_lock(&t->lock);
    for (unsigned i=0;i<count;++i) {
        struct md_fd_origin_entry *e=t->buckets && fds[i]>=0 ? *slot(t,fds[i]) : NULL;
        origins[i]=e ? md_fs_anchor_retain(e->origin) : NULL;
    }
    pthread_mutex_unlock(&t->lock); return 0;
}
static int prepare(struct md_fd_origins *t, struct md_fs_anchor *origin, struct md_fd_channel *channel, unsigned flags,
        struct md_fd_origin_update *out) {
    *out=(struct md_fd_origin_update){0};
    if (!t || (flags & ~FD_CLOEXEC)) return -EINVAL;
    struct md_fd_origin_entry *entry=NULL;
    if (origin || channel) {
        entry=calloc(1,sizeof(*entry));
        if (!entry) return -ENOMEM;
        pthread_mutex_lock(&t->lock);
        if (!t->buckets) t->buckets=calloc(BUCKETS,sizeof(*t->buckets));
        int ready=!!t->buckets;
        pthread_mutex_unlock(&t->lock);
        if (!ready) { free(entry); return -ENOMEM; }
        entry->origin=md_fs_anchor_retain(origin); entry->flags=flags;
        entry->channel=md_fd_channel_retain(channel);
    }
    out->table=md_fd_origins_pin(t); out->entry=entry; return 0;
}
int md_fd_origins_prepare(struct md_fd_origins *t, struct md_fs_anchor *origin, unsigned flags,
        struct md_fd_origin_update *out) {
    return prepare(t,origin,NULL,flags,out);
}
int md_fd_origins_prepare_channel(struct md_fd_origins *t, struct md_fd_channel *channel, unsigned flags,
        struct md_fd_origin_update *out) {
    if (!channel) { *out=(struct md_fd_origin_update){0}; return -EINVAL; }
    return prepare(t,NULL,channel,flags,out);
}
int md_fd_origins_prepare_copy(struct md_fd_origins *t, int source, unsigned flags,
        struct md_fd_origin_update *out) {
    if (!t) { *out=(struct md_fd_origin_update){0}; return -EINVAL; }
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *e=t->buckets && source>=0 ? *slot(t,source) : NULL;
    struct md_fs_anchor *origin=md_fs_anchor_retain(e ? e->origin : NULL);
    struct md_fd_channel *channel=md_fd_channel_retain(e ? e->channel : NULL);
    int uncertain=e && e->uncertain;
    pthread_mutex_unlock(&t->lock);
    int error=prepare(t,origin,channel,flags,out);
    if (!error && out->entry) out->entry->uncertain=uncertain;
    md_fs_anchor_release(origin); md_fd_channel_release(channel); return error;
}
int md_fd_origins_channel(struct md_fd_origins *t, int *number, struct md_fd_channel **out) {
    if (!t || !number || !out || *out) return -EINVAL;
    struct md_fd_channel *channel=NULL; *number=-1;
    int uncertain=0;
    pthread_mutex_lock(&t->lock);
    if (t->buckets) for (unsigned i=0;i<BUCKETS && !channel;++i)
        for (struct md_fd_origin_entry *e=t->buckets[i];e;e=e->next)
            if (e->channel) {
                if (e->uncertain) uncertain=1;
                else { channel=md_fd_channel_retain(e->channel); *number=e->fd; break; }
            }
    pthread_mutex_unlock(&t->lock); *out=channel;
    return !channel && uncertain ? -ESTALE : 0;
}
static struct md_fd_origin_entry *install(struct md_fd_origins *t,
        struct md_fd_origin_entry *entry, int fd) {
    if (!t->buckets) return NULL;
    struct md_fd_origin_entry **p=slot(t,fd), *retired=*p;
    if (entry) {
        entry->fd=fd; entry->next=retired ? retired->next : NULL; *p=entry;
    } else if (retired) *p=retired->next;
    if (retired) retired->next=NULL;
    return retired;
}
int md_fd_origins_channel_candidate(struct md_fd_origins *t, int *number, struct md_fd_channel **out) {
    if (!t || !number || !out || *out) return -EINVAL;
    *number=-1;
    pthread_mutex_lock(&t->lock);
    if (t->buckets) for (unsigned i=0;i<BUCKETS && !*out;++i)
        for (struct md_fd_origin_entry *e=t->buckets[i];e;e=e->next)
            if (e->channel && e->uncertain) { *out=md_fd_channel_retain(e->channel); *number=e->fd; break; }
    pthread_mutex_unlock(&t->lock);
    return *out ? 0 : -ESTALE;
}
int md_fd_origins_channel_resolve(struct md_fd_origins *t, int number, struct md_fd_channel *channel,
        int same, unsigned flags) {
    if (!t || number<0 || !channel || (same!=0 && same!=1) || (flags&~FD_CLOEXEC)) return -EINVAL;
    struct md_fd_origin_entry *retired=NULL;
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *e=t->buckets ? *slot(t,number) : NULL;
    int error=!e || !e->uncertain || e->channel!=channel ? -ESTALE : 0;
    if (!error) {
        if (same) { e->uncertain=0; e->flags=flags; }
        else retired=install(t,NULL,number);
    }
    pthread_mutex_unlock(&t->lock); dispose(retired); return error;
}
void md_fd_origins_finish(struct md_fd_origin_update *update, int result_fd) {
    struct md_fd_origins *t=update->table;
    struct md_fd_origin_entry *retired=update->entry;
    if (t && result_fd>=0) {
        pthread_mutex_lock(&t->lock);
        retired=install(t,update->entry,result_fd);
        pthread_mutex_unlock(&t->lock);
    }
    *update=(struct md_fd_origin_update){0};
    dispose(retired); md_fd_origins_unpin(t);
}
int md_fd_origins_prepare_batch(struct md_fd_origins *t, struct md_fs_anchor *const *origins,
        unsigned flags, unsigned count, struct md_fd_origin_update *updates) {
    if (!t || (flags & ~FD_CLOEXEC) || (count && (!origins || !updates))) return -EINVAL;
    for (unsigned i=0;i<count;++i) updates[i]=(struct md_fd_origin_update){0};
    for (unsigned i=0;i<count;++i) {
        int error=md_fd_origins_prepare(t,origins[i],flags,updates+i);
        if (error) {
            for (unsigned j=0;j<i;++j) md_fd_origins_finish(updates+j,-1);
            return error;
        }
    }
    return 0;
}
int md_fd_origins_finish_batch(struct md_fd_origin_update *updates, unsigned count,
        const int *fds, unsigned received) {
    if (received>count || (count && !updates) || (received && !fds)) return -EINVAL;
    if (!count) return 0;
    struct md_fd_origins *t=updates[0].table;
    if (!t) return -EINVAL;
    for (unsigned i=0;i<count;++i) if (updates[i].table!=t) return -EINVAL;
    for (unsigned i=0;i<received;++i) {
        if (fds[i]<0) return -EPROTO;
        for (unsigned j=0;j<i;++j) if (fds[i]==fds[j]) return -EPROTO;
    }
    struct md_fd_origin_entry *retired=NULL;
    pthread_mutex_lock(&t->lock);
    for (unsigned i=0;i<count;++i) {
        struct md_fd_origin_entry *old=i<received ? install(t,updates[i].entry,fds[i]) : updates[i].entry;
        if (old) { old->next=retired; retired=old; }
        updates[i]=(struct md_fd_origin_update){0};
    }
    pthread_mutex_unlock(&t->lock);
    dispose(retired);
    for (unsigned i=0;i<count;++i) md_fd_origins_unpin(t);
    return 0;
}
int md_fd_origins_set_flags(struct md_fd_origins *t, int fd, unsigned flags) {
    if (!t || fd<0 || (flags & ~FD_CLOEXEC)) return -EINVAL;
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *entry=t->buckets ? *slot(t,fd) : NULL;
    if (entry) entry->flags=flags;
    pthread_mutex_unlock(&t->lock); return 0;
}
enum retirement { RETIRE_CLOSE, RETIRE_CLOEXEC, RETIRE_UNCERTAIN };
static void remove_entries(struct md_fd_origins *t, unsigned first, unsigned last, enum retirement action, int exec) {
    if (!t) return;
    struct md_fd_origin_entry *retired=NULL;
    pthread_mutex_lock(&t->lock);
    if (t->buckets) for (unsigned i=0;i<BUCKETS;++i) {
        struct md_fd_origin_entry **p=&t->buckets[i];
        while (*p) {
            struct md_fd_origin_entry *e=*p;
            int selected=exec ? !e->uncertain && !!(e->flags & FD_CLOEXEC) : (unsigned)e->fd>=first && (unsigned)e->fd<=last;
            if (selected && action==RETIRE_UNCERTAIN && e->channel) { e->uncertain=1; p=&e->next; continue; }
            if (selected && action!=RETIRE_CLOEXEC) { *p=e->next; e->next=retired; retired=e; }
            else { if (selected) e->flags|=FD_CLOEXEC; p=&e->next; }
        }
    }
    pthread_mutex_unlock(&t->lock);
    dispose(retired);
}
int md_fd_origins_close_range(struct md_fd_origins *t, unsigned first, unsigned last, int cloexec) {
    if (!t || first>last) return -EINVAL;
    remove_entries(t,first,last,cloexec ? RETIRE_CLOEXEC : RETIRE_CLOSE,0); return 0;
}
int md_fd_origins_abandon_range(struct md_fd_origins *t, unsigned first, unsigned last) {
    if (!t || first>last) return -EINVAL;
    remove_entries(t,first,last,RETIRE_UNCERTAIN,0); return 0;
}
void md_fd_origins_exec(struct md_fd_origins *t) { remove_entries(t,0,0,RETIRE_CLOSE,1); }

int md_fd_order_begin(struct md_fd_origins *t, struct md_fd_order *op, struct md_resource_wakeup *wake) {
    if (!t || !op) return -EINVAL;
    if (op->table) return -EBUSY;
    op->table=md_fd_origins_pin(t);
    int ready=md_resource_order_begin(&t->order,&op->order,wake);
    if (ready<0) { md_fd_origins_unpin(op->table); op->table=NULL; }
    return ready;
}
enum md_resource_order_state md_fd_order_state(const struct md_fd_order *op) {
    return md_resource_order_state(op ? &op->order : NULL);
}
int md_fd_order_start(struct md_fd_order *op) {
    return md_resource_order_start(op ? &op->order : NULL);
}
static int retired(struct md_fd_order *op, int result) {
    if (op && !op->order.queue) { md_fd_origins_unpin(op->table); op->table=NULL; }
    return result;
}
int md_fd_order_cancel(struct md_fd_order *op) {
    return retired(op,md_resource_order_cancel(op ? &op->order : NULL));
}
int md_fd_order_complete(struct md_fd_order *op) {
    return retired(op,md_resource_order_complete(op ? &op->order : NULL));
}
