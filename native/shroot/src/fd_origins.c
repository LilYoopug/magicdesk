#include "fd_origins.h"
#include "fd_channel.h"
#include "fd_selector.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>

enum { BUCKETS=61 };
struct md_fd_loan {
    atomic_uint refs;
    atomic_int active;
    const struct md_fd_origins *home;
};
struct md_fd_origin_entry {
    struct md_fd_origin_entry *next;
    struct md_fd_object *object;
    struct md_fd_channel *channel;
    struct md_fd_loan *loan;
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
    uint64_t generation;
    unsigned loans;
};
struct md_fd_loan *md_fd_loan_new(struct md_fd_origins *home) {
    if (!home) { errno=EINVAL; return NULL; }
    struct md_fd_loan *loan=calloc(1,sizeof(*loan));
    if (loan) { atomic_init(&loan->refs,1); atomic_init(&loan->active,1); loan->home=home; }
    return loan;
}
static struct md_fd_loan *loan_retain(struct md_fd_loan *loan) {
    if (loan) atomic_fetch_add_explicit(&loan->refs,1,memory_order_relaxed);
    return loan;
}
void md_fd_loan_end(struct md_fd_loan *loan) {
    if (loan) atomic_store_explicit(&loan->active,0,memory_order_release);
}
void md_fd_loan_release(struct md_fd_loan *loan) {
    if (loan && atomic_fetch_sub_explicit(&loan->refs,1,memory_order_acq_rel)==1) free(loan);
}
static void dispose(struct md_fd_origin_entry *entry) {
    while (entry) {
        struct md_fd_origin_entry *next=entry->next;
        md_fd_object_release(entry->object); md_fd_channel_release(entry->channel);
        md_fd_loan_release(entry->loan); free(entry); entry=next;
    }
}
struct md_fd_origins *md_fd_origins_new(void) {
    struct md_fd_origins *t=calloc(1,sizeof(*t));
    if (!t) return NULL;
    if (pthread_mutex_init(&t->lock,NULL)) { free(t); return NULL; }
    if (md_resource_queue_init(&t->order)) { pthread_mutex_destroy(&t->lock); free(t); return NULL; }
    atomic_init(&t->refs,1); t->owners=1; t->generation=1;
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
            *entry=*p; entry->object=md_fd_object_retain(p->object);
            entry->channel=md_fd_channel_retain(p->channel);
            entry->loan=loan_retain(p->loan); copy->loans+=entry->loan!=NULL;
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
static void changed(struct md_fd_origins *t) {
    /* Saturation must invalidate discovery, not allow an ABA after wrapping. */
    if (t->generation!=UINT64_MAX) ++t->generation;
}
int md_fd_origins_observe(struct md_fd_origins *t,int fd,struct md_fd_observation *out) {
    if (!t || !out) return -EINVAL;
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *e=t->buckets && fd>=0 ? *slot(t,fd) : NULL;
    int error=t->generation==UINT64_MAX ? -EOVERFLOW : e && e->uncertain ? -ESTALE : 0;
    if (!error) *out=(struct md_fd_observation){md_fd_object_selectors(e ? e->object : NULL),t->generation};
    pthread_mutex_unlock(&t->lock); return error;
}
int md_fd_origins_validate(const struct md_fd_order *turn,uint64_t generation) {
    if (!turn || !turn->table || !generation) return -EINVAL;
    if (md_fd_order_state(turn)!=MD_RESOURCE_ORDER_RUNNING) return -EBUSY;
    struct md_fd_origins *t=turn->table;
    pthread_mutex_lock(&t->lock);
    int error=t->generation==UINT64_MAX ? -EOVERFLOW : t->generation!=generation ? -EAGAIN : 0;
    pthread_mutex_unlock(&t->lock); return error;
}
struct md_fd_object *md_fd_origins_object(struct md_fd_origins *t, int fd, unsigned *flags) {
    if (flags) *flags=0;
    if (!t || fd<0) return NULL;
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *entry=t->buckets ? *slot(t,fd) : NULL;
    struct md_fd_object *origin=entry ? md_fd_object_retain(entry->object) : NULL;
    if (entry && flags) *flags=entry->flags;
    pthread_mutex_unlock(&t->lock); return origin;
}
struct md_fs_anchor *md_fd_origins_get(struct md_fd_origins *t, int fd, unsigned *flags) {
    struct md_fd_object *object=md_fd_origins_object(t,fd,flags);
    struct md_fs_anchor *anchor=md_fs_anchor_from_object(object);
    if (!anchor) md_fd_object_release(object);
    return anchor;
}
int md_fd_origins_capture(struct md_fd_origins *t, const int *fds, unsigned count,
        struct md_fs_anchor **origins) {
    if (!t || (count && (!fds || !origins))) return -EINVAL;
    for (unsigned i=0;i<count;++i) if (fds[i]<-1) return -EINVAL;
    pthread_mutex_lock(&t->lock);
    for (unsigned i=0;i<count;++i) {
        struct md_fd_origin_entry *e=t->buckets && fds[i]>=0 ? *slot(t,fds[i]) : NULL;
        origins[i]=e ? md_fs_anchor_retain(md_fs_anchor_from_object(e->object)) : NULL;
    }
    pthread_mutex_unlock(&t->lock); return 0;
}
int md_fd_origins_capture_objects(struct md_fd_origins *t, const int *fds, unsigned count,
        struct md_fd_object **objects) {
    if (!t || (count && (!fds || !objects))) return -EINVAL;
    for (unsigned i=0;i<count;++i) if (fds[i]<-1) return -EINVAL;
    pthread_mutex_lock(&t->lock);
    for (unsigned i=0;i<count;++i) {
        struct md_fd_origin_entry *e=t->buckets && fds[i]>=0 ? *slot(t,fds[i]) : NULL;
        objects[i]=e ? md_fd_object_retain(e->object) : NULL;
    }
    pthread_mutex_unlock(&t->lock); return 0;
}
int md_fd_origins_aliases(const struct md_fd_order *turn,const struct md_fd_object *object,
        int *numbers,unsigned capacity,unsigned *count) {
    if (!turn || !turn->table || !object || !count || (capacity && !numbers)) return -EINVAL;
    if (md_fd_order_state(turn)!=MD_RESOURCE_ORDER_RUNNING) return -EBUSY;
    struct md_fd_origins *t=turn->table;
    unsigned found=0; int error=0;
    pthread_mutex_lock(&t->lock);
    if (t->buckets) for (unsigned i=0;i<BUCKETS;++i)
        for (struct md_fd_origin_entry *e=t->buckets[i];e;e=e->next) if (e->object==object) {
            if (e->uncertain) error=-ESTALE;
            ++found;
        }
    if (!error && numbers && found>capacity) error=-ENOSPC;
    if (!error && numbers) {
        unsigned n=0;
        if (t->buckets) for (unsigned i=0;i<BUCKETS;++i)
            for (struct md_fd_origin_entry *e=t->buckets[i];e;e=e->next)
                if (e->object==object) numbers[n++]=e->fd;
    }
    if (error!=-ESTALE) *count=found;
    pthread_mutex_unlock(&t->lock); return error;
}
static int prepare(struct md_fd_origins *t, struct md_fd_object *origin, struct md_fd_channel *channel, unsigned flags,
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
        entry->object=md_fd_object_retain(origin); entry->flags=flags;
        entry->channel=md_fd_channel_retain(channel);
    }
    out->table=md_fd_origins_pin(t); out->entry=entry; return 0;
}
int md_fd_origins_prepare(struct md_fd_origins *t, struct md_fs_anchor *origin, unsigned flags,
        struct md_fd_origin_update *out) {
    return prepare(t,md_fs_anchor_object(origin),NULL,flags,out);
}
int md_fd_origins_prepare_object(struct md_fd_origins *t, struct md_fd_object *object, unsigned flags,
        struct md_fd_origin_update *out) {
    return prepare(t,object,NULL,flags,out);
}
int md_fd_origins_prepare_channel(struct md_fd_origins *t, struct md_fd_channel *channel, unsigned flags,
        struct md_fd_origin_update *out) {
    if (!channel) { *out=(struct md_fd_origin_update){0}; return -EINVAL; }
    return prepare(t,NULL,channel,flags,out);
}
int md_fd_origins_prepare_loan(struct md_fd_origin_update *update,struct md_fd_loan *loan) {
    if (!update || !loan || update->table!=loan->home || !update->entry
            || update->entry->loan || !(update->entry->flags&FD_CLOEXEC)
            || !atomic_load_explicit(&loan->active,memory_order_acquire)) return -EINVAL;
    update->entry->loan=loan_retain(loan); return 0;
}
int md_fd_origins_has_loans(struct md_fd_origins *t) {
    if (!t) return 0;
    pthread_mutex_lock(&t->lock); int found=t->loans!=0;
    pthread_mutex_unlock(&t->lock); return found;
}
int md_fd_origins_exclusive(const struct md_fd_order *turn) {
    return turn && turn->table && md_fd_order_state(turn)==MD_RESOURCE_ORDER_RUNNING
        && turn->table->owners==1;
}
int md_fd_origins_loan_next(const struct md_fd_order *turn,int *number) {
    if (!turn || !turn->table || !number) return -EINVAL;
    if (md_fd_order_state(turn)!=MD_RESOURCE_ORDER_RUNNING) return -EBUSY;
    struct md_fd_origins *t=turn->table;
    int result=0; *number=-1;
    pthread_mutex_lock(&t->lock);
    if (t->loans) for (unsigned i=0;i<BUCKETS && !result;++i)
        for (struct md_fd_origin_entry *e=t->buckets[i];e;e=e->next) {
            if (!e->loan || (atomic_load_explicit(&e->loan->active,memory_order_acquire)
                    && e->loan->home==t)) continue;
            result=e->uncertain ? -ESTALE : 1;
            if (result==1) *number=e->fd;
            break;
        }
    pthread_mutex_unlock(&t->lock); return result;
}
int md_fd_origins_prepare_copy(struct md_fd_origins *t, int source, unsigned flags,
        struct md_fd_origin_update *out) {
    if (!t) { *out=(struct md_fd_origin_update){0}; return -EINVAL; }
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *e=t->buckets && source>=0 ? *slot(t,source) : NULL;
    struct md_fd_object *origin=md_fd_object_retain(e ? e->object : NULL);
    struct md_fd_channel *channel=md_fd_channel_retain(e ? e->channel : NULL);
    int uncertain=e && e->uncertain;
    pthread_mutex_unlock(&t->lock);
    int error=prepare(t,origin,channel,flags,out);
    if (!error && out->entry) out->entry->uncertain=uncertain;
    md_fd_object_release(origin); md_fd_channel_release(channel); return error;
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
    changed(t);
    if (!t->buckets) return NULL;
    struct md_fd_origin_entry **p=slot(t,fd), *retired=*p;
    t->loans+=(entry && entry->loan)!=0;
    t->loans-=(retired && retired->loan)!=0;
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
        if (same) { e->uncertain=0; e->flags=flags; changed(t); }
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
void md_fd_origins_abandon(struct md_fd_origin_update *update) {
    if (update->table) {
        pthread_mutex_lock(&update->table->lock);
        changed(update->table);
        pthread_mutex_unlock(&update->table->lock);
    }
    struct md_fd_object *object=update->entry ? update->entry->object : NULL;
    if (object && object->type->alias_lost) object->type->alias_lost(object);
    md_fd_origins_finish(update,-1);
}
int md_fd_origins_prepare_batch(struct md_fd_origins *t, struct md_fd_object *const *origins,
        unsigned flags, unsigned count, struct md_fd_origin_update *updates) {
    if (!t || (flags & ~FD_CLOEXEC) || (count && (!origins || !updates))) return -EINVAL;
    for (unsigned i=0;i<count;++i) updates[i]=(struct md_fd_origin_update){0};
    for (unsigned i=0;i<count;++i) {
        int error=md_fd_origins_prepare_object(t,origins[i],flags,updates+i);
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
    changed(t);
    pthread_mutex_unlock(&t->lock); return 0;
}
enum retirement { RETIRE_CLOSE, RETIRE_CLOEXEC, RETIRE_UNCERTAIN };
static void remove_entries(struct md_fd_origins *t, unsigned first, unsigned last, enum retirement action, int exec) {
    if (!t) return;
    struct md_fd_origin_entry *retired=NULL;
    pthread_mutex_lock(&t->lock);
    changed(t);
    if (t->buckets) for (unsigned i=0;i<BUCKETS;++i) {
        struct md_fd_origin_entry **p=&t->buckets[i];
        while (*p) {
            struct md_fd_origin_entry *e=*p;
            int selected=exec ? !e->uncertain && !!(e->flags & FD_CLOEXEC) : (unsigned)e->fd>=first && (unsigned)e->fd<=last;
            if (selected && action==RETIRE_UNCERTAIN && (e->channel || e->loan)) { e->uncertain=1; p=&e->next; continue; }
            if (selected && action!=RETIRE_CLOEXEC) {
                t->loans-=e->loan!=NULL; *p=e->next; e->next=retired; retired=e;
            }
            else { if (selected) e->flags|=FD_CLOEXEC; p=&e->next; }
        }
    }
    pthread_mutex_unlock(&t->lock);
    if (action==RETIRE_UNCERTAIN) for (struct md_fd_origin_entry *e=retired;e;e=e->next)
        if (e->object && e->object->type->alias_lost) e->object->type->alias_lost(e->object);
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
