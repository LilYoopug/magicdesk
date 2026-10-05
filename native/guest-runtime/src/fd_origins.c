#include "fd_origins.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

enum { BUCKETS=61 };
struct md_fd_origin_entry {
    struct md_fd_origin_entry *next;
    struct md_fs_anchor *origin;
    int fd;
    unsigned flags;
};
struct md_fd_origins {
    atomic_uint refs;
    unsigned owners;
    pthread_mutex_t lock;
    struct md_fd_origin_entry **buckets;
    struct md_fd_order *first, *last;
};
struct md_fd_wakeup {
    atomic_uint refs;
    int fd;
};
int md_fd_wakeup_create(int fd, struct md_fd_wakeup **out) {
    if (!out) return -EINVAL;
    *out=NULL;
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if (!(flags&O_NONBLOCK)) return -EINVAL;
    struct md_fd_wakeup *wake=malloc(sizeof(*wake));
    if (!wake) return -ENOMEM;
    wake->fd=fcntl(fd,F_DUPFD_CLOEXEC,0);
    if (wake->fd<0) { int error=-errno; free(wake); return error; }
    atomic_init(&wake->refs,1); *out=wake; return 0;
}
static struct md_fd_wakeup *wakeup_retain(struct md_fd_wakeup *wake) {
    if (wake) atomic_fetch_add_explicit(&wake->refs,1,memory_order_relaxed);
    return wake;
}
void md_fd_wakeup_release(struct md_fd_wakeup *wake) {
    if (!wake || atomic_fetch_sub_explicit(&wake->refs,1,memory_order_acq_rel)!=1) return;
    close(wake->fd); free(wake);
}
static int wakeup_signal(struct md_fd_wakeup *wake) {
    if (!wake) return 0;
    uint64_t one=1;
    ssize_t n;
    do { n=write(wake->fd,&one,sizeof(one)); } while (n<0 && errno==EINTR);
    return n==(ssize_t)sizeof(one) || (n<0 && errno==EAGAIN) ? 0 : -EIO;
}
static void dispose(struct md_fd_origin_entry *entry) {
    while (entry) {
        struct md_fd_origin_entry *next=entry->next;
        md_fs_anchor_release(entry->origin); free(entry); entry=next;
    }
}
struct md_fd_origins *md_fd_origins_new(void) {
    struct md_fd_origins *t=calloc(1,sizeof(*t));
    if (!t) return NULL;
    if (pthread_mutex_init(&t->lock,NULL)) { free(t); return NULL; }
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
    free(t->buckets); pthread_mutex_destroy(&t->lock); free(t);
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
int md_fd_origins_prepare(struct md_fd_origins *t, struct md_fs_anchor *origin, unsigned flags,
        struct md_fd_origin_update *out) {
    *out=(struct md_fd_origin_update){0};
    if (!t || (flags & ~FD_CLOEXEC)) return -EINVAL;
    struct md_fd_origin_entry *entry=NULL;
    if (origin) {
        entry=calloc(1,sizeof(*entry));
        if (!entry) return -ENOMEM;
        pthread_mutex_lock(&t->lock);
        if (!t->buckets) t->buckets=calloc(BUCKETS,sizeof(*t->buckets));
        int ready=!!t->buckets;
        pthread_mutex_unlock(&t->lock);
        if (!ready) { free(entry); return -ENOMEM; }
        entry->origin=md_fs_anchor_retain(origin); entry->flags=flags;
    }
    out->table=md_fd_origins_pin(t); out->entry=entry; return 0;
}
void md_fd_origins_finish(struct md_fd_origin_update *update, int result_fd) {
    struct md_fd_origins *t=update->table;
    struct md_fd_origin_entry *retired=update->entry;
    if (t && result_fd>=0) {
        pthread_mutex_lock(&t->lock);
        if (t->buckets) {
            struct md_fd_origin_entry **p=slot(t,result_fd);
            retired=*p;
            if (update->entry) {
                update->entry->fd=result_fd;
                update->entry->next=retired ? retired->next : NULL;
                *p=update->entry;
            } else if (retired) *p=retired->next;
            if (retired) retired->next=NULL;
        }
        pthread_mutex_unlock(&t->lock);
    }
    *update=(struct md_fd_origin_update){0};
    dispose(retired); md_fd_origins_unpin(t);
}
int md_fd_origins_set_flags(struct md_fd_origins *t, int fd, unsigned flags) {
    if (!t || fd<0 || (flags & ~FD_CLOEXEC)) return -EINVAL;
    pthread_mutex_lock(&t->lock);
    struct md_fd_origin_entry *entry=t->buckets ? *slot(t,fd) : NULL;
    if (entry) entry->flags=flags;
    pthread_mutex_unlock(&t->lock); return 0;
}
static void remove_entries(struct md_fd_origins *t, unsigned first, unsigned last, int mark, int exec) {
    if (!t) return;
    struct md_fd_origin_entry *retired=NULL;
    pthread_mutex_lock(&t->lock);
    if (t->buckets) for (unsigned i=0;i<BUCKETS;++i) {
        struct md_fd_origin_entry **p=&t->buckets[i];
        while (*p) {
            struct md_fd_origin_entry *e=*p;
            int selected=exec ? !!(e->flags & FD_CLOEXEC) : (unsigned)e->fd>=first && (unsigned)e->fd<=last;
            if (selected && !mark) { *p=e->next; e->next=retired; retired=e; }
            else { if (selected) e->flags|=FD_CLOEXEC; p=&e->next; }
        }
    }
    pthread_mutex_unlock(&t->lock);
    dispose(retired);
}
int md_fd_origins_close_range(struct md_fd_origins *t, unsigned first, unsigned last, int cloexec) {
    if (!t || first>last) return -EINVAL;
    remove_entries(t,first,last,cloexec,0); return 0;
}
void md_fd_origins_exec(struct md_fd_origins *t) { remove_entries(t,0,0,0,1); }

int md_fd_order_begin(struct md_fd_origins *t, struct md_fd_order *op, struct md_fd_wakeup *wake) {
    if (!t || !op) return -EINVAL;
    if (op->state!=MD_FD_ORDER_IDLE || op->table || op->previous || op->next) return -EBUSY;
    op->table=md_fd_origins_pin(t); op->wakeup=wakeup_retain(wake);
    pthread_mutex_lock(&t->lock);
    op->previous=t->last;
    if (t->last) t->last->next=op; else t->first=op;
    t->last=op;
    op->state=t->first==op ? MD_FD_ORDER_READY : MD_FD_ORDER_QUEUED;
    int ready=op->state==MD_FD_ORDER_READY;
    pthread_mutex_unlock(&t->lock); return ready;
}
enum md_fd_order_state md_fd_order_state(const struct md_fd_order *op) {
    if (!op || !op->table) return MD_FD_ORDER_IDLE;
    struct md_fd_origins *t=op->table;
    pthread_mutex_lock(&t->lock);
    enum md_fd_order_state state=op->state;
    pthread_mutex_unlock(&t->lock); return state;
}
int md_fd_order_start(struct md_fd_order *op) {
    if (!op || !op->table) return -EINVAL;
    struct md_fd_origins *t=op->table;
    pthread_mutex_lock(&t->lock);
    int error=op->state!=MD_FD_ORDER_READY ? -EINVAL : 0;
    if (!error) op->state=MD_FD_ORDER_RUNNING;
    pthread_mutex_unlock(&t->lock); return error;
}
static int retire(struct md_fd_order *op) {
    struct md_fd_origins *t=op->table;
    struct md_fd_wakeup *owner=op->wakeup, *next=NULL;
    int first=t->first==op;
    if (op->previous) op->previous->next=op->next; else t->first=op->next;
    if (op->next) op->next->previous=op->previous; else t->last=op->previous;
    *op=(struct md_fd_order){0};
    if (first && t->first) {
        t->first->state=MD_FD_ORDER_READY;
        next=wakeup_retain(t->first->wakeup);
    }
    pthread_mutex_unlock(&t->lock);
    md_fd_origins_unpin(t);
    int error=wakeup_signal(next);
    md_fd_wakeup_release(next); md_fd_wakeup_release(owner);
    return error;
}
int md_fd_order_cancel(struct md_fd_order *op) {
    if (!op || !op->table) return -EINVAL;
    struct md_fd_origins *t=op->table;
    pthread_mutex_lock(&t->lock);
    if (op->state==MD_FD_ORDER_RUNNING || op->state==MD_FD_ORDER_CANCELLING) {
        op->state=MD_FD_ORDER_CANCELLING; pthread_mutex_unlock(&t->lock); return 1;
    }
    if (op->state!=MD_FD_ORDER_QUEUED && op->state!=MD_FD_ORDER_READY) {
        pthread_mutex_unlock(&t->lock); return -EINVAL;
    }
    return retire(op);
}
int md_fd_order_complete(struct md_fd_order *op) {
    if (!op || !op->table) return -EINVAL;
    struct md_fd_origins *t=op->table;
    pthread_mutex_lock(&t->lock);
    if (op->state!=MD_FD_ORDER_RUNNING && op->state!=MD_FD_ORDER_CANCELLING) {
        pthread_mutex_unlock(&t->lock); return -EINVAL;
    }
    return retire(op);
}
