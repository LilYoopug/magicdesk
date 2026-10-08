#define _GNU_SOURCE
#include "pid_namespace.h"
#include "namespace_identity.h"
#include "guest_identity.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

enum { PID_LEVELS=32, PID_BUCKETS=127 };
struct pid_number {
    struct pid_number *next;
    struct md_pid_identity *identity;
    struct md_pid_namespace *space;
    pid_t number;
};
struct md_pid_namespace {
    atomic_uint references;
    pthread_mutex_t lock;
    struct md_pid_namespace *parent;
    struct md_pid_namespace *registry_next;
    struct md_user_namespace *owner;
    uint64_t inode;
    unsigned depth;
    pid_t next;
    atomic_int dead;
    int initialized;
    struct pid_number *numbers[PID_BUCKETS];
};
struct md_pid_identity {
    atomic_uint references;
    struct md_pid_namespace *space;
    atomic_int native, group, live, subreaper, reaped;
    unsigned count;
    struct md_pid_identity *retired_next;
    struct md_identity exit_identity;
    int credentials;
    struct pid_number numbers[];
};
static pthread_mutex_t registry_lock=PTHREAD_MUTEX_INITIALIZER;
static struct md_pid_namespace *registry;
struct md_pid_namespace *md_pid_namespace_new(struct md_pid_namespace *parent, struct md_user_namespace *owner) {
    if (md_pid_namespace_depth(parent)>=PID_LEVELS) { errno=ENOSPC; return NULL; }
    if (parent && !md_user_namespace_contains(parent->owner,owner)) { errno=EINVAL; return NULL; }
    struct md_pid_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    int error=pthread_mutex_init(&n->lock,NULL);
    if (error) { free(n); errno=error; return NULL; }
    error=md_namespace_identity_new(&n->inode);
    if (error) { pthread_mutex_destroy(&n->lock); free(n); errno=-error; return NULL; }
    atomic_init(&n->references,1); atomic_init(&n->dead,0);
    n->parent=md_pid_namespace_retain(parent); n->owner=md_user_namespace_retain(owner);
    n->depth=md_pid_namespace_depth(parent)+1; n->next=1;
    pthread_mutex_lock(&registry_lock);
    n->registry_next=registry; registry=n;
    pthread_mutex_unlock(&registry_lock);
    return n;
}
struct md_pid_namespace *md_pid_namespace_retain(struct md_pid_namespace *n) {
    if (n) atomic_fetch_add_explicit(&n->references,1,memory_order_relaxed);
    return n;
}
void md_pid_namespace_release(struct md_pid_namespace *n) {
    if (!n || atomic_fetch_sub_explicit(&n->references,1,memory_order_acq_rel)!=1) return;
    pthread_mutex_lock(&registry_lock);
    struct md_pid_namespace **slot=&registry;
    while (*slot!=n) slot=&(*slot)->registry_next;
    *slot=n->registry_next;
    pthread_mutex_unlock(&registry_lock);
    for (unsigned i=0;i<PID_BUCKETS;++i) assert(!n->numbers[i]);
    md_pid_namespace_release(n->parent); md_user_namespace_release(n->owner);
    pthread_mutex_destroy(&n->lock); free(n);
}
struct md_pid_namespace *md_pid_namespace_by_inode(uint64_t inode) {
    struct md_pid_namespace *result=NULL;
    pthread_mutex_lock(&registry_lock);
    for (struct md_pid_namespace *n=registry;n;n=n->registry_next) if (n->inode==inode) {
        unsigned count=atomic_load_explicit(&n->references,memory_order_relaxed);
        while (count && count<UINT_MAX) {
            if (atomic_compare_exchange_weak_explicit(&n->references,&count,count+1,
                    memory_order_acquire,memory_order_relaxed)) { result=n; break; }
        }
        break;
    }
    pthread_mutex_unlock(&registry_lock);
    return result;
}
struct md_pid_namespace *md_pid_namespace_parent(const struct md_pid_namespace *n) { return n ? n->parent : NULL; }
const struct md_user_namespace *md_pid_namespace_owner(const struct md_pid_namespace *n) { return n ? n->owner : NULL; }
uint64_t md_pid_namespace_inode(const struct md_pid_namespace *n) { return n ? n->inode : UINT64_C(0xeffffffc); }
unsigned md_pid_namespace_depth(const struct md_pid_namespace *n) { return n ? n->depth : 0; }
int md_pid_namespace_dead(const struct md_pid_namespace *n) { return n && atomic_load_explicit(&n->dead,memory_order_acquire); }
int md_pid_namespace_initialized(struct md_pid_namespace *n) {
    if (!n) return 1;
    pthread_mutex_lock(&n->lock);
    int value=n->initialized;
    pthread_mutex_unlock(&n->lock); return value;
}
int md_pid_namespace_contains(const struct md_pid_namespace *parent, const struct md_pid_namespace *child) {
    while (child && child!=parent) child=child->parent;
    return child==parent;
}
static struct pid_number **slot(struct md_pid_namespace *n,pid_t number) {
    struct pid_number **p=&n->numbers[(unsigned)number%PID_BUCKETS];
    while (*p && (*p)->number!=number) p=&(*p)->next;
    return p;
}
static int reserve(struct md_pid_namespace *n, struct pid_number *number) {
    pthread_mutex_lock(&n->lock);
    int error=0;
    if (md_pid_namespace_dead(n)) error=-ENOMEM;
    pid_t start=!n->initialized && !*slot(n,1) ? 1 : n->next, next=start;
    if (!error) {
        do {
            if (!*slot(n,next)) break;
            next=next==INT_MAX ? 2 : next+1;
        } while (next!=start);
        if (*slot(n,next)) error=-EAGAIN;
    }
    if (!error) {
        number->space=n; number->number=next; *slot(n,next)=number;
        n->next=next==INT_MAX ? 2 : next+1;
    }
    pthread_mutex_unlock(&n->lock); return error;
}
int md_pid_identity_prepare(struct md_pid_namespace *space, struct md_pid_identity **out) {
    *out=NULL;
    if (!space) return 0;
    struct md_pid_identity *p=calloc(1,sizeof(*p)+space->depth*sizeof(*p->numbers));
    if (!p) return -ENOMEM;
    atomic_init(&p->references,1); atomic_init(&p->native,0); atomic_init(&p->group,0); atomic_init(&p->live,0);
    atomic_init(&p->subreaper,0);
    atomic_init(&p->reaped,0);
    p->space=md_pid_namespace_retain(space);
    for (struct md_pid_namespace *n=space;n;n=n->parent) {
        struct pid_number *number=p->numbers+p->count; number->identity=p;
        int error=reserve(n,number);
        if (error) { md_pid_identity_release(p); return error; }
        ++p->count;
    }
    *out=p; return 0;
}
int md_pid_identity_publish(struct md_pid_identity *p, pid_t native, pid_t group) {
    if (!p) return 0;
    if (native<=0 || group<=0 || atomic_load_explicit(&p->native,memory_order_relaxed)) return -EINVAL;
    for (unsigned i=0;i<p->count;++i) {
        struct md_pid_namespace *n=p->numbers[i].space;
        if (p->numbers[i].number==1) {
            pthread_mutex_lock(&n->lock); n->initialized=1; pthread_mutex_unlock(&n->lock);
        }
    }
    atomic_store_explicit(&p->group,group,memory_order_relaxed);
    atomic_store_explicit(&p->native,native,memory_order_release);
    atomic_store_explicit(&p->live,1,memory_order_release); return 0;
}
struct md_pid_identity *md_pid_identity_retain(struct md_pid_identity *p) {
    if (p) atomic_fetch_add_explicit(&p->references,1,memory_order_relaxed);
    return p;
}
static struct md_pid_identity *try_retain(struct md_pid_identity *p) {
    unsigned count=atomic_load_explicit(&p->references,memory_order_relaxed);
    while (count && count<UINT_MAX) {
        if (atomic_compare_exchange_weak_explicit(&p->references,&count,count+1,
                memory_order_acquire,memory_order_relaxed)) return p;
    }
    return NULL;
}
void md_pid_identity_release(struct md_pid_identity *p) {
    if (!p || atomic_fetch_sub_explicit(&p->references,1,memory_order_acq_rel)!=1) return;
    for (unsigned i=0;i<p->count;++i) {
        struct pid_number *number=p->numbers+i; struct md_pid_namespace *n=number->space;
        pthread_mutex_lock(&n->lock);
        struct pid_number **link=slot(n,number->number); assert(*link==number); *link=number->next;
        pthread_mutex_unlock(&n->lock);
    }
    if (p->credentials) md_identity_release(&p->exit_identity);
    md_pid_namespace_release(p->space); free(p);
}
struct md_pid_namespace *md_pid_identity_namespace(const struct md_pid_identity *p) { return p ? p->space : NULL; }
pid_t md_pid_identity_native(const struct md_pid_identity *p) { return p ? atomic_load_explicit(&p->native,memory_order_acquire) : 0; }
pid_t md_pid_identity_group(const struct md_pid_identity *p) { return p ? atomic_load_explicit(&p->group,memory_order_acquire) : 0; }
pid_t md_pid_identity_number(const struct md_pid_identity *p, const struct md_pid_namespace *n) {
    if (!p) return 0;
    if (!n) return md_pid_identity_native(p);
    for (unsigned i=0;i<p->count;++i) if (p->numbers[i].space==n) return p->numbers[i].number;
    return 0;
}
int md_pid_identity_live(const struct md_pid_identity *p) { return p && atomic_load_explicit(&p->live,memory_order_acquire); }
int md_pid_identity_subreaper(const struct md_pid_identity *p) { return p && atomic_load_explicit(&p->subreaper,memory_order_relaxed); }
void md_pid_identity_set_subreaper(struct md_pid_identity *p,int value) {
    if (p) atomic_store_explicit(&p->subreaper,!!value,memory_order_relaxed);
}
void md_pid_identity_exit_credentials(struct md_pid_identity *p,const struct md_identity *identity) {
    if (!p) return;
    if (p->credentials) md_identity_release(&p->exit_identity);
    p->exit_identity=md_identity_copy(identity); p->credentials=1;
}
const struct md_identity *md_pid_identity_credentials(const struct md_pid_identity *p) {
    return p && p->credentials ? &p->exit_identity : NULL;
}
int md_pid_identity_exit(struct md_pid_identity *p) {
    if (!p || !atomic_exchange_explicit(&p->live,0,memory_order_acq_rel)) return 0;
    struct md_pid_namespace *n=p->space;
    pthread_mutex_lock(&n->lock);
    struct pid_number *init=*slot(n,1);
    pid_t group=md_pid_identity_group(p);
    int last=init && md_pid_identity_group(init->identity)==group;
    for (unsigned i=0;last && i<PID_BUCKETS;++i)
        for (struct pid_number *other=n->numbers[i];other;other=other->next)
            if (md_pid_identity_live(other->identity) && md_pid_identity_group(other->identity)==group) {
                last=0; break;
            }
    if (last) atomic_store_explicit(&n->dead,1,memory_order_release);
    pthread_mutex_unlock(&n->lock); return last;
}
void md_pid_identity_reap(struct md_pid_identity *p) {
    if (p && !md_pid_identity_live(p)) atomic_store_explicit(&p->reaped,1,memory_order_release);
}
void md_pid_identity_exec(struct md_pid_identity *thread,struct md_pid_identity *group) {
    if (!thread || !group || thread==group) return;
    assert(thread->space==group->space && md_pid_identity_group(thread)==md_pid_identity_native(group));
    atomic_store_explicit(&group->reaped,0,memory_order_release);
    atomic_store_explicit(&group->live,1,memory_order_release);
    atomic_store_explicit(&thread->live,0,memory_order_release);
}
struct md_pid_identity *md_pid_namespace_lookup(struct md_pid_namespace *n,pid_t visible) {
    if (!n || visible<=0) return NULL;
    pthread_mutex_lock(&n->lock);
    struct pid_number *number=*slot(n,visible);
    struct md_pid_identity *p=number && md_pid_identity_native(number->identity)
        && !atomic_load_explicit(&number->identity->reaped,memory_order_acquire)
        ? try_retain(number->identity) : NULL;
    pthread_mutex_unlock(&n->lock); return p;
}
struct md_pid_identity *md_pid_namespace_find(struct md_pid_namespace *n,pid_t native) {
    if (!n || native<=0) return NULL;
    struct md_pid_identity *p=NULL;
    pthread_mutex_lock(&n->lock);
    for (unsigned i=0;i<PID_BUCKETS && !p;++i)
        for (struct pid_number *number=n->numbers[i];number;number=number->next)
            if (md_pid_identity_native(number->identity)==native
                    && !atomic_load_explicit(&number->identity->reaped,memory_order_acquire)) {
                p=try_retain(number->identity); break;
            }
    pthread_mutex_unlock(&n->lock); return p;
}
void md_pid_retired_take(struct md_pid_retired *retired, struct md_pid_identity *p) {
    if (!p) return;
    p->retired_next=retired->head; retired->head=p;
}
struct md_pid_identity *md_pid_retired_find(const struct md_pid_retired *retired,pid_t native) {
    for (struct md_pid_identity *p=retired->head;p;p=p->retired_next)
        if (md_pid_identity_native(p)==native) return p;
    return NULL;
}
void md_pid_retired_reap(struct md_pid_retired *retired, pid_t native) {
    struct md_pid_identity **slot=&retired->head;
    while (*slot && md_pid_identity_native(*slot)!=native) slot=&(*slot)->retired_next;
    if (*slot) {
        struct md_pid_identity *p=*slot; *slot=p->retired_next; p->retired_next=NULL;
        md_pid_identity_reap(p);
        md_pid_identity_release(p);
    }
}
void md_pid_retired_release(struct md_pid_retired *retired) {
    while (retired->head) md_pid_retired_reap(retired,md_pid_identity_native(retired->head));
}
void md_pid_retired_collect(struct md_pid_retired *retired,int (*gone)(pid_t)) {
    struct md_pid_identity **at=&retired->head;
    while (*at) {
        struct md_pid_identity *p=*at;
        if (md_pid_identity_live(p) || !gone(md_pid_identity_native(p))) { at=&p->retired_next; continue; }
        *at=p->retired_next; p->retired_next=NULL;
        md_pid_identity_reap(p); md_pid_identity_release(p);
    }
}
