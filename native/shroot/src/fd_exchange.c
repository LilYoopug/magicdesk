#define _GNU_SOURCE
#include "fd_exchange.h"
#include "fd_delivery.h"
#include "event_signal.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

struct md_fd_exchange {
    struct md_fd_exchange *next;
    atomic_uint refs;
    atomic_int closed;
    pthread_mutex_t lock;
    uint64_t id;
    int actor, offered;
    unsigned cwd;
    struct md_fd_origins *files;
    struct md_fs_anchor *input[2];
    struct md_fd_origin_update output[2];
    int numbers[2];
    struct md_fd_delivery delivery;
};
struct md_fd_exchanges {
    pthread_mutex_t lock;
    uint64_t serial;
    struct md_fd_exchange *first;
    int wake;
};
struct md_fd_exchanges *md_fd_exchanges_create(void) {
    struct md_fd_exchanges *set=calloc(1,sizeof(*set));
    if (set && pthread_mutex_init(&set->lock,NULL)) { free(set); return NULL; }
    if (set) {
        set->wake=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
        if (set->wake<0) { pthread_mutex_destroy(&set->lock); free(set); return NULL; }
    }
    return set;
}
int md_fd_exchanges_pollfd(const struct md_fd_exchanges *set) {
    return set ? set->wake : -1;
}
int md_fd_exchanges_drain(struct md_fd_exchanges *set) {
    return set ? md_event_acknowledge(set->wake) : -EINVAL;
}
int md_fd_exchange_closed(const struct md_fd_exchange *e) {
    return e && atomic_load_explicit(&e->closed,memory_order_acquire);
}
void md_fd_exchange_release(struct md_fd_exchange *e) {
    if (!e || atomic_fetch_sub_explicit(&e->refs,1,memory_order_acq_rel)!=1) return;
    md_fd_delivery_dispose(&e->delivery);
    for (unsigned i=0;i<2;++i) md_fs_anchor_release(e->input[i]);
    md_fd_origins_unpin(e->files);
    pthread_mutex_destroy(&e->lock); free(e);
}
void md_fd_exchanges_destroy(struct md_fd_exchanges *set) {
    if (!set) return;
    while (set->first) {
        struct md_fd_exchange *e=set->first;
        set->first=e->next; md_fd_exchange_release(e);
    }
    close(set->wake); pthread_mutex_destroy(&set->lock); free(set);
}
int md_fd_exchange_begin(struct md_fd_exchanges *set, int actor, struct md_fd_origins *files,
        const int bases[2], struct md_fs_anchor *cwd, struct md_fd_exchange **out) {
    *out=NULL;
    if (!set || actor<=0 || !files || !bases) return -EINVAL;
    unsigned mask=0; int numbers[2];
    for (unsigned i=0;i<2;++i) {
        if (bases[i]==AT_FDCWD) mask|=1U<<i;
        numbers[i]=bases[i]==AT_FDCWD ? -1 : bases[i];
    }
    if (mask && !cwd) return -ENODATA;
    struct md_fd_exchange *e=calloc(1,sizeof(*e));
    if (!e) return -ENOMEM;
    int error=pthread_mutex_init(&e->lock,NULL);
    if (error) { free(e); return -error; }
    atomic_init(&e->refs,1); atomic_init(&e->closed,0);
    e->actor=actor; e->files=md_fd_origins_pin(files);
    error=md_fd_origins_capture(files,numbers,2,e->input);
    if (error) { md_fd_exchange_release(e); return error; }
    for (unsigned i=0;i<2;++i) if (mask & (1U<<i)) e->input[i]=md_fs_anchor_retain(cwd);
    e->cwd=mask;
    pthread_mutex_lock(&set->lock);
    if (set->serial==INT64_MAX) error=-EOVERFLOW;
    else {
        e->id=++set->serial;
        e->next=set->first; set->first=e;
        atomic_fetch_add_explicit(&e->refs,1,memory_order_relaxed);
    }
    pthread_mutex_unlock(&set->lock);
    if (error) { md_fd_exchange_release(e); return error; }
    *out=e; return 0;
}
uint64_t md_fd_exchange_id(const struct md_fd_exchange *e) { return e ? e->id : 0; }
struct md_fd_exchange *md_fd_exchange_acquire(struct md_fd_exchanges *set, uint64_t id,
        int actor, struct md_fd_origins *files) {
    if (!set || !id) return NULL;
    pthread_mutex_lock(&set->lock);
    struct md_fd_exchange *e=set->first;
    while (e && e->id!=id) e=e->next;
    if (e && (e->actor!=actor || e->files!=files)) e=NULL;
    if (e) atomic_fetch_add_explicit(&e->refs,1,memory_order_relaxed);
    pthread_mutex_unlock(&set->lock); return e;
}
void md_fd_exchange_close(struct md_fd_exchanges *set, struct md_fd_exchange *e) {
    if (!e) return;
    int found=0;
    pthread_mutex_lock(&set->lock);
    struct md_fd_exchange **at=&set->first;
    while (*at && *at!=e) at=&(*at)->next;
    if (*at) { *at=e->next; found=1; }
    atomic_store_explicit(&e->closed,1,memory_order_release);
    pthread_mutex_unlock(&set->lock);
    md_event_signal(set->wake);
    if (found) md_fd_exchange_release(e);
    md_fd_exchange_release(e);
}
const struct md_fs_anchor *md_fd_exchange_input(const struct md_fd_exchange *e, unsigned slot) {
    return e && slot<2 ? e->input[slot] : NULL;
}
unsigned md_fd_exchange_cwd(const struct md_fd_exchange *e) { return e ? e->cwd : 0; }
int md_fd_exchange_offer(struct md_fd_exchange *e, struct md_fs_anchor *origin, unsigned count) {
    if (!e || count>2) return -EINVAL;
    pthread_mutex_lock(&e->lock);
    int error=md_fd_exchange_closed(e) ? -ECANCELED : e->offered ? -EALREADY : 0;
    struct md_fd_object *origins[2]={md_fs_anchor_object(origin),NULL};
    if (!error && count) error=md_fd_delivery_prepare(&e->delivery,e->files,origins,
        FD_CLOEXEC,count,e->output,e->numbers);
    if (!error) e->offered=1;
    pthread_mutex_unlock(&e->lock); return error;
}
int md_fd_exchange_receipt(const struct md_fd_exchange *e) {
    return e ? md_fd_delivery_receipt(&e->delivery) : -1;
}
int md_fd_exchange_received(struct md_fd_exchange *e) {
    if (!e) return -EINVAL;
    pthread_mutex_lock(&e->lock);
    int result=e->offered ? md_fd_delivery_publish(&e->delivery) : -EAGAIN;
    pthread_mutex_unlock(&e->lock); return result<0 ? result : 0;
}
