#define _GNU_SOURCE
#include "fd_exchange.h"
#include "fd_receipt.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

struct md_fd_exchange {
    struct md_fd_exchange *next;
    atomic_uint refs;
    pthread_mutex_t lock;
    uint64_t id;
    int actor, offered, published;
    unsigned count;
    struct md_fd_origins *files;
    struct md_fs_anchor *input[2];
    struct md_fd_origin_update output[2];
    int receipt_fd;
    struct md_fd_receipt *receipt;
};
struct md_fd_exchanges {
    pthread_mutex_t lock;
    uint64_t serial;
    struct md_fd_exchange *first;
};
struct md_fd_exchanges *md_fd_exchanges_create(void) {
    struct md_fd_exchanges *set=calloc(1,sizeof(*set));
    if (set && pthread_mutex_init(&set->lock,NULL)) { free(set); return NULL; }
    return set;
}
void md_fd_exchange_release(struct md_fd_exchange *e) {
    if (!e || atomic_fetch_sub_explicit(&e->refs,1,memory_order_acq_rel)!=1) return;
    for (unsigned i=0;i<2;++i) {
        md_fd_origins_finish(&e->output[i],-1);
        md_fs_anchor_release(e->input[i]);
    }
    md_fd_origins_unpin(e->files);
    if (e->receipt) munmap(e->receipt,sizeof(*e->receipt));
    if (e->receipt_fd>=0) close(e->receipt_fd);
    pthread_mutex_destroy(&e->lock); free(e);
}
void md_fd_exchanges_destroy(struct md_fd_exchanges *set) {
    if (!set) return;
    while (set->first) {
        struct md_fd_exchange *e=set->first;
        set->first=e->next; md_fd_exchange_release(e);
    }
    pthread_mutex_destroy(&set->lock); free(set);
}
int md_fd_exchange_begin(struct md_fd_exchanges *set, int actor, struct md_fd_origins *files,
        const int bases[2], struct md_fd_exchange **out) {
    *out=NULL;
    if (!set || actor<=0 || !files) return -EINVAL;
    struct md_fd_exchange *e=calloc(1,sizeof(*e));
    if (!e) return -ENOMEM;
    int error=pthread_mutex_init(&e->lock,NULL);
    if (error) { free(e); return -error; }
    atomic_init(&e->refs,1); e->actor=actor; e->files=md_fd_origins_pin(files); e->receipt_fd=-1;
    for (unsigned i=0;i<2;++i) e->input[i]=md_fd_origins_get(files,bases[i],NULL);
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
    pthread_mutex_unlock(&set->lock);
    if (found) md_fd_exchange_release(e);
    md_fd_exchange_release(e);
}
const struct md_fs_anchor *md_fd_exchange_input(const struct md_fd_exchange *e, unsigned slot) {
    return e && slot<2 ? e->input[slot] : NULL;
}
int md_fd_exchange_offer(struct md_fd_exchange *e, struct md_fs_anchor *origin, unsigned count) {
    if (!e || count>2) return -EINVAL;
    pthread_mutex_lock(&e->lock);
    int error=e->offered ? -EALREADY : 0;
    for (unsigned i=0;!error && i<count;++i)
        error=md_fd_origins_prepare(e->files,i ? NULL : origin,FD_CLOEXEC,e->output+i);
    if (!error && count) {
        e->receipt_fd=memfd_create("guest-fd-receipt",MFD_CLOEXEC|MFD_ALLOW_SEALING);
        if (e->receipt_fd<0) error=-errno;
        else if (ftruncate(e->receipt_fd,sizeof(*e->receipt))
                || fcntl(e->receipt_fd,F_ADD_SEALS,F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL)) error=-errno;
        else {
            void *memory=mmap(NULL,sizeof(*e->receipt),PROT_READ|PROT_WRITE,MAP_SHARED,e->receipt_fd,0);
            if (memory==MAP_FAILED) error=-errno; else e->receipt=memory;
        }
    }
    if (error) {
        if (!e->offered) {
            for (unsigned i=0;i<2;++i) md_fd_origins_finish(e->output+i,-1);
            if (e->receipt_fd>=0) close(e->receipt_fd);
            e->receipt_fd=-1;
        }
    } else { e->count=count; e->offered=1; }
    pthread_mutex_unlock(&e->lock); return error;
}
int md_fd_exchange_receipt(const struct md_fd_exchange *e) {
    return e ? e->receipt_fd : -1;
}
int md_fd_exchange_received(struct md_fd_exchange *e) {
    if (!e) return -EINVAL;
    pthread_mutex_lock(&e->lock);
    int numbers[MD_FD_RECEIPT_MAX];
    int count=!e->offered ? -EAGAIN : e->receipt ? md_fd_receipt_read(e->receipt,numbers) : -EINVAL;
    int error=count<0 ? count : e->published ? -EALREADY : (unsigned)count>e->count ? -EPROTO : 0;
    if (!error && count) {
        /* A truncated rights message may have installed only a prefix. Those
         * slots still belong to the receiver and must be published exactly. */
        for (unsigned i=0;i<e->count;++i) md_fd_origins_finish(e->output+i,i<(unsigned)count ? numbers[i] : -1);
        e->published=1;
    }
    pthread_mutex_unlock(&e->lock); return error;
}
