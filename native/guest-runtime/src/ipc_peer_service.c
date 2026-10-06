#define _GNU_SOURCE
#include "ipc_peer_service.h"
#include "fs_worker.h"
#include "fs_engine.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

struct md_ipc_peer_service {
    struct md_fs_worker *worker;
    struct md_ipc_peer_admission *requests;
};
struct md_ipc_peer_admission {
    struct md_fs_work work;
    struct md_ipc_peer_admission *next, **previous;
    struct md_ipc_peer *peer;
    void (*complete)(struct md_ipc_peer_admission *, int, void *);
    void *context;
    uint64_t supported, required;
    int application, control, submitted, error;
    atomic_int cancelled;
};
static void dispose(struct md_ipc_peer_admission *r) {
    *r->previous=r->next;
    if (r->next) r->next->previous=r->previous;
    if (r->application>=0) close(r->application);
    if (r->control>=0) close(r->control);
    md_ipc_peer_close(r->peer); free(r);
}
int md_ipc_peer_service_new(struct md_fs_worker *worker, struct md_ipc_peer_service **out) {
    if (!worker || !out || *out) return -EINVAL;
    struct md_ipc_peer_service *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->worker=worker; *out=s; return 0;
}
void md_ipc_peer_service_destroy(struct md_ipc_peer_service *s) {
    if (!s) return;
    while (s->requests) dispose(s->requests);
    free(s);
}
static void prepare(struct md_fs_work *work, struct md_filesystem *fs, int error) {
    struct md_ipc_peer_admission *r=(struct md_ipc_peer_admission *)work;
    if (!error && atomic_load_explicit(&r->cancelled,memory_order_relaxed)) error=-ECANCELED;
    struct md_ipc_credentials *ipc=NULL;
    if (!error) error=md_fs_ipc_authority(fs,&ipc);
    if (!error) error=md_ipc_peer_open(ipc,r->application,r->control,r->supported,r->required,&r->peer);
    if (!error) r->control=-1;
    close(r->application); r->application=-1;
    if (r->control>=0) { close(r->control); r->control=-1; }
    r->error=error;
}
static int prepared(struct md_fs_work *work) {
    struct md_ipc_peer_admission *r=(struct md_ipc_peer_admission *)work;
    r->submitted=0;
    if (atomic_load_explicit(&r->cancelled,memory_order_relaxed)) dispose(r);
    else r->complete(r,r->error,r->context);
    return 0;
}
int md_ipc_peer_begin(struct md_ipc_peer_service *s, int application, int control,
        uint64_t supported, uint64_t required,
        void (*complete)(struct md_ipc_peer_admission *, int, void *), void *context,
        struct md_ipc_peer_admission **out) {
    if (!s || application<0 || control<0 || application==control || !complete || !out || *out
            || (supported&~(uint64_t)MD_IPC_PEER_ORIGINS) || (required&~supported)) return -EINVAL;
    struct md_ipc_peer_admission *r=calloc(1,sizeof(*r));
    if (!r) return -ENOMEM;
    *r=(struct md_ipc_peer_admission){.work={.run=prepare,.complete=prepared},
        .application=application,.control=control,.supported=supported,.required=required,
        .context=context,.complete=complete,.submitted=1};
    atomic_init(&r->cancelled,0);
    int error=md_fs_worker_submit(s->worker,&r->work);
    if (error) { free(r); return error; }
    r->next=s->requests; r->previous=&s->requests;
    if (r->next) r->next->previous=&r->next;
    s->requests=r; *out=r; return 0;
}
int md_ipc_peer_take(struct md_ipc_peer_admission **owner, struct md_ipc_peer **peer) {
    if (!owner || !*owner || !peer || *peer) return -EINVAL;
    struct md_ipc_peer_admission *r=*owner;
    if (r->submitted) return -EAGAIN;
    int error=r->error;
    if (!error) { *peer=r->peer; r->peer=NULL; }
    *owner=NULL; dispose(r); return error;
}
void md_ipc_peer_cancel(struct md_ipc_peer_admission **owner) {
    if (!owner || !*owner) return;
    struct md_ipc_peer_admission *r=*owner; *owner=NULL;
    atomic_store_explicit(&r->cancelled,1,memory_order_relaxed);
    if (!r->submitted) dispose(r);
}
