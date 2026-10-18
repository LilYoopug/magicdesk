#define _GNU_SOURCE
#include "fs_worker.h"
#include "event_wait.h"
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

struct delayed {
    struct md_fs_work work;
    atomic_int admission,started;
    int runs,completed,error,stages;
};
static int available(struct md_fs_work *base) {
    struct delayed *d=(void *)base;
    return atomic_exchange(&d->admission,0);
}
static void run(struct md_fs_work *base,struct md_filesystem *fs,int error) {
    struct delayed *d=(void *)base;
    ++d->runs; d->error=error;
    if (error) { assert(!fs); return; }
    assert(fs);
    if (d->runs<=d->stages) d->work.await=available;
    atomic_store(&d->started,d->runs);
}
static int complete(struct md_fs_work *base) {
    struct delayed *d=(void *)base; assert(!d->completed); ++d->completed; return 0;
}
static void prepare(struct delayed *d,int stages) {
    *d=(struct delayed){.work={.run=run,.complete=complete},.stages=stages};
    atomic_init(&d->admission,0); atomic_init(&d->started,0);
}
static void event(struct md_fs_worker *w) {
    /* EVENT_WAIT: exact worker completion or pause acknowledgement; bounded failure. */
    assert(md_event_wait_fd(md_fs_worker_fd(w),POLLIN,md_event_now()+5000000000LL)>=0);
    assert(!md_fs_worker_dispatch(w));
}
static void fence(struct md_fs_worker *w) {
    struct delayed d; prepare(&d,0);
    assert(!md_fs_worker_submit(w,&d.work));
    while (!d.completed) event(w);
    assert(d.runs==1 && !d.error);
}
void md_test_fs_deferred(const char *store) {
    char endpoint[80]; snprintf(endpoint,sizeof(endpoint),"md-fs-deferred-%d",getpid());
    struct md_fs_worker *w=NULL;
    assert(!md_fs_worker_start(store,endpoint,NULL,NULL,NULL,NULL,&w));
    struct delayed jobs[97];
    for (unsigned i=0;i<97;++i) { prepare(&jobs[i],2); assert(!md_fs_worker_submit(w,&jobs[i].work)); }
    fence(w);
    for (unsigned i=0;i<97;++i) assert(atomic_load(&jobs[i].started)==1 && !jobs[i].completed);
    /* All parked tasks leave this same worker free for ordinary operations. */
    for (unsigned i=0;i<8;++i) fence(w);
    struct md_fs_worker_pause pause={0};
    assert(!md_fs_worker_pause_begin(w,&pause));
    while (!md_fs_worker_pause_state(&pause)) event(w);
    for (unsigned i=0;i<97;++i) atomic_store(&jobs[i].admission,1);
    md_fs_worker_wake(w);
    assert(!md_fs_worker_pause_end(&pause));
    /* The fairness budget can defer later entries to another loop pass. */
    for (;;) {
        fence(w); unsigned ready=0;
        for (unsigned i=0;i<97;++i) ready+=atomic_load(&jobs[i].started)==2;
        if (ready==97) break;
    }
    for (unsigned i=0;i<97;++i) atomic_store(&jobs[i].admission,i%2 ? -ECANCELED : 1);
    md_fs_worker_wake(w);
    for (;;) {
        unsigned done=0; for (unsigned i=0;i<97;++i) done+=jobs[i].completed;
        if (done==97) break;
        event(w);
    }
    for (unsigned i=0;i<97;++i) assert(jobs[i].runs==3 && jobs[i].error==(i%2 ? -ECANCELED : 0));
    struct delayed stopped; prepare(&stopped,1);
    assert(!md_fs_worker_submit(w,&stopped.work)); fence(w);
    assert(atomic_load(&stopped.started)==1 && !stopped.completed);
    assert(!md_fs_worker_stop(w));
    assert(stopped.runs==2 && stopped.error==-ESHUTDOWN && !stopped.completed);
    puts("PASS deferred filesystem work: independent progress, staged resume, fairness, pause, cancellation, shutdown");
}
