#define _GNU_SOURCE
#include "ipc_peer_service.h"
#include "fs_worker.h"
#include "fs_engine.h"
#include "event_wait.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>

/* Static ARM64 Bionic executables require 64-byte ELF TLS alignment. */
_Alignas(64) static _Thread_local int fail_allocation;
static _Thread_local int lock_notification=-1;
int __real_flock(int, int);
int __wrap_flock(int fd, int operation) {
    if (lock_notification>=0 && operation==LOCK_EX) {
        uint64_t one=1;
        assert(write(lock_notification,&one,sizeof(one))==sizeof(one));
        lock_notification=-1;
    }
    return __real_flock(fd,operation);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_allocation) { fail_allocation=0; errno=ENOMEM; return NULL; }
    return __real_calloc(count,size);
}
static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (entry->d_name[0]!='.') ++n;
    assert(!closedir(dir)); return n;
}
static void pulse(int fd) { uint64_t one=1; assert(write(fd,&one,sizeof(one))==sizeof(one)); }
static void await(int fd) {
    /* EVENT_WAIT: exact fixture barrier/readiness, not a settling delay. */
    assert(md_event_wait_fd(fd,POLLIN,md_event_now()+5000000000LL)>=0);
}
struct owner { struct md_fs_worker *worker; struct md_ipc_peer_service *service; };
static void owner_close(struct owner *o) {
    assert(!md_fs_worker_stop(o->worker)); o->worker=NULL;
    md_ipc_peer_service_destroy(o->service); o->service=NULL;
}
enum operation { MARK, PAIR, STALL, ALLOCATION, LOCK_NOTICE };
struct work {
    struct md_fs_work work;
    enum operation operation;
    int done, fds[2];
};
static void run(struct md_fs_work *base, struct md_filesystem *fs, int error) {
    struct work *w=(struct work *)base;
    if (error) return;
    if (w->operation==PAIR) {
        struct md_ipc_credentials *ipc=NULL; assert(!md_fs_ipc_authority(fs,&ipc));
        struct md_identity identity=md_identity_new(0,0);
        struct md_fs_request q={.operation=MD_FS_IPC,.flags=MD_IPC_PAIR,
            .directory={w->fds[0],w->fds[1]},.peer=getpid()};
        struct md_fs_result result;
        md_ipc_credentials_execute(ipc,&identity,&q,&result,NULL);
        md_identity_release(&identity); assert(!result.error);
    } else if (w->operation==STALL) {
        pulse(w->fds[0]); await(w->fds[1]); uint64_t value;
        assert(read(w->fds[1],&value,sizeof(value))==sizeof(value));
    } else if (w->operation==ALLOCATION) fail_allocation=1;
    else if (w->operation==LOCK_NOTICE) lock_notification=w->fds[0];
}
static int completed(struct md_fs_work *base) {
    struct work *w=(struct work *)base; assert(!w->done++); return 0;
}
static void submit(struct owner *o, struct work *w) {
    w->work=(struct md_fs_work){.run=run,.complete=completed};
    assert(!md_fs_worker_submit(o->worker,&w->work));
}
static void finish(struct owner *o, struct work *w) {
    /* EVENT_WAIT: worker publication through its production completion queue. */
    int64_t deadline=md_event_now()+5000000000LL;
    while (!w->done) {
        assert(md_event_wait_fd(md_fs_worker_fd(o->worker),POLLIN,deadline)>=0);
        assert(!md_fs_worker_dispatch(o->worker));
    }
}
static struct owner owner_new(const char *store) {
    static unsigned serial;
    char endpoint[80]; snprintf(endpoint,sizeof(endpoint),"md-peer-worker-%d-%u",getpid(),++serial);
    struct owner o={0};
    assert(!md_fs_worker_start(store,endpoint,NULL,NULL,NULL,NULL,0,0,&o.worker));
    /* Service-loop wakeup ownership is established after startup publication. */
    struct work mark={0}; submit(&o,&mark); finish(&o,&mark);
    unsigned before=descriptors();
    assert(!md_ipc_peer_service_new(o.worker,&o.service) && descriptors()==before);
    return o;
}
static void pair(struct owner *o, int fd[2]) {
    assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fd));
    struct work w={.operation=PAIR,.fds={fd[0],fd[1]}}; submit(o,&w); finish(o,&w);
}
static void control(int fd[2]) { assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,fd)); }
static void block(struct owner *o, struct work *w) {
    *w=(struct work){.operation=STALL,.fds={eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK),eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK)}};
    assert(w->fds[0]>=0 && w->fds[1]>=0); submit(o,w); await(w->fds[0]);
}
static void unblock(struct owner *o, struct work *w) {
    pulse(w->fds[1]); finish(o,w); close(w->fds[0]); close(w->fds[1]);
}
struct result {
    struct md_ipc_peer_admission *request;
    struct md_ipc_peer *peer;
    pthread_t owner;
    int calls, error, take;
};
static void ready(struct md_ipc_peer_admission *r, int error, void *context) {
    struct result *out=context;
    assert(pthread_equal(pthread_self(),out->owner) && r==out->request && !out->calls++);
    out->error=error;
    if (out->take) assert(md_ipc_peer_take(&out->request,&out->peer)==error && !out->request);
}
static void begin(struct owner *o, int app, int ctl, struct result *out, int take) {
    *out=(struct result){.owner=pthread_self(),.take=take};
    assert(!md_ipc_peer_begin(o->service,app,ctl,1,0,ready,out,&out->request));
    assert(out->request && !out->calls);
}
static void joined_handshake(const char *store) {
    unsigned before=descriptors();
    struct owner owners[]={owner_new(store),owner_new(store)};
    int app[2], ctl[2]; pair(&owners[0],app); control(ctl);
    int data=fcntl(app[1],F_DUPFD_CLOEXEC,0); assert(data>=0);
    assert(send(app[0],"payload",7,MSG_NOSIGNAL)==7);
    struct result results[2];
    for (unsigned i=0;i<2;++i) {
        begin(&owners[i],app[i],ctl[i],&results[i],1);
        struct work mark={0}; submit(&owners[i],&mark); finish(&owners[i],&mark);
        assert(results[i].calls==1 && !results[i].error && results[i].peer);
    }
    char bytes[16]; assert(recv(data,bytes,sizeof(bytes),0)==7 && !memcmp(bytes,"payload",7));
    assert(!recv(data,bytes,sizeof(bytes),MSG_DONTWAIT)); close(data);
    for (unsigned i=0;i<2;++i) {
        assert(recv(ctl[i],bytes,sizeof(bytes),MSG_DONTWAIT)<0 && errno==EAGAIN);
        owner_close(&owners[i]);
    }
    int maintenance=open(store,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(maintenance>=0);
    assert(flock(maintenance,LOCK_EX|LOCK_NB)<0 && errno==EWOULDBLOCK);
    for (unsigned turn=0;turn<4;++turn) for (unsigned i=0;i<2;++i) assert(md_ipc_peer_step(results[i].peer)>=0);
    for (unsigned i=0;i<2;++i) {
        const struct md_ipc_binding *binding=NULL; uint64_t features=0;
        assert(!md_ipc_peer_agreement(results[i].peer,&binding,&features) && features==1 && binding->connection.side==i);
        md_ipc_peer_close(results[i].peer);
    }
    assert(!flock(maintenance,LOCK_EX|LOCK_NB) && !close(maintenance));
    assert(descriptors()==before);
    puts("PASS peer worker admission: two independent workers, supervisor callbacks, no early IO, application EOF, agreement after worker/SQLite teardown");
}
static void cancellation(const char *store, unsigned when) {
    unsigned before=descriptors(); struct owner o=owner_new(store);
    int app[2], ctl[2]; pair(&o,app); control(ctl);
    struct result out; struct work barrier;
    if (!when) block(&o,&barrier);
    begin(&o,app[0],ctl[0],&out,0);
    assert(md_ipc_peer_take(&out.request,&out.peer)==-EAGAIN && !out.peer);
    if (when==1) block(&o,&barrier);
    if (when==2) { struct work mark={0}; submit(&o,&mark); finish(&o,&mark); }
    md_ipc_peer_cancel(&out.request); assert(!out.request);
    if (when<2) unblock(&o,&barrier);
    struct work mark={0}; submit(&o,&mark); finish(&o,&mark);
    assert(out.calls==(when==2));
    char byte; assert(!recv(ctl[1],&byte,1,MSG_DONTWAIT) && !recv(app[1],&byte,1,MSG_DONTWAIT));
    close(ctl[1]); close(app[1]); owner_close(&o);
    assert(descriptors()==before);
    printf("PASS peer cancellation phase=%u: no cancelled callback, exact socket EOF and descriptor balance\n",when);
}
static void failure(const char *store) {
    unsigned before=descriptors(); struct owner o=owner_new(store);
    struct md_ipc_peer_service *failed=NULL;
    fail_allocation=1; assert(md_ipc_peer_service_new(o.worker,&failed)==-ENOMEM && !failed && !fail_allocation);
    for (unsigned mode=0;mode<3;++mode) {
        int app[2], ctl[2];
        if (mode==1) assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,app));
        else pair(&o,app);
        control(ctl);
        struct result out={.owner=pthread_self()};
        if (!mode) {
            fail_allocation=1;
            assert(md_ipc_peer_begin(o.service,app[0],ctl[0],1,0,ready,&out,&out.request)==-ENOMEM);
            assert(!out.request && !fail_allocation && fcntl(app[0],F_GETFD)>=0 && fcntl(ctl[0],F_GETFD)>=0);
            close(app[0]); close(ctl[0]);
        } else {
            struct work fault={.operation=ALLOCATION}, barrier;
            if (mode==2) { block(&o,&barrier); submit(&o,&fault); }
            begin(&o,app[0],ctl[0],&out,1);
            struct work mark={0}; submit(&o,&mark);
            if (mode==2) unblock(&o,&barrier);
            finish(&o,&mark);
            assert(out.calls==1 && out.error==(mode==1 ? -ENODATA : -ENOMEM) && !out.peer && !out.request);
        }
        char byte; assert(!recv(ctl[1],&byte,1,MSG_DONTWAIT) && !recv(app[1],&byte,1,MSG_DONTWAIT));
        close(app[1]); close(ctl[1]);
    }
    owner_close(&o); assert(descriptors()==before);
    puts("PASS peer worker allocation rollback and unknown-application rejection: explicit errors, no early descriptor transfer or leaked sockets");
}
static void cancel_running(const char *store) {
    unsigned before=descriptors(); struct owner o=owner_new(store);
    int app[2], ctl[2]; pair(&o,app); control(ctl);
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/ipc/gate",store);
    int gate=open(path,O_RDWR|O_CLOEXEC),notice=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    assert(gate>=0 && notice>=0 && !flock(gate,LOCK_EX|LOCK_NB));
    struct work arm={.operation=LOCK_NOTICE,.fds={notice,-1}}; submit(&o,&arm); finish(&o,&arm);
    struct result out; begin(&o,app[0],ctl[0],&out,0);
    /* EVENT_WAIT: the admission passed its cancellation check and entered the
     * metadata lock. The main owner must cancel without waiting for this lock. */
    await(notice); md_ipc_peer_cancel(&out.request); assert(!out.request);
    assert(!flock(gate,LOCK_UN));
    struct work mark={0}; submit(&o,&mark); finish(&o,&mark);
    assert(!out.calls);
    char byte; assert(!recv(ctl[1],&byte,1,MSG_DONTWAIT) && !recv(app[1],&byte,1,MSG_DONTWAIT));
    close(gate); close(notice); close(ctl[1]); close(app[1]); owner_close(&o);
    assert(descriptors()==before);
    puts("PASS cancellation during worker metadata admission: nonblocking caller, retained work and no cancelled callback or leaked FD");
}
static void burst(const char *store) {
    enum { COUNT=96 };
    unsigned before=descriptors(); struct owner o=owner_new(store);
    int app[2], controls[COUNT]; pair(&o,app);
    struct result results[COUNT]; struct work barrier; block(&o,&barrier);
    for (unsigned i=0;i<COUNT;++i) {
        int ctl[2]; control(ctl); controls[i]=ctl[1];
        int captured=fcntl(app[0],F_DUPFD_CLOEXEC,0); assert(captured>=0);
        begin(&o,captured,ctl[0],&results[i],i%3==1);
    }
    for (unsigned i=0;i<COUNT;i+=3) md_ipc_peer_cancel(&results[i].request);
    struct work mark={0}; submit(&o,&mark); unblock(&o,&barrier); finish(&o,&mark);
    for (unsigned step=0;step<COUNT;++step) {
        unsigned i=(step*37)%COUNT;
        assert(results[i].calls==(i%3!=0));
        if (i%3==2 && i%2) md_ipc_peer_cancel(&results[i].request);
        else if (i%3==2) assert(!md_ipc_peer_take(&results[i].request,&results[i].peer));
        assert(!results[i].request); md_ipc_peer_close(results[i].peer);
        char byte; assert(!recv(controls[i],&byte,1,MSG_DONTWAIT)); close(controls[i]);
    }
    close(app[0]); char byte; assert(!recv(app[1],&byte,1,MSG_DONTWAIT)); close(app[1]);
    owner_close(&o); assert(descriptors()==before);
    puts("PASS 96 peer admissions: bounded worker batches, mixed cancellation/take order, one callback per owner and exact FD balance");
}
static void shutdown_pending(const char *store, int admitted) {
    unsigned before=descriptors(); struct owner o=owner_new(store);
    int app[2], ctl[2]; pair(&o,app); control(ctl);
    struct result out; struct work barrier;
    if (!admitted) block(&o,&barrier);
    begin(&o,app[0],ctl[0],&out,0);
    if (admitted) block(&o,&barrier);
    /* No dispatch: shutdown must reclaim queued or published worker-owned
     * records after join, not rely on a callback reaching the dead owner. */
    pulse(barrier.fds[1]); owner_close(&o);
    close(barrier.fds[0]); close(barrier.fds[1]);
    assert(!out.calls);
    char byte; assert(!recv(ctl[1],&byte,1,MSG_DONTWAIT) && !recv(app[1],&byte,1,MSG_DONTWAIT));
    close(ctl[1]); close(app[1]); assert(descriptors()==before);
    printf("PASS peer owner shutdown admitted=%d: undelivered completion, join-before-release and exact FD balance\n",admitted);
}
static int worker_failed(void *context, struct md_filesystem *fs, short events) {
    (void)context; (void)fs; return events ? -EIO : 0;
}
static void unavailable(const char *store) {
    unsigned before=descriptors(); struct owner o=owner_new(store);
    int app[2], ctl[2]; pair(&o,app); control(ctl);
    int error=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK); assert(error>=0);
    md_fs_worker_notifications(o.worker,error,NULL,worker_failed); pulse(error);
    /* EVENT_WAIT: injected worker failure publishes its terminal state. */
    int64_t deadline=md_event_now()+5000000000LL;
    while (!md_fs_worker_error(o.worker)) {
        assert(md_event_wait_fd(md_fs_worker_fd(o.worker),POLLIN,deadline)>=0);
        int result=md_fs_worker_dispatch(o.worker); assert(!result || result==-EIO);
    }
    struct result out={.owner=pthread_self()};
    assert(md_ipc_peer_begin(o.service,app[0],ctl[0],1,0,ready,&out,&out.request)==-ESHUTDOWN && !out.request);
    assert(fcntl(app[0],F_GETFD)>=0 && fcntl(ctl[0],F_GETFD)>=0);
    assert(md_fs_worker_stop(o.worker)==-EIO); md_ipc_peer_service_destroy(o.service);
    close(app[0]); close(app[1]); close(ctl[0]); close(ctl[1]); close(error);
    assert(descriptors()==before);
    puts("PASS failed worker rejects new admission without stealing caller descriptors");
}
void md_test_ipc_peer_worker(const char *path) {
    /* EVENT_WAIT: outer failure bound includes worker stall, stop and join. */
    alarm(45); setbuf(stdout,NULL);
    struct md_inode_store *store=NULL; assert(!md_inode_store_open(path,1,&store)); md_inode_store_close(store);
    joined_handshake(path);
    for (unsigned phase=0;phase<3;++phase) cancellation(path,phase);
    cancel_running(path); burst(path); failure(path); shutdown_pending(path,0); shutdown_pending(path,1); unavailable(path);
    puts("PASS asynchronous IPC peer admission");
}
