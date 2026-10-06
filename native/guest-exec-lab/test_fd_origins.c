#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "task_resources.h"
#include "task_registry.h"
#include "event_wait.h"
#include "fd_mutation.h"
#include "fd_exchange.h"
#include "fd_delivery.h"
#include "fd_receipt.h"
#include "fd_channel.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/close_range.h>
#include <unistd.h>

static int allocation_budget=-1;
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__wrap_malloc(size_t n) {
    if (!allocation_budget) { errno=ENOMEM; return NULL; }
    if (allocation_budget>0) --allocation_budget;
    return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t size) {
    if (!allocation_budget) { errno=ENOMEM; return NULL; }
    if (allocation_budget>0) --allocation_budget;
    return __real_calloc(n,size);
}
static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d);
    unsigned n=0; while (readdir(d)) ++n;
    closedir(d); return n;
}
static struct md_fs_anchor *capture(struct md_mount_namespace *view, int fd) {
    struct md_filesystem fs={.mounts=view};
    struct md_fs_anchor *origin=NULL;
    struct md_fs_output out={.origin=&origin};
    struct md_fs_result result={.fd=fd};
    md_view_capture(&fs,view,NULL,&result,&out);
    assert(!result.error && origin); close(result.fd); return origin;
}
static void put(struct md_fd_origins *table, int fd, struct md_fs_anchor *origin, unsigned flags) {
    struct md_fd_origin_update update;
    assert(!md_fd_origins_prepare(table,origin,flags,&update));
    allocation_budget=0;
    md_fd_origins_finish(&update,fd);
    allocation_budget=-1;
    assert(!update.table && !update.entry);
}
static void expect(struct md_fd_origins *table, int fd, struct md_fs_anchor *expected, unsigned flags) {
    unsigned actual=UINT_MAX;
    struct md_fs_anchor *origin=md_fd_origins_get(table,fd,&actual);
    assert(origin==expected && actual==flags); md_fs_anchor_release(origin);
}
static void copy_slot(struct md_fd_origins *table, int from, int to, unsigned flags) {
    struct md_fs_anchor *origin=md_fd_origins_get(table,from,NULL);
    put(table,to,origin,flags); md_fs_anchor_release(origin);
}
static void cwd_context(struct md_fs_anchor *a) {
    struct md_guest_domain *fs=md_domain_new(); assert(fs);
    struct md_fs_location root={.mount=17}, actual;
    struct md_fs_anchor *cwd=NULL;
    assert(!md_domain_set_cwd(fs,a) && !md_domain_scoped(fs));
    assert(!md_domain_set_root(fs,&root) && md_domain_scoped(fs));
    md_domain_paths(fs,&actual,&cwd);
    assert(actual.mount==17 && cwd==a); md_fs_anchor_release(cwd);
    assert(!md_domain_set_cwd(fs,NULL) && md_domain_scoped(fs));
    md_domain_paths(fs,&actual,&cwd); assert(actual.mount==17 && !cwd);
    assert(!md_domain_set_cwd(fs,a));
    root=(struct md_fs_location){0};
    assert(!md_domain_set_root(fs,&root) && !md_domain_scoped(fs));
    md_domain_paths(fs,&actual,&cwd);
    assert(!actual.mount && cwd==a); md_fs_anchor_release(cwd);
    assert(!md_domain_restrict(fs,getpid(),"/proc/self/fdinfo"));
    assert(md_domain_set_cwd(fs,a)==-EPERM);
    assert(!md_domain_chdir_root(fs));
    md_domain_paths(fs,&actual,&cwd); assert(!actual.mount && !cwd);
    md_domain_release(fs);
}
static void ownership(struct md_fs_anchor *a, struct md_fs_anchor *b) {
    for (unsigned sharing=0;sharing<4;++sharing) {
        struct md_task_resources parent, child;
        unsigned long flags=(sharing&1 ? CLONE_FS : 0) | (sharing&2 ? CLONE_FILES : 0);
        assert(!md_resources_init(&parent,a->view));
        assert(!md_domain_set_cwd(parent.fs,a));
        put(parent.files,10,a,0); put(parent.files,71,b,FD_CLOEXEC);
        assert(!md_resources_fork(&parent,flags,&child));
        assert((parent.fs==child.fs)==!!(flags&CLONE_FS));
        assert((parent.files==child.files)==!!(flags&CLONE_FILES));
        put(child.files,10,b,0);
        expect(parent.files,10,flags&CLONE_FILES ? b : a,0);
        assert(!md_domain_set_cwd(child.fs,b));
        struct md_fs_location root;
        struct md_fs_anchor *cwd=NULL;
        md_domain_paths(parent.fs,&root,&cwd);
        assert(cwd==(flags&CLONE_FS ? b : a)); md_fs_anchor_release(cwd);
        struct md_fd_origins *old=child.files;
        struct md_resource_change change;
        assert(!md_resources_unshare_prepare(&child,CLONE_FILES,&change));
        assert(!md_resources_unshare_finish(NULL,&child,&change,-EINVAL));
        assert(child.files==old);
        assert(!md_resources_exec(&child));
        assert(child.files!=parent.files);
        expect(child.files,10,b,0); expect(child.files,71,NULL,0);
        expect(parent.files,71,b,FD_CLOEXEC);
        md_domain_paths(child.fs,&root,&cwd); assert(cwd==b); md_fs_anchor_release(cwd);
        assert((parent.fs==child.fs)==!!(flags&CLONE_FS));
        assert(!md_resources_release(NULL,&child));
        md_fd_origins_pin(parent.files);
        assert(!md_resources_unshare_prepare(&parent,CLONE_FILES,&change));
        assert(change.next.files==parent.files);
        assert(!md_resources_unshare_finish(NULL,&parent,&change,0));
        md_fd_origins_unpin(parent.files);
        assert(!md_resources_release(NULL,&parent));
    }
}
static void rollback(struct md_fs_anchor *a) {
    struct md_task_resources parent, child;
    assert(!md_resources_init(&parent,a->view));
    put(parent.files,5,a,0); put(parent.files,66,a,FD_CLOEXEC);
    assert(!md_resources_fork(&parent,CLONE_FS|CLONE_FILES,&child));
    int completed=0;
    for (int n=0;n<16;++n) {
        struct md_resource_change change;
        allocation_budget=n;
        int result=md_resources_unshare_prepare(&child,CLONE_FS|CLONE_FILES|CLONE_SYSVSEM,&change);
        allocation_budget=-1;
        assert(child.files==parent.files && child.fs==parent.fs);
        if (result) {
            assert(result==-ENOMEM && !change.next.files && !change.next.fs && !change.next.sem_undo);
        } else {
            assert(change.next.files!=parent.files && change.next.fs!=parent.fs);
            assert(!md_resources_unshare_finish(NULL,&child,&change,-ECANCELED));
            completed=1; break;
        }
        expect(parent.files,5,a,0); expect(parent.files,66,a,FD_CLOEXEC);
    }
    assert(completed);
    struct md_resource_change change;
    assert(!md_resources_unshare_prepare(&child,CLONE_FILES,&change));
    assert(!md_resources_unshare_finish(NULL,&child,&change,0));
    assert(child.files!=parent.files && child.fs==parent.fs);
    assert(!md_fd_origins_close_range(child.files,0,UINT_MAX,0));
    expect(child.files,5,NULL,0); expect(parent.files,5,a,0);
    assert(!md_resources_release(NULL,&child)); assert(!md_resources_release(NULL,&parent));
}
struct readers { struct md_fd_origins *table; struct md_fs_anchor *a, *b; pthread_barrier_t start; };
static void *read_origins(void *context) {
    struct readers *r=context;
    /* EVENT_WAIT: start the writer/reader race; the fixture runner bounds a stuck barrier/join. */
    pthread_barrier_wait(&r->start);
    for (unsigned i=0;i<10000;++i) {
        unsigned flags;
        struct md_fs_anchor *origin=md_fd_origins_get(r->table,9,&flags);
        assert((origin==r->a && !flags) || (origin==r->b && flags==FD_CLOEXEC));
        md_fs_anchor_release(origin);
    }
    return NULL;
}
static void registry_and_readers(struct md_fs_anchor *a, struct md_fs_anchor *b) {
    struct md_task_resources resources;
    assert(!md_resources_init(&resources,a->view));
    assert(!md_domain_set_cwd(resources.fs,a));
    assert(!md_domain_scoped(resources.fs));
    struct md_identity identity=md_identity_new(0,0);
    struct md_task_registry *registry=md_task_registry_create(); assert(registry);
    assert(!md_task_registry_publish(registry,123,120,&identity,&resources));
    struct md_task_snapshot snapshot;
    assert(md_task_registry_read(registry,123,119,&snapshot)==-EPERM);
    assert(!snapshot.files && !snapshot.cwd);
    assert(!md_task_registry_read(registry,123,120,&snapshot));
    assert(snapshot.files==resources.files && snapshot.cwd==a && snapshot.mounts==a->view);
    assert(!md_domain_set_cwd(resources.fs,b)); assert(snapshot.cwd==a);
    md_task_registry_forget(registry,123); md_task_registry_destroy(registry);
    md_identity_release(&identity); assert(!md_resources_release(NULL,&resources));
    put(snapshot.files,9,a,0);
    struct readers readers={.table=snapshot.files,.a=a,.b=b};
    assert(!pthread_barrier_init(&readers.start,NULL,2));
    pthread_t reader; assert(!pthread_create(&reader,NULL,read_origins,&readers));
    /* EVENT_WAIT: reader and writer enter together; runner deadline is a failure bound. */
    pthread_barrier_wait(&readers.start);
    for (unsigned i=0;i<10000;++i) {
        struct md_fd_origin_update update;
        assert(!md_fd_origins_prepare(snapshot.files,i%2 ? a : b,i%2 ? 0 : FD_CLOEXEC,&update));
        md_fd_origins_finish(&update,9);
    }
    assert(!pthread_join(reader,NULL)); pthread_barrier_destroy(&readers.start);
    md_task_snapshot_release(&snapshot);
}
static void ordering(struct md_fs_anchor *origin) {
    struct md_fd_origins *table=md_fd_origins_new(); assert(table);
    struct md_fd_origins *shared=md_fd_origins_fork(table,1); assert(shared==table);
    struct md_fd_order a={0}, b={0}, c={0}, d={0}, independent={0};
    assert(md_fd_order_start(&a)==-EINVAL);
    assert(md_fd_order_complete(&a)==-EINVAL);
    struct md_fd_origin_update update;
    assert(!md_fd_origins_prepare(table,origin,0,&update));
    allocation_budget=0;
    assert(md_fd_order_begin(table,&a,NULL)==1);
    assert(md_fd_order_begin(table,&a,NULL)==-EBUSY);
    assert(md_fd_order_complete(&a)==-EINVAL);
    assert(!md_fd_order_start(&a));
    assert(md_fd_order_begin(shared,&b,NULL)==0);
    assert(md_fd_order_begin(table,&c,NULL)==0);
    assert(md_fd_order_begin(table,&d,NULL)==0);
    assert(md_fd_order_start(&b)==-EINVAL);
    assert(md_fd_order_complete(&b)==-EINVAL);
    allocation_budget=-1;
    struct md_fd_origins *copy=md_fd_origins_fork(table,0); assert(copy && copy!=table);
    allocation_budget=0;
    assert(md_fd_order_begin(copy,&independent,NULL)==1 && !md_fd_order_start(&independent));
    assert(!md_fd_order_complete(&independent));
    assert(!md_fd_order_cancel(&c) && md_fd_order_state(&c)==MD_RESOURCE_ORDER_IDLE);
    assert(!md_fd_order_cancel(&d) && md_fd_order_state(&d)==MD_RESOURCE_ORDER_IDLE);
    assert(md_fd_order_cancel(&a)==1 && md_fd_order_state(&a)==MD_RESOURCE_ORDER_CANCELLING);
    assert(md_fd_order_cancel(&a)==1);
    assert(md_fd_order_state(&b)==MD_RESOURCE_ORDER_QUEUED);
    /* Cancellation intent is not proof that the kernel did not install an FD. */
    md_fd_origins_finish(&update,23);
    assert(!md_fd_order_complete(&a) && md_fd_order_state(&b)==MD_RESOURCE_ORDER_READY);
    expect(table,23,origin,0);
    assert(md_fd_order_begin(table,&c,NULL)==0);
    assert(!md_fd_order_cancel(&b) && md_fd_order_state(&c)==MD_RESOURCE_ORDER_READY);
    assert(!md_fd_order_start(&c));
    assert(!md_fd_order_complete(&c));
    assert(md_fd_order_begin(table,&d,NULL)==1 && !md_fd_order_start(&d));
    assert(md_fd_order_begin(table,&a,NULL)==0);
    md_fd_origins_release(shared); md_fd_origins_release(table);
    expect(d.table,23,origin,0);
    assert(!md_fd_order_complete(&d) && md_fd_order_state(&a)==MD_RESOURCE_ORDER_READY && !d.table);
    expect(a.table,23,origin,0);
    assert(!md_fd_order_cancel(&a) && !a.table);
    allocation_budget=-1;
    md_fd_origins_release(copy);
}
static void filesystem_ordering(struct md_fs_anchor *origin) {
    for (unsigned bits=0;bits<4;++bits) {
        unsigned flags=(bits&1 ? CLONE_FS : 0) | (bits&2 ? CLONE_FILES : 0);
        struct md_task_resources parent={0}, child={0};
        assert(!md_resources_init(&parent,origin->view));
        assert(!md_domain_set_cwd(parent.fs,origin));
        assert(!md_resources_fork(&parent,flags,&child));
        struct md_fs_order a={0}, b={0};
        struct md_fd_order files={0};
        allocation_budget=0;
        assert(md_fs_order_begin(parent.fs,&a,NULL)==1 && !md_fs_order_start(&a));
        assert(md_fd_order_begin(child.files,&files,NULL)==1 && !md_fd_order_start(&files));
        assert(md_fs_order_begin(child.fs,&b,NULL)==!(flags&CLONE_FS));
        assert(md_fs_order_cancel(&a)==1);
        assert(!md_resources_release(NULL,&parent) && !md_resources_release(NULL,&child));
        assert(!md_fs_order_complete(&a));
        assert(md_fs_order_state(&b)==MD_RESOURCE_ORDER_READY && !md_fs_order_start(&b));
        struct md_fs_location root;
        struct md_fs_anchor *cwd=NULL;
        md_domain_paths(b.fs,&root,&cwd); assert(cwd==origin); md_fs_anchor_release(cwd);
        assert(!md_fs_order_complete(&b) && !b.fs);
        assert(!md_fd_order_complete(&files));
        allocation_budget=-1;
    }
    puts("PASS independent filesystem ordering for every CLONE_FS/CLONE_FILES combination and owner teardown");
}
struct event_owner {
    struct md_fd_origins *table;
    pthread_barrier_t *start;
    unsigned *committed;
    atomic_uint *inside;
};
static void *ordered_writer(void *opaque) {
    struct event_owner *owner=opaque;
    int fd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK); assert(fd>=0);
    struct md_resource_wakeup *wakeup=NULL;
    assert(!md_resource_wakeup_create(fd,&wakeup));
    /* EVENT_WAIT: all producers are ready; the fixture runner bounds failure. */
    pthread_barrier_wait(owner->start);
    for (unsigned i=0;i<1000;++i) {
        struct md_fd_order op={0};
        int ready=md_fd_order_begin(owner->table,&op,wakeup); assert(ready>=0);
        if (!ready && i%3==0) {
            assert(!md_fd_order_cancel(&op));
            assert(md_fd_order_begin(owner->table,&op,wakeup)>=0);
        }
        int64_t deadline=md_event_now()+5000000000LL;
        while (md_fd_order_state(&op)!=MD_RESOURCE_ORDER_READY) {
            /* EVENT_WAIT: another owner retires its exact operation; timeout
             * fails the fixture, never grants admission. Late hints are OK. */
            assert(!md_event_wait_fd(fd,POLLIN,deadline));
            uint64_t hints;
            ssize_t n;
            do { n=read(fd,&hints,sizeof(hints)); } while (n<0 && errno==EINTR);
            assert(n==sizeof(hints));
        }
        assert(!md_fd_order_start(&op));
        assert(atomic_fetch_add(owner->inside,1)==0);
        unsigned previous=*owner->committed;
        assert(!md_fd_origins_set_flags(owner->table,9,previous&1 ? FD_CLOEXEC : 0));
        *owner->committed=previous+1;
        assert(atomic_fetch_sub(owner->inside,1)==1);
        assert(!md_fd_order_complete(&op));
    }
    close(fd); md_resource_wakeup_release(wakeup); return NULL;
}
static void event_ordering(struct md_fs_anchor *origin) {
    struct md_fd_origins *table=md_fd_origins_new(); assert(table);
    put(table,9,origin,0);
    pthread_barrier_t start; assert(!pthread_barrier_init(&start,NULL,3));
    unsigned committed=0; atomic_uint inside=0;
    struct event_owner owner={table,&start,&committed,&inside};
    pthread_t threads[3];
    for (unsigned i=0;i<3;++i) assert(!pthread_create(threads+i,NULL,ordered_writer,&owner));
    /* EVENT_WAIT: all producer loops retire their records; runner bounds joins. */
    for (unsigned i=0;i<3;++i) assert(!pthread_join(threads[i],NULL));
    assert(committed==3000 && !atomic_load(&inside));
    pthread_barrier_destroy(&start);
    int fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC); assert(fd>=0);
    struct md_resource_wakeup *wake=NULL;
    assert(!md_resource_wakeup_create(fd,&wake));
    struct md_fd_order a={0}, b={0};
    assert(md_fd_order_begin(table,&a,NULL)==1 && !md_fd_order_start(&a));
    assert(!md_fd_order_begin(table,&b,wake));
    uint64_t full=UINT64_MAX-1, count;
    assert(write(fd,&full,sizeof(full))==sizeof(full));
    assert(!md_fd_order_complete(&a));
    assert(read(fd,&count,sizeof(count))==sizeof(count) && count==full);
    assert(md_fd_order_state(&b)==MD_RESOURCE_ORDER_READY && !md_fd_order_cancel(&b));
    assert(md_fd_order_begin(table,&a,NULL)==1 && !md_fd_order_start(&a));
    assert(!md_fd_order_begin(table,&b,wake));
    /* The queued record retains the notification endpoint, not the loop. */
    close(fd); md_resource_wakeup_release(wake);
    assert(!md_fd_order_complete(&a));
    assert(md_fd_order_state(&b)==MD_RESOURCE_ORDER_READY && !md_fd_order_cancel(&b));
    md_fd_origins_release(table);
}
static void mutations(struct md_fs_anchor *a, struct md_fs_anchor *b) {
    struct md_fd_origins *files=md_fd_origins_new(); assert(files);
    put(files,10,a,0); put(files,11,b,0);
    struct md_fd_mutation op;
    unsigned long args[6]={10,11,O_CLOEXEC};
    assert(!md_fd_mutation_prepare(files,SYS_dup3,args,&op));
    allocation_budget=0;
    assert(!md_fd_mutation_finish(&op,files,11));
    allocation_budget=-1;
    expect(files,11,a,FD_CLOEXEC);
    args[1]=(1UL<<32)|F_DUPFD_CLOEXEC;
    assert(!md_fd_mutation_prepare(files,SYS_fcntl,args,&op));
    assert(!md_fd_mutation_finish(&op,files,12)); expect(files,12,a,FD_CLOEXEC);
    args[1]=(1UL<<32)|F_SETFD; args[2]=FD_CLOEXEC;
    assert(!md_fd_mutation_prepare(files,SYS_fcntl,args,&op));
    assert(!md_fd_mutation_finish(&op,files,-EPERM)); expect(files,10,a,0);
    assert(!md_fd_mutation_prepare(files,SYS_fcntl,args,&op));
    assert(!md_fd_mutation_finish(&op,files,0)); expect(files,10,a,FD_CLOEXEC);
    assert(!md_fd_mutation_prepare(files,SYS_close,args,&op));
    assert(!md_fd_mutation_finish(&op,files,-EPERM)); expect(files,10,a,FD_CLOEXEC);
    assert(!md_fd_mutation_prepare(files,SYS_close,args,&op));
    assert(!md_fd_mutation_finish(&op,files,0)); expect(files,10,NULL,0);
    args[0]=11; args[1]=12; args[2]=CLOSE_RANGE_CLOEXEC;
    assert(!md_fd_mutation_prepare(files,SYS_close_range,args,&op));
    assert(!md_fd_mutation_finish(&op,files,0));
    expect(files,11,a,FD_CLOEXEC); expect(files,12,a,FD_CLOEXEC);
    args[0]=11; args[1]=12; args[2]=0;
    assert(!md_fd_mutation_prepare(files,SYS_dup3,args,&op));
    assert(!md_fd_mutation_abandon(&op,files));
    expect(files,11,a,FD_CLOEXEC); expect(files,12,NULL,0);
    args[0]=11; args[1]=F_SETFD;
    assert(!md_fd_mutation_prepare(files,SYS_fcntl,args,&op));
    assert(!md_fd_mutation_abandon(&op,files)); expect(files,11,NULL,0);
    args[0]=(unsigned long)AT_FDCWD; args[2]=O_PATH|O_CLOEXEC;
    assert(!md_fd_mutation_prepare(files,SYS_openat,args,&op));
    long result=123;
    assert(!md_fd_mutation_terminal_open(&op,0,&result) && result==123);
    assert(!md_fd_origins_prepare(files,a,FD_CLOEXEC,&op.update));
    allocation_budget=0;
    assert(md_fd_mutation_terminal_open(&op,0,&result) && !result);
    assert(md_fd_mutation_terminal_open(&op,63,&result) && result==63);
    assert(md_fd_mutation_terminal_open(&op,(unsigned long)-EMFILE,&result) && result==-EMFILE);
    assert(md_fd_mutation_terminal_open(&op,(unsigned long)AT_FDCWD,&result) && result<0);
    assert(md_fd_mutation_terminal_open(&op,(unsigned)AT_FDCWD,&result) && result<0);
    result=123;
    assert(!md_fd_mutation_terminal_open(&op,1UL<<32,&result) && result==123);
    assert(!md_fd_mutation_terminal_open(&op,(unsigned long)-4096,&result) && result==123);
    op.args[0]=3;
    assert(!md_fd_mutation_terminal_open(&op,3,&result) && result==123);
    op.args[0]=(unsigned)AT_FDCWD; op.args[2]=O_RDONLY;
    assert(!md_fd_mutation_terminal_open(&op,3,&result) && result==123);
    op.args[2]=O_PATH|O_CLOEXEC;
    assert(md_fd_mutation_terminal_open(&op,63,&result) && result==63);
    assert(!md_fd_mutation_finish(&op,files,result));
    allocation_budget=-1;
    expect(files,63,a,FD_CLOEXEC);
    md_fd_origins_release(files);
}
static void exchanges(struct md_fs_anchor *a, struct md_fs_anchor *b) {
    struct md_fd_exchanges *set=md_fd_exchanges_create(); assert(set);
    struct md_fd_origins *files=md_fd_origins_new(), *other=md_fd_origins_new(); assert(files && other);
    put(files,7,a,0);
    int bases[]={7,-1}, targets[]={10,11};
    struct md_fd_exchange *owner=NULL;
    assert(!md_fd_exchange_begin(set,120,files,bases,NULL,&owner));
    uint64_t id=md_fd_exchange_id(owner); assert(id);
    assert(!md_fd_exchange_acquire(set,id,121,files));
    assert(!md_fd_exchange_acquire(set,id,120,other));
    struct md_fd_exchange *worker=md_fd_exchange_acquire(set,id,120,files); assert(worker);
    put(files,7,b,0);
    assert(md_fd_exchange_input(worker,0)==a && !md_fd_exchange_input(worker,1));
    assert(md_fd_exchange_received(owner)==-EAGAIN);
    allocation_budget=0;
    assert(md_fd_exchange_offer(worker,b,2)==-ENOMEM);
    allocation_budget=-1;
    assert(!md_fd_exchange_offer(worker,b,2));
    size_t size=md_fd_receipt_size(2);
    struct md_fd_receipt *receipt=mmap(NULL,size,PROT_READ|PROT_WRITE,
        MAP_SHARED,md_fd_exchange_receipt(worker),0);
    assert(receipt!=MAP_FAILED);
    assert(!md_fd_exchange_received(owner));
    assert(!md_fd_receipt_reset(receipt,2));
    struct cmsghdr *c=(void *)receipt->control;
    c->cmsg_len=CMSG_LEN(sizeof(targets)); c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS;
    int invalid[]={10,10}; memcpy(CMSG_DATA(c),invalid,sizeof(invalid));
    assert(md_fd_exchange_received(owner)==-EPROTO);
    memcpy(CMSG_DATA(c),targets,sizeof(targets));
    assert(md_fd_exchange_offer(worker,a,1)==-EALREADY);
    md_fd_exchange_close(set,owner);
    assert(!md_fd_exchange_acquire(set,id,120,files));
    allocation_budget=0;
    assert(!md_fd_exchange_received(worker));
    allocation_budget=-1;
    expect(files,10,b,FD_CLOEXEC); expect(files,11,NULL,0);
    assert(md_fd_exchange_received(worker)==-EALREADY);
    assert(!munmap(receipt,size));
    md_fd_exchange_release(worker);
    assert(!md_fd_exchange_begin(set,120,files,bases,NULL,&owner));
    assert(md_fd_exchange_id(owner)!=id);
    md_fd_exchange_close(set,owner);
    int cwd_bases[]={AT_FDCWD,7};
    owner=NULL;
    assert(md_fd_exchange_begin(set,120,files,cwd_bases,NULL,&owner)==-ENODATA && !owner);
    allocation_budget=0;
    assert(md_fd_exchange_begin(set,120,files,cwd_bases,a,&owner)==-ENOMEM && !owner);
    allocation_budget=-1;
    assert(!md_fd_exchange_begin(set,120,files,cwd_bases,a,&owner));
    assert(md_fd_exchange_cwd(owner)==1);
    worker=md_fd_exchange_acquire(set,md_fd_exchange_id(owner),120,files); assert(worker);
    put(files,7,a,0);
    md_fd_exchange_close(set,owner);
    assert(md_fd_exchange_input(worker,0)==a && md_fd_exchange_input(worker,1)==b);
    md_fd_exchange_release(worker);
    cwd_bases[1]=AT_FDCWD;
    assert(!md_fd_exchange_begin(set,120,files,cwd_bases,b,&owner));
    assert(md_fd_exchange_cwd(owner)==3 && md_fd_exchange_input(owner,0)==b
        && md_fd_exchange_input(owner,1)==b);
    md_fd_exchange_close(set,owner);
    md_fd_origins_release(files); md_fd_origins_release(other); md_fd_exchanges_destroy(set);
}
struct batch_reader {
    struct md_fd_origins *table;
    struct md_fs_anchor *a, *b;
    pthread_barrier_t start;
};
static void *read_batch(void *opaque) {
    struct batch_reader *r=opaque;
    int fds[]={40,41};
    /* EVENT_WAIT: both metadata owners are ready; runner deadline bounds failure. */
    pthread_barrier_wait(&r->start);
    for (unsigned i=0;i<10000;++i) {
        struct md_fs_anchor *pair[2];
        assert(!md_fd_origins_capture(r->table,fds,2,pair));
        assert((pair[0]==r->a && pair[1]==r->b) || (pair[0]==r->b && pair[1]==r->a));
        md_fs_anchor_release(pair[0]); md_fs_anchor_release(pair[1]);
    }
    return NULL;
}
static void batches(struct md_fs_anchor *a, struct md_fs_anchor *b) {
    struct md_fd_origins *source=md_fd_origins_new(), *target=md_fd_origins_new();
    assert(source && target);
    put(source,7,a,0); put(source,8,b,FD_CLOEXEC);
    int fds[]={7,8,900,-1,7}, destination[]={40,41,42,43,44};
    struct md_fs_anchor *origins[5]={0};
    allocation_budget=0;
    assert(!md_fd_origins_capture(source,fds,5,origins));
    allocation_budget=-1;
    put(source,7,b,0); md_fd_origins_release(source);
    assert(origins[0]==a && origins[1]==b && !origins[2] && !origins[3] && origins[4]==a);
    for (unsigned i=0;i<5;++i) put(target,destination[i],b,0);
    struct md_fd_origin_update updates[5]={0};
    for (int budget=0;budget<3;++budget) {
        allocation_budget=budget;
        assert(md_fd_origins_prepare_batch(target,origins,FD_CLOEXEC,5,updates)==-ENOMEM);
        allocation_budget=-1;
        for (unsigned i=0;i<5;++i) {
            assert(!updates[i].table && !updates[i].entry);
            expect(target,destination[i],b,0);
        }
    }
    for (unsigned pass=0;pass<3;++pass) {
        if (pass==2) { put(target,43,b,0); put(target,44,b,0); }
        assert(!md_fd_origins_prepare_batch(target,origins,FD_CLOEXEC,5,updates));
        allocation_budget=0;
        int duplicate[]={40,41,40}, invalid[]={40,-1};
        assert(md_fd_origins_finish_batch(updates,5,duplicate,3)==-EPROTO);
        assert(md_fd_origins_finish_batch(updates,5,invalid,2)==-EPROTO);
        assert(md_fd_origins_finish_batch(updates,5,destination,6)==-EINVAL);
        for (unsigned i=0;i<5;++i) {
            int changed=pass && !(pass==2 && i>=3);
            struct md_fs_anchor *expected=changed ? origins[i] : b;
            expect(target,destination[i],expected,changed && expected ? FD_CLOEXEC : 0);
        }
        unsigned received=pass==2 ? 3 : 5;
        assert(!md_fd_origins_finish_batch(updates,5,destination,received));
        allocation_budget=-1;
        for (unsigned i=0;i<received;++i)
            expect(target,destination[i],origins[i],origins[i] ? FD_CLOEXEC : 0);
        for (unsigned i=received;i<5;++i) expect(target,destination[i],b,0);
        /* Peeks prepare independent deliveries from the same immutable snapshot. */
        for (unsigned i=0;i<5;++i) assert(!updates[i].table && !updates[i].entry);
    }
    struct md_fs_anchor *unknowns[2]={0};
    allocation_budget=0;
    assert(!md_fd_origins_prepare_batch(target,unknowns,0,2,updates));
    assert(!md_fd_origins_finish_batch(updates,2,destination,2));
    expect(target,40,NULL,0); expect(target,41,NULL,0);
    allocation_budget=-1;
    assert(!md_fd_origins_prepare_batch(target,origins,0,5,updates));
    assert(!md_fd_origins_finish_batch(updates,5,NULL,0));
    expect(target,40,NULL,0);

    struct md_fd_origins *other=md_fd_origins_new(); assert(other);
    assert(!md_fd_origins_prepare(target,a,0,updates));
    assert(!md_fd_origins_prepare(other,b,0,updates+1));
    assert(md_fd_origins_finish_batch(updates,2,destination,2)==-EINVAL);
    expect(target,40,NULL,0); expect(other,41,NULL,0);
    md_fd_origins_finish(updates,-1); md_fd_origins_finish(updates+1,-1);
    md_fd_origins_release(other);
    for (unsigned i=0;i<5;++i) md_fs_anchor_release(origins[i]);

    put(target,40,a,0); put(target,41,b,0);
    struct batch_reader reader={.table=target,.a=a,.b=b};
    assert(!pthread_barrier_init(&reader.start,NULL,2));
    pthread_t thread; assert(!pthread_create(&thread,NULL,read_batch,&reader));
    /* EVENT_WAIT: enter the concurrent snapshot/publication test together. */
    pthread_barrier_wait(&reader.start);
    for (unsigned i=0;i<10000;++i) {
        struct md_fs_anchor *pair[]={i%2 ? a : b,i%2 ? b : a};
        assert(!md_fd_origins_prepare_batch(target,pair,0,2,updates));
        assert(!md_fd_origins_finish_batch(updates,2,destination,2));
    }
    assert(!pthread_join(thread,NULL)); pthread_barrier_destroy(&reader.start);
    assert(!md_fd_origins_prepare_batch(target,unknowns,0,2,updates));
    md_fd_origins_release(target);
    allocation_budget=0;
    assert(!md_fd_origins_finish_batch(updates,2,destination,2));
    allocation_budget=-1;
}
static void deliveries(struct md_fs_anchor *a, struct md_fs_anchor *b) {
    unsigned before=descriptors();
    struct md_fd_delivery delivery={0};
    struct md_fd_origins *files=md_fd_origins_new(); assert(files);
    struct md_fs_anchor *origins[]={a,NULL,b};
    struct md_fd_origin_update updates[3];
    int numbers[3]={-9,-9,-9};
    int fds[]={open("/",O_PATH|O_CLOEXEC),open("/",O_PATH|O_CLOEXEC),open("/",O_PATH|O_CLOEXEC)};
    for (unsigned i=0;i<3;++i) { assert(fds[i]>=0); put(files,fds[i],b,0); }
    assert(md_fd_delivery_receipt(&delivery)==-1);
    assert(md_fd_delivery_publish(&delivery)==-EINVAL);
    assert(md_fd_delivery_prepare(&delivery,files,origins,0,0,updates,numbers)==-EINVAL);
    assert(md_fd_delivery_prepare(&delivery,files,origins,0,MD_FD_RECEIPT_MAX+1,updates,numbers)==-EINVAL);
    assert(md_fd_delivery_prepare(&delivery,files,origins,2,3,updates,numbers)==-EINVAL);
    unsigned prepared_before=descriptors();
    for (int budget=0;budget<2;++budget) {
        allocation_budget=budget;
        assert(md_fd_delivery_prepare(&delivery,files,origins,FD_CLOEXEC,3,updates,numbers)==-ENOMEM);
        allocation_budget=-1;
        assert(!delivery.capacity && md_fd_delivery_receipt(&delivery)==-1);
        for (unsigned i=0;i<3;++i) {
            assert(!updates[i].table && !updates[i].entry);
            expect(files,fds[i],b,0);
        }
        assert(descriptors()==prepared_before);
    }
    struct rlimit limit; assert(!getrlimit(RLIMIT_NOFILE,&limit));
    int first_free=0;
    while (fcntl(first_free,F_GETFD)>=0) ++first_free;
    assert(errno==EBADF && (rlim_t)first_free<limit.rlim_cur);
    struct rlimit exhausted=limit; exhausted.rlim_cur=(rlim_t)first_free;
    assert(!setrlimit(RLIMIT_NOFILE,&exhausted));
    int error=md_fd_delivery_prepare(&delivery,files,origins,0,3,updates,numbers);
    assert(!setrlimit(RLIMIT_NOFILE,&limit));
    assert(error==-EMFILE && !delivery.capacity && descriptors()==prepared_before);
    for (unsigned i=0;i<3;++i) {
        assert(!updates[i].table && !updates[i].entry);
        expect(files,fds[i],b,0);
    }
    for (unsigned count=0;count<=3;++count) {
        assert(!md_fd_delivery_prepare(&delivery,files,origins,FD_CLOEXEC,3,updates,numbers));
        int receipt_fd=md_fd_delivery_receipt(&delivery); assert(receipt_fd>=0);
        assert(md_fd_delivery_prepare(&delivery,files,origins,0,3,updates,numbers)==-EBUSY);
        assert(md_fd_delivery_receipt(&delivery)==receipt_fd);
        allocation_budget=0;
        assert(!md_fd_delivery_publish(&delivery));
        assert(!md_fd_receipt_reset(delivery.receipt,3));
        assert(!md_fd_delivery_publish(&delivery));
        struct cmsghdr *c=(void *)delivery.receipt->control;
        *c=(struct cmsghdr){.cmsg_len=CMSG_LEN(2*sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
        int invalid[]={fds[0],fds[0]};
        delivery.receipt->message.msg_controllen=CMSG_LEN(sizeof(invalid));
        memcpy(CMSG_DATA(c),invalid,sizeof(invalid));
        assert(md_fd_delivery_publish(&delivery)==-EPROTO);
        for (unsigned i=0;i<3;++i) expect(files,fds[i],b,0);
        assert(numbers[0]==-9);
        assert(!md_fd_receipt_reset(delivery.receipt,3));
        c=(void *)delivery.receipt->control;
        c->cmsg_len=CMSG_LEN(count*sizeof(int)); c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS;
        memcpy(CMSG_DATA(c),fds,count*sizeof(int));
        delivery.receipt->message.msg_controllen=CMSG_LEN(count*sizeof(int));
        if (count<3) delivery.receipt->message.msg_flags=MSG_CTRUNC;
        /* An admitted delivery retains the table even after its task owner exits. */
        struct md_fd_origins *pin=md_fd_origins_pin(files);
        md_fd_origins_release(files);
        assert(md_fd_delivery_publish(&delivery)==(int)count);
        if (count) assert(md_fd_delivery_publish(&delivery)==-EALREADY);
        md_fd_delivery_dispose(&delivery);
        md_fd_delivery_dispose(&delivery);
        assert(!delivery.capacity && md_fd_delivery_receipt(&delivery)==-1);
        assert(fcntl(receipt_fd,F_GETFD)==-1 && errno==EBADF);
        for (unsigned i=0;i<3;++i) {
            struct md_fs_anchor *expected=i<count ? origins[i] : b;
            expect(pin,fds[i],expected,i<count && expected ? FD_CLOEXEC : 0);
            assert(fcntl(fds[i],F_GETFD)==FD_CLOEXEC);
        }
        allocation_budget=-1;
        md_fd_origins_unpin(pin);
        files=md_fd_origins_new(); assert(files);
        for (unsigned i=0;i<3;++i) { put(files,fds[i],b,0); numbers[i]=-9; }
    }
    md_fd_origins_release(files);
    for (unsigned i=0;i<3;++i) assert(!close(fds[i]));
    assert(descriptors()==before);
}
static void receipts(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    assert(md_fd_receipt_size(MD_FD_RECEIPT_MAX)<page);
    void *memory=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED && !mprotect((char *)memory+page,page,PROT_NONE));
    int output[MD_FD_RECEIPT_MAX+1];
    assert(!md_fd_receipt_size(0) && !md_fd_receipt_size(MD_FD_RECEIPT_MAX+1));
    assert(md_fd_receipt_reset(NULL,1)==-EINVAL);
    for (unsigned capacity=1;capacity<=MD_FD_RECEIPT_MAX;++capacity) {
        struct md_fd_receipt *receipt=(void *)((char *)memory+page-md_fd_receipt_size(capacity));
        allocation_budget=0;
        assert(!md_fd_receipt_reset(receipt,capacity));
        for (unsigned i=0;i<=MD_FD_RECEIPT_MAX;++i) output[i]=-9;
        assert(!md_fd_receipt_read(receipt,capacity,output) && output[0]==-9);
        struct cmsghdr *c=(void *)receipt->control;
        *c=(struct cmsghdr){.cmsg_len=CMSG_LEN(capacity*sizeof(int)),
            .cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
        int *numbers=(void *)CMSG_DATA(c);
        for (unsigned i=0;i<capacity;++i) numbers[i]=10+(int)i;
        /* Pointer fields are foreign process addresses, not parser inputs. */
        receipt->message.msg_control=(void *)1; receipt->message.msg_iov=(void *)1;
        assert(md_fd_receipt_read(receipt,capacity,output)==(int)capacity);
        for (unsigned i=0;i<capacity;++i) assert(output[i]==10+(int)i);
        assert(output[capacity]==-9);
        numbers[capacity-1]=-1;
        assert(md_fd_receipt_read(receipt,capacity,output)==-EPROTO);
        assert(output[capacity-1]==10+(int)capacity-1);
        numbers[capacity-1]=10+(int)capacity-1;
        if (capacity>2) {
            numbers[capacity-1]=numbers[1];
            assert(md_fd_receipt_read(receipt,capacity,output)==-EPROTO);
            assert(output[capacity-1]==10+(int)capacity-1);
            numbers[capacity-1]=10+(int)capacity-1;
        }
        ++receipt->message.msg_controllen;
        assert(md_fd_receipt_read(receipt,capacity,output)==-EPROTO);
        --receipt->message.msg_controllen;
        --c->cmsg_len;
        assert(md_fd_receipt_read(receipt,capacity,output)==-EPROTO);
        ++c->cmsg_len;
        c->cmsg_type=SCM_CREDENTIALS;
        assert(md_fd_receipt_read(receipt,capacity,output)==-EPROTO);
        assert(output[capacity-1]==10+(int)capacity-1 && output[capacity]==-9);
        c->cmsg_type=SCM_RIGHTS;
        c->cmsg_len=CMSG_LEN(sizeof(int));
        receipt->message.msg_controllen=CMSG_LEN(sizeof(int));
        receipt->message.msg_flags=MSG_CTRUNC;
        assert(md_fd_receipt_read(receipt,capacity,output)==1 && output[0]==10);
        assert(!md_fd_receipt_reset(receipt,capacity));
        assert(!md_fd_receipt_read(receipt,capacity,output));
        allocation_budget=-1;
    }
    assert(!munmap(memory,page*2));
}
static void expect_export(struct md_fd_origins *table, struct md_fd_channel *expected, int number) {
    struct md_fd_channel *actual=NULL; int slot=-2;
    assert(!md_fd_origins_channel(table,&slot,&actual) && actual==expected && slot==number);
    md_fd_channel_release(actual);
}
static void export_messages(void) {
    unsigned before=descriptors();
    for (unsigned mode=0;mode<5;++mode) {
        struct md_fd_channel *channel=NULL; assert(!md_fd_channel_new(&channel));
        int pipefd[2]; assert(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK));
        struct md_fd_channel_capture capture={0};
        if (mode!=4) assert(!md_fd_channel_capture_begin(channel,getpid(),1,&capture));
        uint64_t token=mode==1 ? 0 : mode==4 ? 41 : capture.request;
        struct iovec vector={&token,mode==2 ? 1 : sizeof(token)};
        union { struct cmsghdr align; char data[CMSG_SPACE(3*sizeof(int))]; } control={0};
        unsigned count=mode==3 ? 3 : 1;
        struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
            .msg_control=control.data,.msg_controllen=CMSG_SPACE(count*sizeof(int))};
        struct cmsghdr *header=CMSG_FIRSTHDR(&message);
        header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS;
        header->cmsg_len=CMSG_LEN(count*sizeof(int));
        for (unsigned i=0;i<count;++i) memcpy(CMSG_DATA(header)+i*sizeof(int),pipefd+1,sizeof(int));
        assert(sendmsg(md_fd_channel_endpoint(channel),&message,MSG_NOSIGNAL)==(ssize_t)vector.iov_len);
        assert(!close(pipefd[1]));
        char byte;
        assert(read(pipefd[0],&byte,1)==-1 && errno==EAGAIN);
        if (mode!=4) {
            struct md_fd_channel_input received;
            int result=md_fd_channel_capture_finish(&capture,&received);
            if (!mode) {
                assert(!result && received.request==token && received.peer==getpid() && received.count==1);
                assert(fcntl(received.fd[0],F_GETFD)==FD_CLOEXEC);
                md_fd_channel_input_close(&received);
            } else assert(result==-EPROTO && !received.count);
            assert(!md_fd_channel_capture_begin(channel,getpid(),1,&capture));
            assert(md_fd_channel_capture_finish(&capture,&received)==-EPROTO && !received.count);
        }
        md_fd_channel_release(channel);
        assert(read(pipefd[0],&byte,1)==0 && !close(pipefd[0]) && descriptors()==before);
    }
    puts("PASS export messages: kernel sender, exact payload, malformed/truncated rights and queued-owner release preserve EOF");
}
static void capture_send(struct md_fd_channel *channel, uint64_t token, int fd, unsigned count) {
    struct iovec vector={&token,sizeof(token)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(2*sizeof(int))]; } control={0};
    assert(count && count<=2);
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=CMSG_SPACE(count*sizeof(int))};
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS;
    header->cmsg_len=CMSG_LEN(count*sizeof(int));
    for (unsigned i=0;i<count;++i) memcpy(CMSG_DATA(header)+i*sizeof(fd),&fd,sizeof(fd));
    assert(sendmsg(md_fd_channel_endpoint(channel),&message,MSG_NOSIGNAL)==sizeof(token));
}
static void channel_captures(void) {
    unsigned before=descriptors();
    struct md_fd_channel *channel=NULL,*other=NULL;
    assert(!md_fd_channel_new(&channel) && !md_fd_channel_new(&other));
    struct md_fd_channel_capture leases[6]={0};
    int pipes[6][2];
    for (unsigned i=0;i<6;++i) assert(!pipe2(pipes[i],O_CLOEXEC|O_NONBLOCK));
    allocation_budget=0;
    for (unsigned i=0;i<6;++i)
        assert(!md_fd_channel_capture_begin(i==5 ? other : channel,
            getpid()+(i==4),i==3 ? 2 : 1,leases+i));
    assert(leases[0].request==leases[5].request);
    assert(md_fd_channel_capture_begin(channel,getpid(),1,leases)==-EINVAL);
    /* Reverse delivery crosses independent consumers and fork-copied tables.
     * Cancelling one owner must retain packets accepted for every other one. */
    for (int i=5;i>=0;--i) capture_send(i==5 ? other : channel,leases[i].request,pipes[i][1],1);
    capture_send(channel,leases[1].request,pipes[1][1],1);
    capture_send(channel,UINT64_MAX,pipes[3][1],1);
    for (unsigned i=0;i<6;++i) assert(!close(pipes[i][1]));
    char byte;
    for (unsigned i=0;i<6;++i) assert(read(pipes[i][0],&byte,1)==-1 && errno==EAGAIN);
    md_fd_channel_capture_cancel(leases+2);
    assert(!leases[2].channel && read(pipes[2][0],&byte,1)==0);
    for (unsigned i=0;i<6;++i) {
        if (i==2) continue;
        struct md_fd_channel_input result;
        int error=md_fd_channel_capture_finish(leases+i,&result);
        assert(!leases[i].channel);
        if (i==3 || i==4) assert(error==-EPROTO && !result.count);
        else {
            assert(!error && result.count==1 && result.peer==getpid());
            assert(read(pipes[i][0],&byte,1)==-1 && errno==EAGAIN);
            md_fd_channel_input_close(&result);
        }
        assert(read(pipes[i][0],&byte,1)==0);
    }
    /* A terminal sender may never have queued anything. Its retired token
     * cannot capture a later packet or consume a new owner's valid vector. */
    assert(!md_fd_channel_capture_begin(channel,getpid(),1,leases));
    uint64_t retired=leases[0].request;
    md_fd_channel_capture_cancel(leases);
    assert(!close(pipes[2][0]));
    assert(!pipe2(pipes[2],O_CLOEXEC|O_NONBLOCK));
    assert(!md_fd_channel_capture_begin(channel,getpid(),1,leases));
    capture_send(channel,retired,pipes[2][1],1);
    capture_send(channel,leases[0].request,pipes[2][1],1);
    assert(!close(pipes[2][1]));
    struct md_fd_channel_input result;
    assert(!md_fd_channel_capture_finish(leases,&result));
    md_fd_channel_input_close(&result);
    assert(read(pipes[2][0],&byte,1)==0);
    allocation_budget=-1;
    for (unsigned i=0;i<6;++i) assert(!close(pipes[i][0]));
    md_fd_channel_release(channel); md_fd_channel_release(other);
    assert(descriptors()==before);
    puts("PASS channel captures: independent owners, reverse/duplicate delivery, wrong peer/count/channel, cancellation, late tokens and exact EOF without allocation");
}
static void infrastructure(void) {
    unsigned before=descriptors();
    struct md_fd_channel *channel=NULL;
    allocation_budget=0; assert(md_fd_channel_new(&channel)==-ENOMEM && !channel);
    allocation_budget=-1; assert(!md_fd_channel_new(&channel));
    struct md_fd_origins *table=md_fd_origins_new(); assert(table);
    struct md_fd_origin_update update;
    for (int budget=0;budget<2;++budget) {
        allocation_budget=budget;
        assert(md_fd_origins_prepare_channel(table,channel,FD_CLOEXEC,&update)==-ENOMEM);
        allocation_budget=-1; expect_export(table,NULL,-1);
    }
    assert(!md_fd_origins_prepare_channel(table,channel,FD_CLOEXEC,&update));
    allocation_budget=0; md_fd_origins_finish(&update,10); allocation_budget=-1;
    expect_export(table,channel,10);
    struct md_fd_mutation duplicate={0}; unsigned long args[6]={10,11,O_CLOEXEC};
    assert(!md_fd_mutation_prepare(table,SYS_dup3,args,&duplicate));
    allocation_budget=0; assert(!md_fd_mutation_finish(&duplicate,table,11)); allocation_budget=-1;
    assert(!md_fd_origins_close_range(table,10,10,0)); expect_export(table,channel,11);
    struct md_fd_origins *copy=md_fd_origins_fork(table,0), *shared=md_fd_origins_fork(table,1);
    assert(copy && shared==table);
    md_fd_origins_exec(copy); expect_export(copy,NULL,-1); expect_export(table,channel,11);
    assert(!md_fd_origins_set_flags(table,11,0)); md_fd_origins_exec(table);
    expect_export(shared,channel,11);
    put(table,11,NULL,0); expect_export(table,NULL,-1);
    assert(!md_fd_origins_prepare_channel(table,channel,FD_CLOEXEC,&update));
    md_fd_origins_finish(&update,12);
    struct md_fd_mutation closing={0}; args[0]=12;
    assert(!md_fd_mutation_prepare(table,SYS_close,args,&closing));
    assert(!md_fd_mutation_abandon(&closing,table));
    struct md_fd_channel *unknown=NULL; int slot;
    assert(md_fd_origins_channel(table,&slot,&unknown)==-ESTALE && !unknown);
    md_fd_origins_exec(table);
    assert(md_fd_origins_channel(table,&slot,&unknown)==-ESTALE && !unknown);
    assert(!md_fd_origins_close_range(table,12,12,0)); expect_export(table,NULL,-1);
    md_fd_origins_release(shared); md_fd_origins_release(copy); md_fd_origins_release(table);
    md_fd_channel_release(channel); assert(descriptors()==before);
    puts("PASS export infrastructure: shared/copied tables, dup, replacement, flags, exec, ambiguous terminal fail-closed and allocation rollback");
}
static void channel_reconciliation(void) {
    unsigned before=descriptors();
    for (unsigned mode=0;mode<6;++mode) {
        struct md_fd_channel *channel=NULL,*different=NULL;
        assert(!md_fd_channel_new(&channel) && !md_fd_channel_new(&different));
        struct md_fd_origins *files=md_fd_origins_new(); assert(files);
        int number=fcntl(md_fd_channel_endpoint(channel),F_DUPFD_CLOEXEC,0); assert(number>=0);
        struct md_fd_origin_update update={0};
        assert(!md_fd_origins_prepare_channel(files,channel,FD_CLOEXEC,&update));
        md_fd_origins_finish(&update,number);
        assert(!md_fd_origins_abandon_range(files,number,number));
        if (mode==1) assert(!fcntl(number,F_SETFD,0));
        if (mode==2) {
            int file=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(file>=0);
            assert(dup3(file,number,O_CLOEXEC)==number && !close(file));
        }
        if (mode==3) assert(!close(number));
        if (mode==4) assert(dup3(md_fd_channel_endpoint(different),number,O_CLOEXEC)==number);
        unsigned present=descriptors();
        struct md_fd_channel *candidate=NULL; int slot=-1;
        allocation_budget=0;
        assert(!md_fd_origins_channel_candidate(files,&slot,&candidate) && candidate==channel && slot==number);
        struct md_fd_channel_observation o={.error=-EPERM};
        assert(md_fd_channel_resolve(candidate,files,number,&o)==-EPERM);
        struct md_fd_channel *unresolved=NULL;
        assert(md_fd_origins_channel(files,&slot,&unresolved)==-ESTALE && !unresolved);
        o=(struct md_fd_channel_observation){.length=sizeof(o.cookie)};
        int flags=fcntl(number,F_GETFD);
        if (flags<0) o.error=-errno;
        else {
            o.flags=(unsigned)flags;
            if (getsockopt(number,SOL_SOCKET,SO_COOKIE,&o.cookie,&o.length)) o.error=-errno;
        }
        if (mode==5) {
            struct md_fd_channel_observation invalid=o; invalid.length=1;
            assert(md_fd_channel_resolve(candidate,files,number,&invalid)==-EPROTO);
        }
        assert(!md_fd_channel_resolve(candidate,files,number,&o));
        assert(md_fd_channel_resolve(candidate,files,number,&o)==-ESTALE);
        md_fd_channel_release(candidate);
        allocation_budget=-1;
        assert(descriptors()==present);
        int same=mode<2 || mode==5;
        expect_export(files,same ? channel : NULL,same ? number : -1);
        if (mode!=3) assert(fcntl(number,F_GETFD)==flags && !close(number));
        md_fd_origins_release(files); md_fd_channel_release(channel); md_fd_channel_release(different);
        assert(descriptors()==before);
    }
    puts("PASS channel reconciliation: same/closed/replaced slot, CLOEXEC, denied observation, malformed reply, no allocation or guest close");
}
void test_fd_origins(void) {
    export_messages();
    infrastructure();
    channel_reconciliation();
    channel_captures();
    unsigned before=descriptors();
    struct md_mount_namespace *first=md_mount_namespace_new(), *second=md_mount_namespace_new();
    assert(first && second);
    struct md_fs_anchor *a=capture(first,open("/",O_PATH|O_CLOEXEC));
    struct md_fs_anchor *b=capture(second,open("/",O_PATH|O_CLOEXEC));
    filesystem_ordering(a);
    struct stat x,y; assert(!fstat(a->fd,&x) && !fstat(b->fd,&y));
    assert(x.st_dev==y.st_dev && x.st_ino==y.st_ino && a->view!=b->view);
    struct md_fd_origins *table=md_fd_origins_new(); assert(table);
    struct md_fd_origin_update update;
    for (int n=0;n<2;++n) {
        allocation_budget=n;
        int r=md_fd_origins_prepare(table,a,0,&update);
        allocation_budget=-1;
        assert(r==-ENOMEM && !update.table && !update.entry);
        expect(table,10,NULL,0);
    }
    put(table,10,a,FD_CLOEXEC); copy_slot(table,10,71,0);
    assert(!md_fd_origins_prepare(table,b,0,&update));
    md_fd_origins_finish(&update,-EIO); expect(table,10,a,FD_CLOEXEC);
    put(table,10,b,0); expect(table,71,a,0); expect(table,10,b,0);
    copy_slot(table,999,10,0); expect(table,10,NULL,0);
    put(table,INT_MAX,b,0); put(table,10,b,0);
    assert(!md_fd_origins_close_range(table,71,UINT_MAX,1));
    expect(table,71,a,FD_CLOEXEC); expect(table,INT_MAX,b,FD_CLOEXEC);
    assert(!md_fd_origins_set_flags(table,71,0));
    md_fd_origins_exec(table);
    expect(table,71,a,0); expect(table,INT_MAX,NULL,0); expect(table,10,b,0);
    assert(md_fd_origins_close_range(table,2,1,0)==-EINVAL);
    assert(md_fd_origins_prepare(table,a,2,&update)==-EINVAL);
    assert(md_fd_origins_set_flags(table,71,2)==-EINVAL);
    assert(!md_fd_origins_close_range(table,10,10,0)); expect(table,10,NULL,0);
    int stream[2]; assert(!pipe2(stream,O_CLOEXEC|O_NONBLOCK));
    struct md_fs_anchor *pipe_origin=capture(first,stream[1]);
    put(table,12,pipe_origin,0); md_fs_anchor_release(pipe_origin);
    char byte; assert(read(stream[0],&byte,1)==0); close(stream[0]);
    md_fd_origins_release(table);
    cwd_context(a); ownership(a,b); rollback(a); registry_and_readers(a,b); ordering(a); event_ordering(a);
    mutations(a,b); exchanges(a,b); batches(a,b); deliveries(a,b); receipts();
    table=md_fd_origins_new(); assert(table);
    assert(!md_fd_origins_prepare(table,a,0,&update));
    md_fd_origins_release(table);
    md_fs_anchor_release(a); md_fs_anchor_release(b);
    md_mount_namespace_release(first); md_mount_namespace_release(second);
    md_fd_origins_finish(&update,5);
    assert(descriptors()==before);
    puts("PASS sparse FD origins: prepared publication, cancellation, alias replacement, flags, ranges and EOF");
    puts("PASS independent CLONE_FILES/CLONE_FS, unshare rollback, exec CLOEXEC and retained cwd");
    puts("PASS allocation-failure rollback, allocation-free publication and concurrent retained snapshots");
    puts("PASS per-file-table ordering: cancellation awaits kernel completion, independent owners progress, no allocations");
    puts("PASS cross-loop ordering: 3000 publications, concurrent cancellation, saturated wake and owner teardown");
    puts("PASS descriptor mutations and authenticated RPC exchange: prepare rollback, owner loss and exact publication");
    puts("PASS RPC cwd origins: retained mixed/two-base snapshots, unknown rejection and allocation rollback");
    puts("PASS origin vectors: sender lifetime, repeated/unknown sources, peek reuse, prefix publication, invalid receipts and atomic snapshots");
    puts("PASS retained receipt capacities 1..253: bounded parsing, foreign pointers, invalid/duplicate numbers and unchanged error output");
    puts("PASS shared FD delivery: preparation rollback, retry, partial publication, owner loss, once-only commit and caller FD lifetime");
}
