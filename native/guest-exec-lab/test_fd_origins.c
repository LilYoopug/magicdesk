#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "task_resources.h"
#include "task_registry.h"
#include "event_wait.h"
#include "fd_mutation.h"
#include "fd_exchange.h"
#include "fd_receipt.h"
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
    md_fd_origins_release(files);
}
static void exchanges(struct md_fs_anchor *a, struct md_fs_anchor *b) {
    struct md_fd_exchanges *set=md_fd_exchanges_create(); assert(set);
    struct md_fd_origins *files=md_fd_origins_new(), *other=md_fd_origins_new(); assert(files && other);
    put(files,7,a,0);
    int bases[]={7,-1}, targets[]={10,11};
    struct md_fd_exchange *owner=NULL;
    assert(!md_fd_exchange_begin(set,120,files,bases,&owner));
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
    struct md_fd_receipt *receipt=mmap(NULL,sizeof(*receipt),PROT_READ|PROT_WRITE,
        MAP_SHARED,md_fd_exchange_receipt(worker),0);
    assert(receipt!=MAP_FAILED);
    assert(!md_fd_exchange_received(owner));
    md_fd_receipt_reset(receipt);
    struct cmsghdr *c=&receipt->control.align;
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
    assert(!munmap(receipt,sizeof(*receipt)));
    md_fd_exchange_release(worker);
    assert(!md_fd_exchange_begin(set,120,files,bases,&owner));
    assert(md_fd_exchange_id(owner)!=id);
    md_fd_exchange_close(set,owner);
    md_fd_origins_release(files); md_fd_origins_release(other); md_fd_exchanges_destroy(set);
}
void test_fd_origins(void) {
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
    mutations(a,b); exchanges(a,b);
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
}
