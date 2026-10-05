#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "task_resources.h"
#include "task_registry.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
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
    struct md_fd_order a={0}, b={0}, c={0}, d={0}, independent={0}, *next=NULL;
    assert(md_fd_order_start(&a)==-EINVAL);
    assert(md_fd_order_complete(&a,&next)==-EINVAL && !next);
    struct md_fd_origin_update update;
    assert(!md_fd_origins_prepare(table,origin,0,&update));
    allocation_budget=0;
    assert(md_fd_order_begin(table,&a)==1);
    assert(md_fd_order_begin(table,&a)==-EBUSY);
    assert(md_fd_order_complete(&a,&next)==-EINVAL);
    assert(!md_fd_order_start(&a));
    assert(md_fd_order_begin(shared,&b)==0);
    assert(md_fd_order_begin(table,&c)==0);
    assert(md_fd_order_begin(table,&d)==0);
    assert(md_fd_order_start(&b)==-EINVAL);
    assert(md_fd_order_complete(&b,&next)==-EINVAL && !next);
    allocation_budget=-1;
    struct md_fd_origins *copy=md_fd_origins_fork(table,0); assert(copy && copy!=table);
    allocation_budget=0;
    assert(md_fd_order_begin(copy,&independent)==1 && !md_fd_order_start(&independent));
    assert(!md_fd_order_complete(&independent,&next) && !next);
    assert(!md_fd_order_cancel(&c,&next) && !next && c.state==MD_FD_ORDER_IDLE);
    assert(!md_fd_order_cancel(&d,&next) && !next && d.state==MD_FD_ORDER_IDLE);
    assert(md_fd_order_cancel(&a,&next)==1 && !next && a.state==MD_FD_ORDER_CANCELLING);
    assert(md_fd_order_cancel(&a,&next)==1 && !next);
    assert(b.state==MD_FD_ORDER_QUEUED);
    /* Cancellation intent is not proof that the kernel did not install an FD. */
    md_fd_origins_finish(&update,23);
    assert(!md_fd_order_complete(&a,&next) && next==&b);
    expect(table,23,origin,0);
    assert(md_fd_order_begin(table,&c)==0);
    assert(!md_fd_order_cancel(&b,&next) && next==&c);
    assert(!md_fd_order_start(&c));
    assert(!md_fd_order_complete(&c,&next) && !next);
    assert(md_fd_order_begin(table,&d)==1 && !md_fd_order_start(&d));
    assert(md_fd_order_begin(table,&a)==0);
    md_fd_origins_release(shared); md_fd_origins_release(table);
    expect(d.table,23,origin,0);
    assert(!md_fd_order_complete(&d,&next) && next==&a && !d.table);
    expect(a.table,23,origin,0);
    assert(!md_fd_order_cancel(&a,&next) && !next && !a.table);
    allocation_budget=-1;
    md_fd_origins_release(copy);
}
void test_fd_origins(void) {
    unsigned before=descriptors();
    struct md_mount_namespace *first=md_mount_namespace_new(), *second=md_mount_namespace_new();
    assert(first && second);
    struct md_fs_anchor *a=capture(first,open("/",O_PATH|O_CLOEXEC));
    struct md_fs_anchor *b=capture(second,open("/",O_PATH|O_CLOEXEC));
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
    cwd_context(a); ownership(a,b); rollback(a); registry_and_readers(a,b); ordering(a);
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
}
