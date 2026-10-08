#define _GNU_SOURCE
#include "interception_buffers.h"
#include "interception_memory.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

static int fail_allocation;
static unsigned allocations;
void *__real_calloc(size_t,size_t);
void *__real_malloc(size_t);
void *__real_realloc(void *,size_t);
void *__wrap_calloc(size_t n, size_t size) {
    ++allocations; return fail_allocation ? NULL : __real_calloc(n,size);
}
void *__wrap_malloc(size_t size) {
    ++allocations; return fail_allocation ? NULL : __real_malloc(size);
}
void *__wrap_realloc(void *p, size_t size) {
    ++allocations; return fail_allocation ? NULL : __real_realloc(p,size);
}
static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d);
    unsigned n=0; struct dirent *e;
    while ((e=readdir(d))) if (strcmp(e->d_name,".") && strcmp(e->d_name,"..")) ++n;
    assert(!closedir(d)); return n;
}
static void slots(void) {
    struct md_interception_buffers *p=NULL;
    assert(!md_buffers_create(3,8193,8193,&p));
    int fd=md_buffers_fd(p), seals=F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL;
    assert((fcntl(fd,F_GETFD)&FD_CLOEXEC) && fcntl(fd,F_GET_SEALS)==seals);
    assert(ftruncate(fd,1)==-1 && errno==EPERM);
    struct md_interception_buffer a={0},b={0},c={0},extra={0},retained={0};
    struct md_buffer_span av,bv,cv;
    fail_allocation=1;
    unsigned before=allocations;
    assert(!md_buffers_take(p,&a) && !md_buffers_take(p,&b) && !md_buffers_take(p,&c));
    assert(md_buffers_take(p,&extra)==-EAGAIN && !extra.pool);
    assert(md_buffers_take(p,&a)==-EBUSY);
    assert(!md_buffer_span(&a,&av) && !md_buffer_span(&b,&bv) && !md_buffer_span(&c,&cv));
    assert(av.size==8193 && bv.size==8193 && cv.size==8193);
    assert(av.offset+av.size<=bv.offset && bv.offset+bv.size<=cv.offset);
    assert(cv.offset+cv.size<=md_buffers_size(p));
    memset(av.data,0x31,av.size); memset(bv.data,0x52,bv.size); memset(cv.data,0x73,cv.size);
    assert(!md_buffer_pin(&b,&retained) && md_buffer_pin(&a,&retained)==-EBUSY);
    struct md_interception_buffer stale=b;
    assert(!md_buffer_release(&b) && !b.pool);
    assert(md_buffers_take(p,&extra)==-EAGAIN);
    assert(!md_buffer_span(&retained,&bv) && ((unsigned char *)bv.data)[8192]==0x52);
    assert(!md_buffer_release(&retained));
    assert(!md_buffers_take(p,&extra) && extra.index==stale.index && extra.generation!=stale.generation);
    assert(md_buffer_span(&stale,&bv)==-ESTALE);
    assert(md_buffer_release(&stale)==-ESTALE);
    assert(!md_buffer_span(&extra,&bv));
    for (unsigned i=0;i<bv.size;++i) assert(!((unsigned char *)bv.data)[i]);
    for (unsigned i=0;i<av.size;++i) assert(((unsigned char *)av.data)[i]==0x31);
    for (unsigned i=0;i<cv.size;++i) assert(((unsigned char *)cv.data)[i]==0x73);
    assert(!md_buffer_release(&a) && !md_buffer_release(&c) && !md_buffer_release(&extra));
    assert(!md_buffer_release(&extra));
    assert(allocations==before);
    fail_allocation=0;
    md_buffers_release(p);
    puts("PASS request buffers: bounded slots, exact spans, sealed size, retained ownership, stale generation and allocation-free reuse");
}
static void owner_lifetime(void) {
    struct md_interception_buffers *old=NULL,*next=NULL;
    assert(!md_buffers_create(1,65536,65536,&old));
    struct md_interception_buffers *fork_owner=md_buffers_retain(old); assert(fork_owner==old);
    struct md_interception_buffer task={0},worker={0},blocked={0};
    assert(!md_buffers_take(old,&task) && !md_buffer_pin(&task,&worker));
    struct md_buffer_span a; assert(!md_buffer_span(&task,&a));
    memset(a.data,0x6b,a.size);
    int fd=md_buffers_fd(old);
    md_buffers_release(old);
    assert(!md_buffer_release(&task));
    assert(md_buffers_take(fork_owner,&blocked)==-EAGAIN);
    md_buffers_release(fork_owner);
    assert(!md_buffers_create(1,65536,65536,&next));
    assert(!md_buffers_take(next,&task));
    struct md_buffer_span b; assert(!md_buffer_span(&task,&b));
    assert(b.data!=a.data && !((unsigned char *)b.data)[0]);
    assert(!md_buffer_span(&worker,&a) && ((unsigned char *)a.data)[65535]==0x6b);
    assert(fcntl(fd,F_GETFD)>=0);
    assert(!md_buffer_release(&worker));
    assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
    assert(!md_buffer_release(&task)); md_buffers_release(next);
    puts("PASS request buffers: request survives mapping-owner release; replacement image has independent storage");
}
static void failures(void) {
    struct md_interception_buffers *p=NULL;
    assert(md_buffers_create(0,1,1,&p)==-EINVAL && !p);
    assert(md_buffers_create(1,0,0,&p)==-EINVAL && !p);
    assert(md_buffers_create(1,SIZE_MAX,SIZE_MAX,&p)==-EOVERFLOW && !p);
    assert(md_buffers_create(2,PTRDIFF_MAX,PTRDIFF_MAX,&p)==-EOVERFLOW && !p);
    fail_allocation=1;
    assert(md_buffers_create(1,4096,4096,&p)==-ENOMEM && !p);
    fail_allocation=0;
    struct rlimit saved; assert(!getrlimit(RLIMIT_NOFILE,&saved) && saved.rlim_max>=64);
    struct rlimit limit=saved; limit.rlim_cur=64; assert(!setrlimit(RLIMIT_NOFILE,&limit));
    int fds[64],n=0,fd;
    while ((fd=fcntl(STDERR_FILENO,F_DUPFD_CLOEXEC,0))>=0) { assert(n<64); fds[n++]=fd; }
    assert(errno==EMFILE && n);
    assert(md_buffers_create(1,4096,4096,&p)==-EMFILE && !p);
    for (int i=0;i<n;++i) assert(!close(fds[i]));
    assert(!setrlimit(RLIMIT_NOFILE,&saved));
    puts("PASS request buffers: invalid sizes, allocation failure and exhausted provider FD table leave no pool");
}
static void address_spaces(void) {
    struct md_interception_memory *parent=md_memory_new(); assert(parent);
    fail_allocation=1;
    assert(md_memory_buffers_prepare(parent,2,5000,5000)==-ENOMEM && !md_memory_buffers(parent));
    fail_allocation=0;
    assert(!md_memory_buffers_prepare(parent,2,5000,5000));
    assert(md_memory_buffers_prepare(parent,2,5000,5000)==-EALREADY);
    struct md_interception_buffers *pool=md_memory_buffers(parent);
    size_t size=md_buffers_size(pool);
    struct md_interception_buffer a={0},b={0},worker={0},extra={0};
    assert(!md_buffers_take(pool,&a));
    assert(!md_memory_buffer_address(parent,&a));
    assert(md_memory_buffers_mapped(parent,0x40000001,size)==-EINVAL);
    assert(md_memory_buffers_mapped(parent,0x40000000,size+1)==-EINVAL);
    assert(!md_memory_buffers_mapped(parent,0x40000000,size));
    assert(md_memory_buffers_mapped(parent,0x40000000,size)==-EALREADY);
    struct md_interception_memory *thread=md_memory_fork(parent,1);
    struct md_interception_memory *child=md_memory_fork(parent,0);
    assert(thread==parent && child && child!=parent && md_memory_buffers(child)==pool);
    struct md_resource_order first={0}, next={0}, independent={0};
    assert(md_memory_order_begin(parent,&first,NULL)==1 && !md_resource_order_start(&first));
    assert(md_memory_order_begin(thread,&next,NULL)==0);
    assert(md_memory_order_begin(child,&independent,NULL)==1 && !md_resource_order_start(&independent));
    assert(md_resource_order_state(&next)==MD_RESOURCE_ORDER_QUEUED);
    assert(md_resource_order_cancel(&first)==1);
    assert(md_resource_order_state(&next)==MD_RESOURCE_ORDER_QUEUED);
    assert(!md_resource_order_complete(&first));
    assert(md_resource_order_state(&next)==MD_RESOURCE_ORDER_READY);
    assert(!md_resource_order_cancel(&next) && !md_resource_order_complete(&independent));
    assert(!md_buffers_take(md_memory_buffers(child),&b));
    assert(md_memory_buffer_address(parent,&a)==md_memory_buffer_address(child,&a));
    assert(md_memory_buffer_address(child,&a)!=md_memory_buffer_address(child,&b));
    assert(md_buffers_take(pool,&extra)==-EAGAIN);
    assert(!md_buffer_pin(&a,&worker));
    int fd=md_buffers_fd(pool);
    md_memory_release(parent); md_memory_release(thread); md_memory_release(child);
    assert(!md_buffer_release(&a) && !md_buffer_release(&b));
    assert(fcntl(fd,F_GETFD)>=0);
    struct md_interception_memory *exec=md_memory_new(); assert(exec);
    assert(!md_memory_buffers(exec) && !md_memory_buffer_address(exec,&worker));
    assert(!md_memory_buffers_prepare(exec,1,4096,4096));
    assert(md_memory_buffers(exec)!=worker.pool);
    md_memory_release(exec);
    assert(!md_buffer_release(&worker) && fcntl(fd,F_GETFD)==-1 && errno==EBADF);
    puts("PASS adapter memory: CLONE_VM owner, fork-shared allocator, exact mapping admission, exec isolation and terminal worker pins");
}
static void payload_reuse(void) {
    struct md_interception_buffers *pool=NULL;
    assert(md_buffers_create(1,64,65,&pool)==-EINVAL && !pool);
    assert(!md_buffers_create(1,65536,64,&pool));
    struct md_interception_buffer slot={0}; struct md_buffer_span span;
    assert(!md_buffers_take(pool,&slot) && !md_buffer_span(&slot,&span));
    memset(span.data,0x7a,span.size);
    assert(!md_buffer_release(&slot));
    unsigned before=allocations; fail_allocation=1;
    assert(!md_buffers_take(pool,&slot) && !md_buffer_span(&slot,&span));
    for (size_t i=0;i<span.size;++i) assert(((unsigned char *)span.data)[i]==(i<64 ? 0 : 0x7a));
    assert(allocations==before && !md_buffer_release(&slot));
    fail_allocation=0; md_buffers_release(pool);
    puts("PASS buffer payload reuse: only declared header cleared, no allocation or bulk overwrite");
}
static void mapping_policy(void) {
    struct md_interception_memory *m=md_memory_new(); assert(m);
    struct md_mapping_change c={0};
    size_t p=(size_t)getpagesize(); uintptr_t base=0x10000000;
    unsigned before=allocations;
    fail_allocation=1;
    assert(!md_memory_mapping_prepare(m,&c,MD_MAPPING_MAP,0,p,0,0,0));
    md_memory_mapping_finish(m,&c,(long)base);
    assert(!md_memory_has_policy(m) && !md_memory_exec_check(m,base,p));
    assert(allocations==before);
    assert(md_memory_mapping_prepare(m,&c,MD_MAPPING_MAP,0,3*p,0,0,1)==-ENOMEM && !c.prepared);
    fail_allocation=0;
    assert(!md_memory_mapping_prepare(m,&c,MD_MAPPING_MAP,0,3*p,0,0,1));
    md_memory_mapping_finish(m,&c,-ENOMEM);
    assert(!md_memory_has_policy(m));
    assert(!md_memory_mapping_prepare(m,&c,MD_MAPPING_MAP,0,3*p,0,0,1));
    md_memory_mapping_finish(m,&c,(long)base);
    assert(md_memory_exec_check(m,base,p)==-EACCES);
    struct md_interception_memory *copy=md_memory_fork(m,0); assert(copy);
    before=allocations; fail_allocation=1;
    assert(!md_memory_mapping_prepare(m,&c,MD_MAPPING_UNMAP,base+p,p,0,0,0));
    md_memory_mapping_finish(m,&c,0);
    assert(md_memory_exec_check(m,base,p)==-EACCES);
    assert(!md_memory_exec_check(m,base+p,p));
    assert(md_memory_exec_check(m,base+2*p,p)==-EACCES);
    assert(md_memory_exec_check(copy,base+p,p)==-EACCES);
    assert(!md_memory_mapping_prepare(m,&c,MD_MAPPING_REMAP,base,p,2*p,MREMAP_MAYMOVE|MREMAP_FIXED,0));
    md_memory_mapping_finish(m,&c,(long)(base+10*p));
    assert(!md_memory_exec_check(m,base,p));
    assert(md_memory_exec_check(m,base+11*p,p)==-EACCES);
    assert(!md_memory_mapping_prepare(m,&c,MD_MAPPING_REMAP,base+10*p,0,p,MREMAP_MAYMOVE,0));
    md_memory_mapping_finish(m,&c,(long)(base+20*p));
    assert(md_memory_exec_check(m,base+10*p,p)==-EACCES);
    assert(md_memory_exec_check(m,base+20*p,p)==-EACCES);
    assert(allocations==before);
    fail_allocation=0;
    assert(!md_memory_mapping_prepare(m,&c,MD_MAPPING_MAP,base,p,0,0,1));
    md_memory_mapping_abandon(m,&c);
    assert(md_memory_exec_check(m,base,p)==-EIO);
    assert(md_memory_exec_check(copy,base,p)==-EACCES);
    assert(md_memory_exec_check(copy,base+1,p)==-EINVAL);
    assert(md_memory_exec_check(copy,base,SIZE_MAX)==-ENOMEM);
    md_memory_release(m); md_memory_release(copy);
    puts("PASS mapping policy: allocation-free ordinary IO, prepare rollback, split/move/clone, fork independence and unknown terminal result");
}
int main(void) {
    unsigned before=descriptors();
    slots(); owner_lifetime(); failures(); address_spaces(); payload_reuse(); mapping_policy();
    assert(descriptors()==before);
    puts("PASS shared request buffer ownership");
    return 0;
}
