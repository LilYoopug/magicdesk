#define _GNU_SOURCE
#include "control_event.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

static atomic_int no_allocation;
static atomic_uint fail_allocation;
void control_no_allocation(int enabled) { atomic_store(&no_allocation,enabled); }
void control_fail_allocation(unsigned after) { atomic_store(&fail_allocation,after); }
static int allocation_fails(void) {
    unsigned left=atomic_load(&fail_allocation);
    if (!left || atomic_fetch_sub(&fail_allocation,1)!=1) return 0;
    errno=ENOMEM; return 1;
}
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__wrap_malloc(size_t size) {
    assert(!atomic_load(&no_allocation));
    if (allocation_fails()) return NULL;
    return __real_malloc(size);
}
void *__wrap_calloc(size_t n,size_t size) {
    assert(!atomic_load(&no_allocation));
    if (allocation_fails()) return NULL;
    return __real_calloc(n,size);
}
static void ready(int fd,int expected) {
    struct pollfd p={fd,POLLIN,0};
    assert(poll(&p,1,0)==expected);
    assert(p.revents==(expected ? POLLIN : 0));
}
static void independent_opens(void) {
    struct md_control_event *source=md_control_event_new(); assert(source);
    struct md_control_cursor a,b,c;
    md_control_cursor_open(&a,source); md_control_cursor_open(&b,source);
    assert(a.wake==-1 && b.wake==-1);
    assert(!md_control_cursor_poll(&a));
    assert(!md_control_event_publish(source));
    md_control_cursor_open(&c,source);
    int aw=md_control_cursor_watch(&a),bw=md_control_cursor_watch(&b);
    assert(aw>=0 && bw>=0 && aw!=bw && md_control_cursor_watch(&a)==aw);
    assert(fcntl(aw,F_GETFD)&FD_CLOEXEC);
    assert(fcntl(aw,F_GETFL)&O_NONBLOCK);
    ready(aw,1); ready(bw,1);
    assert(md_control_cursor_poll(&a)==1);
    ready(aw,0); ready(bw,1);
    assert(!md_control_cursor_poll(&a));
    assert(md_control_cursor_poll(&b)==1 && !md_control_cursor_poll(&c));
    md_control_event_release(source);
    assert(!md_control_event_publish(a.source));
    assert(md_control_cursor_poll(&a)==1);
    assert(md_control_cursor_poll(&b)==1);
    assert(md_control_cursor_poll(&c)==1);
    md_control_cursor_close(&a); md_control_cursor_close(&b); md_control_cursor_close(&c);
    assert(fcntl(aw,F_GETFD)<0 && errno==EBADF);
    puts("PASS independent opens, shared cursor, late subscription and source lifetime");
}
struct race {
    struct md_control_event *source;
    pthread_barrier_t gate;
};
static void *publisher(void *opaque) {
    struct race *r=opaque;
    for (unsigned i=0;i<10000;++i) {
        /* EVENT_WAIT: paired test phases; the fixture process deadline owns
         * failure if either participant fails to arrive. */
        pthread_barrier_wait(&r->gate);
        assert(!md_control_event_publish(r->source));
        pthread_barrier_wait(&r->gate);
    }
    return NULL;
}
static void publication_races(void) {
    struct race r={.source=md_control_event_new()}; assert(r.source);
    assert(!pthread_barrier_init(&r.gate,NULL,2));
    pthread_t thread; assert(!pthread_create(&thread,NULL,publisher,&r));
    for (unsigned i=0;i<10000;++i) {
        struct md_control_cursor c;
        md_control_cursor_open(&c,r.source);
        pthread_barrier_wait(&r.gate);
        int fd=md_control_cursor_watch(&c); assert(fd>=0);
        if (i&1) {
            int first=md_control_cursor_poll(&c); assert(first>=0);
            pthread_barrier_wait(&r.gate);
            int second=md_control_cursor_poll(&c); assert(second>=0 && first+second==1);
        } else {
            /* Publication races retirement, including reuse of the same slot. */
            md_control_cursor_close(&c);
            int reused=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK); assert(reused>=0);
            pthread_barrier_wait(&r.gate); ready(reused,0); close(reused);
        }
        md_control_cursor_close(&c);
    }
    assert(!pthread_join(thread,NULL));
    pthread_barrier_destroy(&r.gate); md_control_event_release(r.source);
    puts("PASS publication/subscribe/acknowledge/close races (10000 rounds)");
}
static void event_loop(void) {
    struct md_control_event *source=md_control_event_new(); assert(source);
    struct md_control_cursor c; md_control_cursor_open(&c,source);
    int ep=epoll_create1(EPOLL_CLOEXEC),native=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    int wake=md_control_cursor_watch(&c); assert(ep>=0 && native>=0 && wake>=0);
    struct epoll_event e={.events=EPOLLIN,.data.u64=10},out[2];
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,wake,&e));
    e.data.u64=20; assert(!epoll_ctl(ep,EPOLL_CTL_ADD,native,&e));
    atomic_store(&no_allocation,1);
    for (unsigned i=0;i<100000;++i) {
        assert(!md_control_event_publish(source));
        assert(!md_control_event_publish(source));
        assert(epoll_wait(ep,out,2,0)==1 && out[0].data.u64==10);
        assert(md_control_cursor_poll(&c)==1);
        assert(epoll_wait(ep,out,2,0)==0);
        uint64_t one=1,value=0;
        assert(write(native,&one,sizeof(one))==sizeof(one));
        assert(epoll_wait(ep,out,2,0)==1 && out[0].data.u64==20);
        assert(read(native,&value,sizeof(value))==sizeof(value) && value==1);
    }
    atomic_store(&no_allocation,0);
    close(native); close(ep); md_control_cursor_close(&c); md_control_event_release(source);
    puts("PASS mixed native wakeups and coalesced generations, no hot-path allocations (100000 rounds)");
}
int main(void) {
    extern void test_control_epoll(void);
    independent_opens(); publication_races(); event_loop();
    test_control_epoll();
    return 0;
}
