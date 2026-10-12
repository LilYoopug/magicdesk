#define _GNU_SOURCE
#include "fd_weak.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

struct object {
    struct md_fd_object object;
    atomic_uint *destroyed;
    unsigned value;
};
static void destroy(struct md_fd_object *o) {
    struct object *p=(void *)o;
    assert(p->value==42);
    atomic_fetch_add(p->destroyed,1); free(p);
}
static const struct md_fd_object_type type={.destroy=destroy};
struct race {
    pthread_barrier_t gate;
    struct md_fd_weak *weak;
};
static void phase(struct race *r) {
    /* EVENT_WAIT: paired fixture phase; the test launcher deadline bounds a
     * missing participant without treating a delay as a completed release. */
    int result=pthread_barrier_wait(&r->gate);
    assert(result==0 || result==PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *locker(void *opaque) {
    struct race *r=opaque;
    for (unsigned n=0;n<10000;++n) {
        phase(r);
        for (unsigned i=0;i<16;++i) {
            struct md_fd_object *o=md_fd_weak_lock(r->weak);
            if (o) assert(((struct object *)o)->value==42);
            md_fd_object_release(o);
        }
        phase(r);
    }
    return NULL;
}
void test_fd_weak(void) {
    atomic_uint destroyed=0;
    struct race r;
    assert(!pthread_barrier_init(&r.gate,NULL,2));
    pthread_t thread; assert(!pthread_create(&thread,NULL,locker,&r));
    for (unsigned n=0;n<10000;++n) {
        struct object *o=calloc(1,sizeof(*o)); assert(o);
        md_fd_object_init(&o->object,&type); o->value=42; o->destroyed=&destroyed;
        r.weak=md_fd_weak_observe(&o->object); assert(r.weak);
        struct md_fd_weak *again=md_fd_weak_observe(&o->object); assert(again==r.weak);
        md_fd_weak_release(again);
        int fd=md_fd_weak_descriptor(r.weak);
        assert(fcntl(fd,F_GETFD)&FD_CLOEXEC);
        assert(fcntl(fd,F_GETFL)&O_NONBLOCK);
        struct pollfd p={fd,POLLIN,0}; assert(!poll(&p,1,0));
        phase(&r);
        md_fd_object_release(&o->object);
        phase(&r);
        assert(atomic_load(&destroyed)==n+1);
        assert(md_fd_weak_expired(r.weak) && !md_fd_weak_lock(r.weak));
        assert(poll(&p,1,0)==1 && p.revents==POLLIN);
        assert(poll(&p,1,0)==1);
        md_fd_weak_release(r.weak);
        assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
    }
    assert(!pthread_join(thread,NULL));
    pthread_barrier_destroy(&r.gate);
    puts("PASS weak descriptor authority: lock/final-release races, no resurrection, persistent expiry (10000 rounds)");
}
