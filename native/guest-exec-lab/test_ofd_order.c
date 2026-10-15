#define _GNU_SOURCE
#include "ofd_order.h"
#include "queue_signal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

static void queue_signals(void) {
    struct md_queue_signal signal;
    assert(!md_queue_signal_open(&signal));
    assert(fcntl(signal.reader,F_GETFL)&O_NONBLOCK);
    assert(fcntl(signal.writer,F_GETFD)&FD_CLOEXEC);
    assert(!md_queue_signal_acknowledge(&signal));
    for (unsigned i=0;i<10000;++i) assert(!md_queue_signal_send(&signal));
    struct pollfd ready={signal.reader,POLLIN,0};
    unsigned drains=0;
    while (poll(&ready,1,0)==1) { assert(!md_queue_signal_acknowledge(&signal)); ++drains; }
    assert(drains && drains<=20);
    assert(!md_queue_signal_send(&signal) && poll(&ready,1,0)==1);
    assert(!md_queue_signal_acknowledge(&signal) && !poll(&ready,1,0));
    struct md_resource_wakeup *wake=NULL;
    assert(!md_resource_wakeup_create_pipe(signal.reader,signal.writer,&wake));
    struct md_resource_queue queue; assert(!md_resource_queue_init(&queue));
    struct md_resource_order first={0}, second={0};
    assert(md_resource_order_begin(&queue,&first,wake)==1 && !md_resource_order_start(&first));
    assert(!md_resource_order_begin(&queue,&second,wake));
    md_resource_wakeup_release(wake);
    int reader=signal.reader, writer=signal.writer;
    md_queue_signal_close(&signal);
    int unrelated=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC); assert(unrelated>=0);
    assert(dup2(unrelated,reader)==reader && dup2(unrelated,writer)==writer);
    /* Retained readiness neither reaches a reused number nor loses its reader
     * after the loop exits. In particular, no SIGPIPE can be generated. */
    assert(!md_resource_order_complete(&first));
    assert(md_resource_order_state(&second)==MD_RESOURCE_ORDER_READY);
    uint64_t value; assert(read(unrelated,&value,sizeof(value))<0 && errno==EAGAIN);
    assert(!md_resource_order_cancel(&second));
    close(reader); close(writer);
    if (unrelated!=reader && unrelated!=writer) close(unrelated);
    md_resource_queue_destroy(&queue);
    puts("PASS bounded pipe readiness, saturation, retained wake lifetime and FD reuse");
}
void test_ofd_order(void) {
    queue_signals();
    struct md_ofd_orders *q=NULL; assert(!md_ofd_orders_new(&q));
    int fd=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC), other=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    int alias=dup(fd), event=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    assert(fd>=0 && other>=0 && alias>=0 && event>=0);
    struct md_resource_wakeup *wake=NULL; assert(!md_resource_wakeup_create(event,&wake));
    for (unsigned i=0;i<100;++i) {
        struct md_ofd_order a={0}, b={0}, c={0}, d={0};
        assert(md_ofd_order_begin(q,fd,0,&a,wake)==1 && !a.owner);
        assert(md_ofd_order_begin(q,fd,1,&a,wake)==1 && a.owner);
        assert(!md_ofd_order_start(&a));
        assert(md_ofd_order_begin(q,alias,0,&b,wake)==0);
        assert(md_ofd_order_begin(q,other,0,&c,wake)==1 && !c.owner);
        assert(md_ofd_order_begin(q,other,1,&c,wake)==1 && c.owner);
        assert(!md_ofd_order_start(&c) && !md_ofd_order_complete(&c));
        assert(md_ofd_order_begin(q,alias,1,&d,wake)==0);
        assert(md_ofd_order_cancel(&a)==1);
        assert(md_ofd_order_state(&b)==MD_RESOURCE_ORDER_QUEUED);
        assert(!md_ofd_order_complete(&a));
        uint64_t value; assert(read(event,&value,sizeof(value))==sizeof(value) && value==1);
        assert(md_ofd_order_state(&b)==MD_RESOURCE_ORDER_READY);
        assert(!md_ofd_order_cancel(&d));
        assert(!md_ofd_order_start(&b) && !md_ofd_order_complete(&b));
        assert(md_ofd_order_begin(q,fd,0,&a,wake)==1 && !a.owner);
    }
    /* Closing/reusing the admitted number cannot retarget either the owner or
     * a later dup. A separately opened description must never share its turn. */
    struct md_ofd_order a={0}, b={0}, c={0};
    assert(md_ofd_order_begin(q,fd,1,&a,wake)==1 && !md_ofd_order_start(&a));
    assert(!close(fd) && dup2(other,fd)==fd);
    assert(md_ofd_order_begin(q,fd,0,&b,wake)==1 && !b.owner);
    assert(md_ofd_order_begin(q,alias,0,&c,wake)==0);
    assert(!md_ofd_order_cancel(&c) && !md_ofd_order_complete(&a));
    assert(md_ofd_order_begin(q,fd,1,&a,wake)==1 && !md_ofd_order_start(&a));
    md_ofd_orders_release(q);
    assert(!md_ofd_order_complete(&a));
    md_resource_wakeup_release(wake);
    assert(!close(fd) && !close(other) && !close(alias) && !close(event));
    puts("PASS active OFD ordering: aliases, independent opens, cancellation, readiness and number reuse");
}
