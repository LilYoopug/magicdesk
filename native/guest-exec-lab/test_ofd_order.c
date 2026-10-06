#define _GNU_SOURCE
#include "ofd_order.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <unistd.h>

void test_ofd_order(void) {
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
