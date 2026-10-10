#include "pending.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>

struct item { struct md_pending_node node; unsigned calls; };
struct test { struct md_pending_queue queue; struct item items[4]; int mutate; };
static void run(struct md_pending_node *node, void *context) {
    struct test *test=context;
    struct item *item=(struct item *)node;
    item->calls++;
    if (item==&test->items[0] && test->mutate) {
        md_pending_cancel(&test->items[1].node);
        /* Reuse cancelled storage while a dispatch still owns its snapshot. */
        test->items[1]=(struct item){0};
        md_pending_add(&test->queue,&test->items[1].node);
        md_pending_add(&test->queue,&test->items[3].node);
        assert(md_pending_dispatch(&test->queue,run,test)==-EBUSY);
    }
    md_pending_add(&test->queue,node);
    md_pending_add(&test->queue,node);
}
int main(void) {
    struct test test={.mutate=1};
    assert(!md_pending_dispatch(&test.queue,run,&test));
    for (unsigned i=0;i<3;i++) md_pending_add(&test.queue,&test.items[i].node);
    assert(!md_pending_dispatch(&test.queue,run,&test));
    assert(test.items[0].calls==1 && !test.items[1].calls
        && test.items[2].calls==1 && !test.items[3].calls);
    test.mutate=0;
    assert(!md_pending_dispatch(&test.queue,run,&test));
    for (unsigned i=0;i<4;i++) assert(test.items[i].calls==(i==0 || i==2 ? 2u : 1u));
    for (unsigned i=0;i<4;i++) {
        md_pending_cancel(&test.items[i].node);
        md_pending_cancel(&test.items[i].node);
    }
    assert(!md_pending_dispatch(&test.queue,run,&test));
    for (unsigned i=0;i<4;i++) assert(test.items[i].calls==(i==0 || i==2 ? 2u : 1u));
    puts("PASS pending continuations: coalescing, bounded dispatch, cancellation, reuse, recursion");
}
