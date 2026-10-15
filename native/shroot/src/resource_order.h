#ifndef MD_RESOURCE_ORDER_H
#define MD_RESOURCE_ORDER_H
#include <pthread.h>

struct md_resource_wakeup;
struct md_resource_order;
/* Embedded in an independently shared resource. Its typed adapter pins that
 * resource while an order record is admitted; kernel objects remain borrowed. */
struct md_resource_queue {
    pthread_mutex_t lock;
    struct md_resource_order *first, *last;
};
enum md_resource_order_state { MD_RESOURCE_ORDER_IDLE, MD_RESOURCE_ORDER_QUEUED,
    MD_RESOURCE_ORDER_READY, MD_RESOURCE_ORDER_RUNNING, MD_RESOURCE_ORDER_CANCELLING };
/* Caller-owned, zero-initialized storage. One serialized owner starts, cancels
 * or completes it; sharing that owner across threads requires external locking.
 * Queue mutation and cross-loop readiness are synchronized. */
struct md_resource_order {
    struct md_resource_queue *queue;
    struct md_resource_order *previous, *next;
    enum md_resource_order_state state;
    struct md_resource_wakeup *wakeup;
};
int md_resource_queue_init(struct md_resource_queue *);
void md_resource_queue_destroy(struct md_resource_queue *);
/* One duplicated nonblocking eventfd per loop, not per operation. Retained
 * tokens cannot signal a reused descriptor after the receiving loop exits. */
int md_resource_wakeup_create(int eventfd, struct md_resource_wakeup **);
/* A pipe-backed loop retains both ends so a late signal remains harmless
 * after the loop closes its descriptors. No SIGPIPE policy is required. */
int md_resource_wakeup_create_pipe(int reader, int writer, struct md_resource_wakeup **);
struct md_resource_wakeup *md_resource_wakeup_retain(struct md_resource_wakeup *);
void md_resource_wakeup_release(struct md_resource_wakeup *);
/* No allocation, blocking wait or event-loop callback. Returns 1 ready, 0 queued.
 * NULL wakeup is only for synchronous callers that explicitly inspect state. */
int md_resource_order_begin(struct md_resource_queue *, struct md_resource_order *, struct md_resource_wakeup *);
enum md_resource_order_state md_resource_order_state(const struct md_resource_order *);
int md_resource_order_start(struct md_resource_order *);
/* Running cancellation returns 1 and retains the turn until the exact kernel
 * completion/terminal event. Retirement signals the next owner without exposing
 * its record pointer. Publication precedes completion. */
int md_resource_order_cancel(struct md_resource_order *);
int md_resource_order_complete(struct md_resource_order *);
#endif
