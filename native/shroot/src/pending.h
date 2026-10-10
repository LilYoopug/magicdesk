#ifndef MD_PENDING_H
#define MD_PENDING_H

struct md_pending_node;
struct md_pending_list { struct md_pending_node *first, *last; };
/* Event-loop-owned intrusive continuations. Zero initialization is sufficient;
 * nodes must be cancelled before their owning storage is freed or reused. */
struct md_pending_node {
    struct md_pending_node *previous, *next;
    struct md_pending_list *list;
};
struct md_pending_queue {
    struct md_pending_list lists[2];
    unsigned current;
    int running;
};
void md_pending_add(struct md_pending_queue *, struct md_pending_node *);
void md_pending_cancel(struct md_pending_node *);
/* Each admitted node runs at most once per dispatch. Callbacks may cancel any
 * node, or requeue themselves; additions wait for the next event-loop turn.
 * Recursive dispatch returns -EBUSY; the caller must retain its wakeup. */
int md_pending_dispatch(struct md_pending_queue *, void (*)(struct md_pending_node *, void *), void *);
#endif
