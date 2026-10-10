#include "pending.h"
#include <errno.h>
#include <stddef.h>

void md_pending_add(struct md_pending_queue *queue, struct md_pending_node *node) {
    if (node->list) return;
    struct md_pending_list *list=&queue->lists[queue->current];
    node->list=list; node->previous=list->last;
    if (list->last) list->last->next=node; else list->first=node;
    list->last=node;
}
void md_pending_cancel(struct md_pending_node *node) {
    struct md_pending_list *list=node->list;
    if (!list) return;
    if (node->previous) node->previous->next=node->next; else list->first=node->next;
    if (node->next) node->next->previous=node->previous; else list->last=node->previous;
    *node=(struct md_pending_node){0};
}
int md_pending_dispatch(struct md_pending_queue *queue,
        void (*run)(struct md_pending_node *, void *), void *context) {
    if (queue->running) return -EBUSY;
    struct md_pending_list *ready=&queue->lists[queue->current];
    if (!ready->first) return 0;
    queue->current^=1; queue->running=1;
    while (ready->first) {
        struct md_pending_node *node=ready->first;
        md_pending_cancel(node);
        run(node,context);
    }
    queue->running=0; return 0;
}
