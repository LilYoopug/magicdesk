#include "resource_order.h"
#include "event_signal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

struct md_resource_wakeup { atomic_uint refs; int fd; };
int md_resource_queue_init(struct md_resource_queue *q) {
    *q=(struct md_resource_queue){0};
    return -pthread_mutex_init(&q->lock,NULL);
}
void md_resource_queue_destroy(struct md_resource_queue *q) { pthread_mutex_destroy(&q->lock); }
int md_resource_wakeup_create(int fd, struct md_resource_wakeup **out) {
    if (!out) return -EINVAL;
    *out=NULL;
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if (!(flags&O_NONBLOCK)) return -EINVAL;
    struct md_resource_wakeup *wake=malloc(sizeof(*wake));
    if (!wake) return -ENOMEM;
    wake->fd=fcntl(fd,F_DUPFD_CLOEXEC,0);
    if (wake->fd<0) { int error=-errno; free(wake); return error; }
    atomic_init(&wake->refs,1); *out=wake; return 0;
}
static struct md_resource_wakeup *retain(struct md_resource_wakeup *wake) {
    if (wake) atomic_fetch_add_explicit(&wake->refs,1,memory_order_relaxed);
    return wake;
}
void md_resource_wakeup_release(struct md_resource_wakeup *wake) {
    if (!wake || atomic_fetch_sub_explicit(&wake->refs,1,memory_order_acq_rel)!=1) return;
    close(wake->fd); free(wake);
}
static int signal_ready(struct md_resource_wakeup *wake) {
    return wake ? md_event_signal(wake->fd) : 0;
}
int md_resource_order_begin(struct md_resource_queue *q, struct md_resource_order *op, struct md_resource_wakeup *wake) {
    if (!q || !op) return -EINVAL;
    if (op->state!=MD_RESOURCE_ORDER_IDLE || op->queue || op->previous || op->next) return -EBUSY;
    op->queue=q; op->wakeup=retain(wake);
    pthread_mutex_lock(&q->lock);
    op->previous=q->last;
    if (q->last) q->last->next=op; else q->first=op;
    q->last=op;
    op->state=q->first==op ? MD_RESOURCE_ORDER_READY : MD_RESOURCE_ORDER_QUEUED;
    int ready=op->state==MD_RESOURCE_ORDER_READY;
    pthread_mutex_unlock(&q->lock); return ready;
}
enum md_resource_order_state md_resource_order_state(const struct md_resource_order *op) {
    if (!op || !op->queue) return MD_RESOURCE_ORDER_IDLE;
    struct md_resource_queue *q=op->queue;
    pthread_mutex_lock(&q->lock);
    enum md_resource_order_state state=op->state;
    pthread_mutex_unlock(&q->lock); return state;
}
int md_resource_order_start(struct md_resource_order *op) {
    if (!op || !op->queue) return -EINVAL;
    struct md_resource_queue *q=op->queue;
    pthread_mutex_lock(&q->lock);
    int error=op->state!=MD_RESOURCE_ORDER_READY ? -EINVAL : 0;
    if (!error) op->state=MD_RESOURCE_ORDER_RUNNING;
    pthread_mutex_unlock(&q->lock); return error;
}
static int retire(struct md_resource_order *op) {
    struct md_resource_queue *q=op->queue;
    struct md_resource_wakeup *owner=op->wakeup, *next=NULL;
    int first=q->first==op;
    if (op->previous) op->previous->next=op->next; else q->first=op->next;
    if (op->next) op->next->previous=op->previous; else q->last=op->previous;
    *op=(struct md_resource_order){0};
    if (first && q->first) {
        q->first->state=MD_RESOURCE_ORDER_READY;
        next=retain(q->first->wakeup);
    }
    pthread_mutex_unlock(&q->lock);
    int error=signal_ready(next);
    md_resource_wakeup_release(next); md_resource_wakeup_release(owner);
    return error;
}
int md_resource_order_cancel(struct md_resource_order *op) {
    if (!op || !op->queue) return -EINVAL;
    struct md_resource_queue *q=op->queue;
    pthread_mutex_lock(&q->lock);
    if (op->state==MD_RESOURCE_ORDER_RUNNING || op->state==MD_RESOURCE_ORDER_CANCELLING) {
        op->state=MD_RESOURCE_ORDER_CANCELLING; pthread_mutex_unlock(&q->lock); return 1;
    }
    if (op->state!=MD_RESOURCE_ORDER_QUEUED && op->state!=MD_RESOURCE_ORDER_READY) {
        pthread_mutex_unlock(&q->lock); return -EINVAL;
    }
    return retire(op);
}
int md_resource_order_complete(struct md_resource_order *op) {
    if (!op || !op->queue) return -EINVAL;
    struct md_resource_queue *q=op->queue;
    pthread_mutex_lock(&q->lock);
    if (op->state!=MD_RESOURCE_ORDER_RUNNING && op->state!=MD_RESOURCE_ORDER_CANCELLING) {
        pthread_mutex_unlock(&q->lock); return -EINVAL;
    }
    return retire(op);
}
