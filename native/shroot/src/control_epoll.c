#define _GNU_SOURCE
#include "control_epoll.h"
#include "event_signal.h"
#include "fd_weak.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/eventfd.h>

struct interest {
    struct interest *next,*previous,*ready_next,*ready_previous;
    struct md_fd_weak *identity;
    struct md_control_file provider;
    struct epoll_event event;
    int fd,wake,lifetime,armed,lifetime_armed,queued,disabled;
};
struct md_control_epoll {
    struct md_fd_object object;
    int events,ready,signalled;
    unsigned pending;
    struct interest *first,*head,*tail;
};
static int ready_signal(struct md_control_epoll *q) {
    int pending=!!q->pending;
    if (pending==q->signalled) return 0;
    int error=pending ? md_event_signal(q->ready) : md_event_acknowledge(q->ready);
    if (!error) q->signalled=pending;
    return error;
}
static void enqueue(struct md_control_epoll *q,struct interest *i) {
    if (i->queued || (i->disabled && !md_fd_weak_expired(i->identity))) return;
    i->ready_previous=q->tail; i->ready_next=NULL;
    if (q->tail) q->tail->ready_next=i; else q->head=i;
    q->tail=i; i->queued=1; ++q->pending;
}
static void dequeue(struct md_control_epoll *q,struct interest *i) {
    if (!i->queued) return;
    if (i->ready_previous) i->ready_previous->ready_next=i->ready_next; else q->head=i->ready_next;
    if (i->ready_next) i->ready_next->ready_previous=i->ready_previous; else q->tail=i->ready_previous;
    i->ready_next=i->ready_previous=NULL; i->queued=0; --q->pending;
}
static int arm(struct md_control_epoll *q,struct interest *i) {
    if (i->wake<0 || i->armed) return 0;
    struct epoll_event event={.events=EPOLLIN|EPOLLET,.data.ptr=i};
    if (epoll_ctl(q->events,EPOLL_CTL_ADD,i->wake,&event)) return -errno;
    i->armed=1; return 0;
}
static int disarm(struct md_control_epoll *q,struct interest *i) {
    if (!i->armed) return 0;
    if (epoll_ctl(q->events,EPOLL_CTL_DEL,i->wake,NULL)) return -errno;
    i->armed=0; return 0;
}
static void discard(struct md_control_epoll *q,struct interest *i) {
    dequeue(q,i);
    if (i->wake>=0) {
        /* Explicit DEL is required: another registration can retain a dup of
         * this source's OFD, so closing this descriptor alone is insufficient. */
        disarm(q,i); close(i->wake);
    }
    if (i->lifetime>=0) {
        if (i->lifetime_armed) epoll_ctl(q->events,EPOLL_CTL_DEL,i->lifetime,NULL);
        close(i->lifetime);
    }
    if (i->previous) i->previous->next=i->next; else q->first=i->next;
    if (i->next) i->next->previous=i->previous;
    md_fd_weak_release(i->identity); free(i);
}
static void transport_close(struct md_control_epoll *q) {
    if (q->ready>=0) close(q->ready);
    if (q->events>=0) close(q->events);
    q->events=q->ready=-1; q->signalled=0;
}
static int transport_open(struct md_control_epoll *q) {
    if (q->events>=0) return 0;
    q->events=epoll_create1(EPOLL_CLOEXEC); q->ready=-1;
    int error=q->events<0 ? errno : 0;
    if (!error) { q->ready=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK); if (q->ready<0) error=errno; }
    if (!error) {
        struct epoll_event event={.events=EPOLLIN,.data.ptr=NULL};
        if (epoll_ctl(q->events,EPOLL_CTL_ADD,q->ready,&event)) error=errno;
    }
    if (error) transport_close(q);
    return -error;
}
static void destroy(struct md_fd_object *object) {
    struct md_control_epoll *q=(void *)object;
    while (q->first) discard(q,q->first);
    transport_close(q); free(q);
}
static const struct md_fd_object_type type={.destroy=destroy};
struct md_control_epoll *md_control_epoll_new(void) {
    struct md_control_epoll *q=calloc(1,sizeof(*q));
    if (!q) return NULL;
    md_fd_object_init(&q->object,&type);
    q->events=q->ready=-1;
    return q;
}
struct md_fd_object *md_control_epoll_object(struct md_control_epoll *q) {
    return q ? &q->object : NULL;
}
struct md_control_epoll *md_control_epoll_from_object(struct md_fd_object *object) {
    return object && object->type==&type ? (void *)object : NULL;
}
void md_control_epoll_release(struct md_control_epoll *q) {
    md_fd_object_release(md_control_epoll_object(q));
}
int md_control_epoll_descriptor(const struct md_control_epoll *q) {
    return q ? q->events : -EINVAL;
}
static struct interest *find(struct md_control_epoll *q,int fd,const struct md_fd_object *identity) {
    struct md_fd_weak *weak=atomic_load_explicit(&identity->weak,memory_order_acquire);
    for (struct interest *i=q->first;i;i=i->next)
        if (i->fd==fd && i->identity==weak) return i;
    return NULL;
}
static int harvest(struct md_control_epoll *q) {
    if (q->events<0) return 0;
    struct epoll_event wakes[32];
    int count=epoll_wait(q->events,wakes,32,0);
    if (count<0) return -errno;
    /* Several entries can refer to one interest (source and retirement).
     * Queue the complete batch before freeing any interest. */
    for (int n=0;n<count;++n) if (wakes[n].data.ptr) enqueue(q,wakes[n].data.ptr);
    return 0;
}
static void reap(struct md_control_epoll *q) {
    for (struct interest *i=q->head,*next;i;i=next) {
        next=i->ready_next;
        if (md_fd_weak_expired(i->identity)) discard(q,i);
    }
}
static uint32_t requested(const struct epoll_event *e) {
    return (e->events&~(EPOLLET|EPOLLONESHOT))|EPOLLERR|EPOLLHUP;
}
int md_control_epoll_ctl(struct md_control_epoll *q,int operation,int fd,
        struct md_fd_object *identity,struct md_control_file provider,const struct epoll_event *event) {
    if (!q || !identity || fd<0) return -EINVAL;
    if (operation!=EPOLL_CTL_ADD && operation!=EPOLL_CTL_MOD && operation!=EPOLL_CTL_DEL) return -EINVAL;
    if (operation!=EPOLL_CTL_DEL && !event) return -EFAULT;
    /* These policies need a distinct owner; do not silently approximate them. */
    if (event && operation!=EPOLL_CTL_DEL && (event->events&(EPOLLEXCLUSIVE|EPOLLWAKEUP))) return -EOPNOTSUPP;
    int observed=harvest(q);
    if (observed) return observed;
    reap(q);
    observed=ready_signal(q);
    if (observed) return observed;
    struct interest *i=find(q,fd,identity);
    if (operation==EPOLL_CTL_DEL) {
        if (!i) return -ENOENT;
        int error=disarm(q,i);
        if (error) return error;
        discard(q,i); return ready_signal(q);
    }
    if (operation==EPOLL_CTL_MOD) {
        if (!i) return -ENOENT;
        int error=arm(q,i);
        if (error) return error;
        long mask=i->provider.ops->poll(i->provider.context);
        if (mask<0) { if (i->disabled) disarm(q,i); return (int)mask; }
        i->event=*event; i->disabled=0;
        dequeue(q,i);
        if ((uint32_t)mask&requested(event)) enqueue(q,i);
        return ready_signal(q);
    }
    if (i) return -EEXIST;
    if (!provider.ops || !provider.ops->poll) return -EPERM;
    int cold=q->events<0;
    i=calloc(1,sizeof(*i));
    if (!i) return -ENOMEM;
    i->wake=i->lifetime=-1; i->fd=fd; i->event=*event;
    i->identity=md_fd_weak_observe(identity); i->provider=provider;
    if (!i->identity) { int error=-errno; free(i); return error; }
    i->next=q->first; if (q->first) q->first->previous=i; q->first=i;
    int descriptor=-1;
    int error=provider.ops->poll_descriptor ? provider.ops->poll_descriptor(provider.context,&descriptor) : 0;
    if (!error && descriptor>=0) {
        i->wake=fcntl(descriptor,F_DUPFD_CLOEXEC,3);
        if (i->wake<0) error=-errno;
    }
    if (!error) {
        i->lifetime=fcntl(md_fd_weak_descriptor(i->identity),F_DUPFD_CLOEXEC,3);
        if (i->lifetime<0) error=-errno;
    }
    if (!error) error=transport_open(q);
    if (!error) {
        struct epoll_event expiry={.events=EPOLLIN|EPOLLET,.data.ptr=i};
        if (epoll_ctl(q->events,EPOLL_CTL_ADD,i->lifetime,&expiry)) error=-errno;
        else i->lifetime_armed=1;
    }
    if (!error) error=arm(q,i);
    long mask=error ? error : provider.ops->poll(provider.context);
    if (mask<0) {
        discard(q,i);
        if (cold) transport_close(q);
        return (int)mask;
    }
    if ((uint32_t)mask&requested(event)) enqueue(q,i);
    error=ready_signal(q);
    if (error) { discard(q,i); if (cold) transport_close(q); }
    return error;
}
int md_control_epoll_collect(struct md_control_epoll *q,struct epoll_event *out,int capacity) {
    if (!q || capacity<=0) return -EINVAL;
    if (!out) return -EFAULT;
    if (q->events<0) return 0;
    int observed=harvest(q);
    if (observed) return observed;
    /* A bounded ready-list turn prevents level-ready entries from appearing
     * twice in one result and preserves fair rotation across small buffers. */
    unsigned turn=q->pending;
    int delivered=0,error=0;
    while (turn-- && q->head && delivered<capacity) {
        struct interest *i=q->head;
        dequeue(q,i);
        struct md_fd_object *owner=md_fd_weak_lock(i->identity);
        if (!owner) { discard(q,i); continue; }
        long mask=i->provider.ops->poll(i->provider.context);
        md_fd_object_release(owner);
        if (mask<0) { enqueue(q,i); error=(int)mask; break; }
        uint32_t events=(uint32_t)mask&requested(&i->event);
        if (!events) continue;
        if (i->event.events&EPOLLONESHOT) {
            error=disarm(q,i);
            if (error) { enqueue(q,i); break; }
            i->disabled=1;
        } else if (!(i->event.events&EPOLLET)) enqueue(q,i);
        out[delivered++]=(struct epoll_event){.events=events,.data=i->event.data};
    }
    int signal_error=ready_signal(q);
    return delivered ? delivered : error ? error : signal_error;
}
