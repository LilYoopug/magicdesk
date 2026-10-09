#define _GNU_SOURCE
#include "task_quiesce.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

struct participant {
    struct participant *next;
    pid_t pid;
    int stopped, resume, interrupted, synthetic;
};
struct deferred {
    struct deferred *next;
    pid_t pid;
    int status;
    struct rusage usage;
};
struct md_task_quiesce {
    struct participant *participants;
    struct deferred *first, *last;
    long (*trace)(int,pid_t,void *,void *);
};
struct md_task_quiesce *md_task_quiesce_new(long (*trace)(int,pid_t,void *,void *)) {
    struct md_task_quiesce *q=calloc(1,sizeof(*q));
    if (q) q->trace=trace;
    return q;
}
void md_task_quiesce_destroy(struct md_task_quiesce *q) {
    if (!q) return;
    while (q->participants) { struct participant *p=q->participants; q->participants=p->next; free(p); }
    while (q->first) { struct deferred *d=q->first; q->first=d->next; free(d); }
    free(q);
}
static struct participant *find(struct md_task_quiesce *q,pid_t pid) {
    for (struct participant *p=q->participants;p;p=p->next) if (p->pid==pid) return p;
    return NULL;
}
int md_task_quiesce_add(struct md_task_quiesce *q,pid_t pid,int stopped,int request) {
    struct participant *p=find(q,pid);
    if (!p) {
        p=calloc(1,sizeof(*p)); if (!p) return -ENOMEM;
        *p=(struct participant){.next=q->participants,.pid=pid}; q->participants=p;
    }
    /* Helper ownership overrides the outer thread's saved continuation. */
    p->stopped=stopped; p->resume=request;
    for (struct deferred *d=q->first;d;d=d->next) if (d->pid==pid) p->stopped=1;
    return 0;
}
int md_task_quiesce_stop(struct md_task_quiesce *q) {
    for (struct deferred *d=q->first;d;d=d->next)
        if (!find(q,d->pid)) { int e=md_task_quiesce_add(q,d->pid,1,0); if (e) return e; }
    for (struct participant *p=q->participants;p;p=p->next) if (!p->stopped && p->resume) {
        if (q->trace(PTRACE_INTERRUPT,p->pid,NULL,NULL)<0 && errno!=ESRCH) return -errno;
        p->interrupted=1;
    }
    return 0;
}
int md_task_quiesce_ready(const struct md_task_quiesce *q) {
    for (const struct participant *p=q->participants;p;p=p->next) if (!p->stopped) return 0;
    return 1;
}
void md_task_quiesce_describe(const struct md_task_quiesce *q,int fd) {
    for (const struct participant *p=q->participants;p;p=p->next) if (!p->stopped)
        dprintf(fd,"guest-runtime: memory writer pid=%d resume=%d interrupted=%d\n",
            p->pid,p->resume,p->interrupted);
}
int md_task_quiesce_event(struct md_task_quiesce *q,pid_t pid,int status,const struct rusage *usage) {
    struct participant *p=find(q,pid);
    if (!p) { int e=md_task_quiesce_add(q,pid,0,0); if (e) return e; p=find(q,pid); }
    unsigned event=(unsigned)status>>16;
    if (!p->stopped && p->interrupted && event==PTRACE_EVENT_STOP && WSTOPSIG(status)==SIGTRAP) {
        p->stopped=p->synthetic=1; return 0;
    }
    p->stopped=1; p->synthetic=0;
    struct deferred *d=calloc(1,sizeof(*d)); if (!d) return -ENOMEM;
    *d=(struct deferred){.pid=pid,.status=status}; if (usage) d->usage=*usage;
    if (q->last) q->last->next=d; else q->first=d; q->last=d;
    if (event==PTRACE_EVENT_CLONE || event==PTRACE_EVENT_FORK || event==PTRACE_EVENT_VFORK) {
        unsigned long child;
        if (q->trace(PTRACE_GETEVENTMSG,pid,NULL,&child)<0) return -errno;
        /* Birth already stops the child; wait for its own stop, in either order. */
        if (!find(q,(pid_t)child)) return md_task_quiesce_add(q,(pid_t)child,0,0);
    }
    return 0;
}
int md_task_quiesce_release(struct md_task_quiesce *q) {
    int error=0;
    while (q->participants) {
        struct participant *p=q->participants; q->participants=p->next;
        if (p->synthetic && p->resume && q->trace(p->resume,p->pid,NULL,NULL)<0 && errno!=ESRCH) error=-errno;
        free(p);
    }
    return error;
}
pid_t md_task_quiesce_take(struct md_task_quiesce *q,int *status,struct rusage *usage) {
    if (!q || !q->first) return 0;
    struct deferred *d=q->first; q->first=d->next; if (!q->first) q->last=NULL;
    pid_t pid=d->pid; *status=d->status; if (usage) *usage=d->usage; free(d); return pid;
}
int md_task_quiesce_newborn(struct md_task_quiesce *q,pid_t pid) {
    if (!q) return 0;
    struct deferred **at=&q->first,*previous=NULL;
    while (*at && (*at)->pid!=pid) { previous=*at; at=&(*at)->next; }
    if (!*at) return 0;
    struct deferred *d=*at;
    if ((unsigned)d->status>>16!=PTRACE_EVENT_STOP || WSTOPSIG(d->status)!=SIGTRAP) return -EPROTO;
    *at=d->next; if (q->last==d) q->last=previous; free(d); return 1;
}
