#define _GNU_SOURCE
#include "svc_lifecycle.h"
#include "svc_signal.h"
#include "svc_registry.h"
#include "task_quiesce.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

struct member { struct member *next; pid_t pid; int selected,draining; uintptr_t pc,sp; };
struct md_svc_lifecycle {
    struct md_task_quiesce *barrier;
    struct member *members;
    struct md_svc_signal_window window;
    pid_t caller,target;
    int status,stage,cancelled;
    struct rusage usage;
    struct md_svc_registry *registry;
    struct md_svc_site *publication;
};
static int intersects(uintptr_t a,uint64_t size,uintptr_t begin,uintptr_t end) {
    return size && a<end && (a>=begin || size>begin-a);
}
static int range(const struct md_svc_signal_window *w,uintptr_t a,uint64_t size) {
    return intersects(a,size,w->edge.call,w->edge.call+4)
        || intersects(a,size,w->edge.callee,w->edge.svc+4)
        || intersects(a,size,w->begin,w->end)
        || intersects(a,size,w->edge.frames,w->edge.frames+MD_SVC_POOL_SIZE+MD_SVC_PAYLOAD_SIZE);
}
int md_svc_lifecycle_overlap(const struct md_svc_signal_window *w,long nr,const uint64_t *a) {
    if (nr==SYS_mmap) return (a[3]&MAP_FIXED) && range(w,a[0],a[1]);
    if (nr==SYS_mprotect || nr==SYS_munmap || nr==SYS_madvise) return range(w,a[0],a[1]);
    if (nr==SYS_mremap) return range(w,a[0],a[1]) || ((a[3]&MREMAP_FIXED) && range(w,a[4],a[2]));
    return 0;
}
static int word(pid_t pid,uintptr_t at,uint64_t *out) {
    errno=0; *out=(unsigned long)ptrace(PTRACE_PEEKTEXT,pid,(void *)at,NULL);
    return errno ? -errno : 0;
}
int md_svc_lifecycle_patched(pid_t pid,const struct md_svc_signal_window *w) {
    uint64_t value; int error=word(pid,w->edge.call&~(uintptr_t)7,&value);
    if (error==-EIO || error==-EFAULT) return 0;
    if (error) return error;
    return (uint32_t)(value>>((w->edge.call&7)*8))==w->replacement;
}
struct md_svc_lifecycle *md_svc_lifecycle_new(pid_t caller,pid_t target,int status,
        const struct rusage *usage,const struct md_svc_signal_window *window,
        long (*trace)(int,pid_t,void *,void *)) {
    struct md_svc_lifecycle *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    p->barrier=md_task_quiesce_new(trace);
    if (!p->barrier) { free(p); return NULL; }
    p->caller=caller; p->target=target; p->status=status; p->window=*window;
    p->stage=-1;
    if (usage) p->usage=*usage;
    return p;
}
struct md_svc_lifecycle *md_svc_lifecycle_update(pid_t caller,int status,const struct rusage *usage,
        struct md_svc_registry *registry,struct md_svc_site *site,long (*trace)(int,pid_t,void *,void *)) {
    struct md_svc_signal_window empty={0};
    struct md_svc_lifecycle *p=md_svc_lifecycle_new(caller,caller,status,usage,&empty,trace);
    if (p) { p->registry=registry; p->publication=site; }
    return p;
}
int md_svc_lifecycle_publication(const struct md_svc_lifecycle *p) { return p && p->publication; }
int md_svc_lifecycle_add(struct md_svc_lifecycle *p,pid_t pid,int stopped,int resume,int selected,
        uintptr_t pc,uintptr_t sp) {
    struct member *m=calloc(1,sizeof(*m));
    if (!m) return -ENOMEM;
    *m=(struct member){.next=p->members,.pid=pid,.selected=selected,.pc=pc,.sp=sp}; p->members=m;
    return md_task_quiesce_add(p->barrier,pid,stopped,resume);
}
int md_svc_lifecycle_starting(const struct md_svc_lifecycle *p) { return p && p->stage==-1; }
struct md_task_quiesce *md_svc_lifecycle_barrier(struct md_svc_lifecycle *p) {
    return p && !p->stage ? p->barrier : NULL;
}
int md_svc_lifecycle_stop(struct md_svc_lifecycle *p) {
    p->stage=0; return md_task_quiesce_stop(p->barrier);
}
int md_svc_lifecycle_event(struct md_svc_lifecycle *p,pid_t pid,int status,const struct rusage *usage) {
    if (p && pid==p->caller && (WIFEXITED(status) || WIFSIGNALED(status)
            || (unsigned)status>>16==PTRACE_EVENT_EXIT || (unsigned)status>>16==PTRACE_EVENT_EXEC)) p->cancelled=1;
    if (!p || p->stage || !md_task_quiesce_contains(p->barrier,pid)) return 0;
    int error=md_task_quiesce_event(p->barrier,pid,status,usage);
    return error ? error : 1;
}
int md_svc_lifecycle_progress(struct md_svc_lifecycle *p) {
    if (!p || p->stage || !md_task_quiesce_ready(p->barrier)) return 0;
    if (p->registry) {
        int error=0;
        if (p->publication) {
            error=p->cancelled ? -ESRCH : md_svc_registry_publish(p->registry,p->publication,p->target);
            if (error) p->publication->state=MD_SVC_RETIRED;
            fprintf(stderr,"SVC_PUBLISH {\"task\":%d,\"result\":%d}\n",p->target,error);
            /* Optional publication failure leaves the original instruction.
             * A failed tracer write does not commit half an instruction. */
        } else {
            for (unsigned i=0;i<p->registry->count;++i) {
                struct md_svc_site *s=&p->registry->sites[i];
                if (s->state!=MD_SVC_PUBLISHED) continue;
                int patched=md_svc_lifecycle_patched(p->target,&s->window);
                if (patched<0 && patched!=-ESRCH) return patched;
                if (patched>0) {
                    error=md_svc_registry_write(p->target,s->window.edge.call,&s->window.original,4);
                    if (error) return error;
                }
            }
            for (struct member *m=p->members;m;m=m->next) if (m->selected) {
                struct md_svc_signal_window window;
                int found=m->selected==2 ? md_svc_signal_window_at(m->pid,m->pc,m->sp,&window)
                    : md_svc_signal_window(m->pid,&window);
                if (!found) continue;
                int draining=md_svc_signal_drain(m->pid,&window,m->selected==2);
                if (draining<0) return draining;
                m->draining=draining;
            }
        }
        error=md_task_quiesce_release(p->barrier);
        if (!error) p->stage=1;
        return error;
    }
    uintptr_t at=p->window.edge.call&~(uintptr_t)7;
    uint64_t value; int error=word(p->target,at,&value);
    unsigned shift=(unsigned)(p->window.edge.call&7)*8;
    if (error && error!=-ESRCH) return error;
    if (!error && (uint32_t)(value>>shift)==p->window.replacement) {
        value=(value&~(UINT64_C(0xffffffff)<<shift))|((uint64_t)p->window.original<<shift);
        if (ptrace(PTRACE_POKETEXT,p->target,(void *)at,(void *)value)<0) return -errno;
        unsigned draining=0;
        for (struct member *m=p->members;m;m=m->next) if (m->selected) {
            int result=md_svc_signal_drain(m->pid,&p->window,m->selected==2);
            if (result<0) return result;
            m->draining=result; draining+=!!result;
        }
        fprintf(stderr,"SVC_RETIRE {\"caller\":%d,\"target\":%d,\"draining\":%u}\n",
            p->caller,p->target,draining);
    }
    /* No new entry is possible. Existing invocations finish through the normal
     * event owners; only the destructive caller remains at its original stop. */
    error=md_task_quiesce_release(p->barrier);
    if (!error) p->stage=1;
    return error;
}
pid_t md_svc_lifecycle_take(struct md_svc_lifecycle *p,int *status,struct rusage *usage) {
    if (!p || p->stage<=0) return 0;
    pid_t pid=md_task_quiesce_take(p->barrier,status,usage);
    if (pid) return pid;
    if (p->stage!=1) return 0;
    for (struct member *m=p->members;m;m=m->next)
        if (m->draining && md_svc_signal_pending(m->pid)) return 0;
    if (p->registry && !p->publication)
        for (unsigned i=0;i<p->registry->count;++i)
            if (p->registry->sites[i].state==MD_SVC_PUBLISHED) p->registry->sites[i].state=MD_SVC_RETIRED;
    if (p->cancelled) { p->stage=2; return 0; }
    *status=p->status; if (usage) *usage=p->usage; p->stage=2;
    return p->caller;
}
int md_svc_lifecycle_done(const struct md_svc_lifecycle *p) { return p && p->stage==2; }
void md_svc_lifecycle_destroy(struct md_svc_lifecycle *p) {
    if (!p) return;
    md_task_quiesce_destroy(p->barrier);
    while (p->members) { struct member *m=p->members; p->members=m->next; free(m); }
    free(p);
}
