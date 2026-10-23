#define _GNU_SOURCE
#include "signal_delivery.h"
#include "signal_protocol.h"
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

struct md_signal_delivery_node {
    struct md_signal_delivery_node *next;
    siginfo_t info;
};
static struct md_signal_delivery_node **realtime_first(struct md_signal_delivery *q,int signal) {
    struct md_signal_delivery_node **at=&q->realtime;
    while (*at && (*at)->info.si_signo!=signal) at=&(*at)->next;
    return at;
}
static int realtime_hold(struct md_signal_delivery *q,const siginfo_t *info,int front) {
    struct md_signal_delivery_node **at=realtime_first(q,info->si_signo);
    struct md_signal_delivery_node *node=malloc(sizeof(*node));
    if (!node) return -ENOMEM;
    if (!front) while (*at) at=&(*at)->next;
    *node=(struct md_signal_delivery_node){.next=*at,.info=*info}; *at=node;
    return 0;
}
static int realtime_publish(struct md_signal_delivery *q,pid_t tid,pid_t group) {
    /* A non-leader exec moves this queue to the surviving task owner. */
    if (!q->carrier_cookie) q->carrier_cookie=(uintptr_t)q;
    unsigned counts[NSIG]={0};
    for (struct md_signal_delivery_node *n=q->realtime;n;n=n->next) ++counts[n->info.si_signo];
    for (int n=SIGRTMIN;n<NSIG;++n) while (q->carriers[n]<counts[n]) {
        siginfo_t info={.si_signo=n,.si_code=SI_QUEUE};
        info.si_pid=getpid(); info.si_uid=getuid(); info.si_value.sival_ptr=(void *)q->carrier_cookie;
        if (syscall(SYS_rt_tgsigqueueinfo,group,tid,n,&info)<0) return -errno;
        ++q->carriers[n];
    }
    return 0;
}
static int realtime_event(struct md_signal_delivery *q,pid_t tid,int signal,int *deliver) {
    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO,tid,NULL,&info)<0) return -errno;
    int carrier=info.si_code==SI_QUEUE && info.si_pid==getpid()
        && (uintptr_t)info.si_value.sival_ptr==q->carrier_cookie && q->carriers[signal];
    struct md_signal_delivery_node **at=realtime_first(q,signal);
    if (carrier) --q->carriers[signal];
    if (*at) {
        if (!carrier) { int error=realtime_hold(q,&info,0); if (error) return error; }
        struct md_signal_delivery_node *node=*at;
        info=node->info; *at=node->next; free(node);
        if (ptrace(PTRACE_SETSIGINFO,tid,NULL,&info)<0) return -errno;
        return MD_SIGNAL_RESTORED;
    } else if (carrier) { *deliver=0; return MD_SIGNAL_CARRIER; }
    return MD_SIGNAL_NEW;
}
static int job_control(int signal) {
    return signal==SIGCONT || signal==SIGTSTP || signal==SIGTTIN || signal==SIGTTOU;
}
int md_signal_delivery_hold(struct md_signal_delivery *q,const siginfo_t *info) {
    if (info->si_signo<=0 || info->si_signo>=SIGRTMIN
            || info->si_signo==SIGKILL || info->si_signo==SIGSTOP || job_control(info->si_signo)) return -EINVAL;
    if (info->si_code>0 && (info->si_signo==SIGTRAP || info->si_signo==SIGILL
            || info->si_signo==SIGBUS || info->si_signo==SIGSEGV || info->si_signo==SIGFPE
            || info->si_signo==SIGSYS)) return -EINVAL;
    for (struct md_signal_delivery_node *n=q->first;n;n=n->next)
        if (n->info.si_signo==info->si_signo) return 0;
    struct md_signal_delivery_node *n=malloc(sizeof(*n));
    if (!n) return -ENOMEM;
    *n=(struct md_signal_delivery_node){.info=*info};
    if (q->last) q->last->next=n; else q->first=n;
    q->last=n; return 0;
}
int md_signal_delivery_retain(struct md_signal_delivery *q,pid_t tid,const siginfo_t *info) {
    if (info->si_signo>=SIGRTMIN && info->si_signo<NSIG) return realtime_hold(q,info,1);
    if (!job_control(info->si_signo)) return md_signal_delivery_hold(q,info);
    uint64_t mask;
    if (ptrace(PTRACE_GETSIGMASK,tid,(void *)sizeof(mask),&mask)<0) return -errno;
    uint64_t signal=UINT64_C(1)<<(info->si_signo-1);
    if (!(mask&signal)) {
        mask|=signal;
        if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(mask),&mask)<0) return -errno;
        q->kernel_mask|=signal;
    }
    /* Resume this real delivery stop with the same blocked signal. ptrace
     * requeues it without repeating generation-time STOP/CONT side effects;
     * a later opposite signal can then discard it in the kernel normally. */
    return info->si_signo;
}
static int arm(struct md_signal_delivery *q,pid_t tid) {
    int signal=q->first->info.si_signo;
    uint64_t mask=md_signal_blockable_mask() & ~(UINT64_C(1)<<(signal-1));
    if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(mask),&mask)<0) return -errno;
    return syscall(SYS_tkill,tid,signal)<0 ? -errno : 0;
}
int md_signal_delivery_publish(struct md_signal_delivery *q,pid_t tid,pid_t group) {
    if (q->active || !md_signal_delivery_pending(q)) return 0;
    if (q->realtime) { int error=realtime_publish(q,tid,group); if (error) return error; }
    if (!q->first && !q->kernel_mask) return 0;
    if (ptrace(PTRACE_GETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
    q->mask&=~q->kernel_mask;
    if (!q->first) {
        if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
        q->kernel_mask=0; return 0;
    }
    int error=arm(q,tid);
    if (error) {
        if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
        return error;
    }
    q->kernel_mask=0; q->active=1; return 0;
}
int md_signal_delivery_event(struct md_signal_delivery *q,pid_t tid,int signal,int *deliver) {
    if (signal>=SIGRTMIN && signal<NSIG && (q->realtime || q->carriers[signal]))
        return realtime_event(q,tid,signal,deliver);
    if (!q->active || signal!=q->first->info.si_signo) return MD_SIGNAL_NEW;
    siginfo_t observed;
    if (ptrace(PTRACE_GETSIGINFO,tid,NULL,&observed)<0) return -errno;
    if (observed.si_code>0) return MD_SIGNAL_NEW;
    struct md_signal_delivery_node *n=q->first;
    if (ptrace(PTRACE_SETSIGINFO,tid,NULL,&n->info)<0) return -errno;
    *deliver=signal;
    q->first=n->next; if (!q->first) q->last=NULL;
    free(n);
    if (q->first) {
        /* Requeue this blocked signal and select the next inside the same
         * kernel get_signal invocation. Do not execute a userspace checkpoint:
         * it would discard the pending SA_RESTART decision. */
        int error=arm(q,tid);
        return error ? error : MD_SIGNAL_CARRIER;
    }
    if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
    /* This is now the original delivery stop. Keep debugger admission and
     * recipient-namespace translation in the ordinary signal path. */
    q->active=0; return MD_SIGNAL_RESTORED;
}
void md_signal_delivery_clear(struct md_signal_delivery *q) {
    while (q->first) {
        struct md_signal_delivery_node *n=q->first; q->first=n->next; free(n);
    }
    while (q->realtime) {
        struct md_signal_delivery_node *n=q->realtime; q->realtime=n->next; free(n);
    }
    *q=(struct md_signal_delivery){0};
}
