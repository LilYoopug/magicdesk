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
int md_signal_delivery_publish(struct md_signal_delivery *q,pid_t tid) {
    if (q->active || !md_signal_delivery_pending(q)) return 0;
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
    if (!q->active || signal!=q->first->info.si_signo) return 0;
    siginfo_t observed;
    if (ptrace(PTRACE_GETSIGINFO,tid,NULL,&observed)<0) return -errno;
    if (observed.si_code>0) return 0;
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
        return error ? error : 1;
    }
    if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
    q->active=0; return 1;
}
void md_signal_delivery_clear(struct md_signal_delivery *q) {
    while (q->first) {
        struct md_signal_delivery_node *n=q->first; q->first=n->next; free(n);
    }
    *q=(struct md_signal_delivery){0};
}
