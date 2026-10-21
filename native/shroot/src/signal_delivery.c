#define _GNU_SOURCE
#include "signal_delivery.h"
#include "signal_protocol.h"
#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/ptrace.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

struct md_signal_delivery_node {
    struct md_signal_delivery_node *next;
    siginfo_t info;
};
int md_signal_delivery_hold(struct md_signal_delivery *q,const siginfo_t *info) {
    if ((info->si_code>0 && info->si_code!=SI_KERNEL) || info->si_signo<=0 || info->si_signo>=SIGRTMIN
            || info->si_signo==SIGKILL || info->si_signo==SIGSTOP) return -EINVAL;
    if (info->si_code==SI_KERNEL && (info->si_signo==SIGTRAP || info->si_signo==SIGILL
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
static int registers(pid_t tid,int request,struct user_pt_regs *regs) {
    struct iovec io={regs,sizeof(*regs)};
    return ptrace(request,tid,(void *)NT_PRSTATUS,&io)<0 ? -errno : 0;
}
static int step(struct md_signal_delivery *q,pid_t tid) {
    struct user_pt_regs regs=q->registers;
    regs.pc=q->gate;
    return registers(tid,PTRACE_SETREGSET,&regs);
}
int md_signal_delivery_publish(struct md_signal_delivery *q,pid_t tid,uintptr_t gate) {
    if (q->active || q->preparing || !q->first) return 0;
    if (!gate || (gate&3)) return -EINVAL;
    int error=registers(tid,PTRACE_GETREGSET,&q->registers);
    if (error) return error;
    if (ptrace(PTRACE_GETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
    struct ptrace_syscall_info call={0};
    if (ptrace(PTRACE_GET_SYSCALL_INFO,tid,(void *)sizeof(call),&call)<0) return -errno;
    q->syscall_boundary=call.op!=PTRACE_SYSCALL_INFO_NONE;
    /* arm64 forces debug exceptions: keep TRAP unblocked until the owned
     * stop, otherwise the kernel can reset the application's disposition. */
    uint64_t mask=md_signal_protocol_mask();
    if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(mask),&mask)<0) return -errno;
    q->gate=gate;
    if (call.op==PTRACE_SYSCALL_INFO_ENTRY || call.op==PTRACE_SYSCALL_INFO_SECCOMP) {
        int number=-1;
        struct iovec span={&number,sizeof(number)};
        if (ptrace(PTRACE_SETREGSET,tid,(void *)NT_ARM_SYSTEM_CALL,&span)<0) return -errno;
        q->registers.pc-=4;
        q->preparing=1; return 0;
    }
    error=step(q,tid);
    if (error) {
        if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
        return error;
    }
    q->active=1; return 0;
}
static siginfo_t take(struct md_signal_delivery *q,struct md_signal_delivery_node **at,
        struct md_signal_delivery_node *previous) {
    struct md_signal_delivery_node *n=*at;
    siginfo_t info=n->info; *at=n->next;
    if (q->last==n) q->last=previous;
    free(n); return info;
}
int md_signal_delivery_event(struct md_signal_delivery *q,pid_t tid,int signal,int *deliver) {
    if (q->preparing && signal==(SIGTRAP|0x80)) {
        struct ptrace_syscall_info call={0};
        if (ptrace(PTRACE_GET_SYSCALL_INFO,tid,(void *)sizeof(call),&call)<0) return -errno;
        if (call.op!=PTRACE_SYSCALL_INFO_EXIT) return -EPROTO;
        int error=step(q,tid);
        if (error) return error;
        q->preparing=0; q->active=1; q->syscall_boundary=1;
        *deliver=0; return 1;
    }
    if (q->preparing && signal==SIGTRAP) {
        siginfo_t info;
        if (ptrace(PTRACE_GETSIGINFO,tid,NULL,&info)<0) return -errno;
        if (info.si_code>0) return 0;
        int error=md_signal_delivery_hold(q,&info);
        if (error) return error;
        *deliver=0; return 1;
    }
    if (!q->active || signal!=SIGTRAP) return 0;
    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO,tid,NULL,&info)<0) return -errno;
    struct user_pt_regs regs;
    int error=registers(tid,PTRACE_GETREGSET,&regs);
    if (error) return error;
    /* arm64 can report a syscall-return single-step boundary before executing
     * our NOP. Its kernel-only siginfo is not an application SIGTRAP. */
    int boundary=q->syscall_boundary;
    q->syscall_boundary=0;
    if (boundary && info.si_code==SI_USER && !info.si_pid && !info.si_uid && regs.pc==q->gate) {
        *deliver=0; return 1;
    }
    if (info.si_code<=0) {
        int error=md_signal_delivery_hold(q,&info);
        if (error) return error;
        error=step(q,tid);
        if (error) return error;
        *deliver=0; return 1;
    }
    if (info.si_code!=TRAP_TRACE) return 0;
    if (regs.pc!=q->gate+4) return -EPROTO;
    struct md_signal_delivery_node **at=&q->first,*previous=NULL;
    while (*at && (*at)->info.si_signo==SIGTRAP) { previous=*at; at=&(*at)->next; }
    if (*at) {
        /* The substituted signal is blocked, so ptrace_signal requeues its
         * exact siginfo. Only our NOP runs before the next owned step stop. */
        error=step(q,tid);
        if (error) return error;
        info=take(q,at,previous);
        if (ptrace(PTRACE_SETSIGINFO,tid,NULL,&info)<0) return -errno;
        *deliver=info.si_signo; return 1;
    }
    error=registers(tid,PTRACE_SETREGSET,&q->registers);
    if (error) return error;
    if (ptrace(PTRACE_SETSIGMASK,tid,(void *)sizeof(q->mask),&q->mask)<0) return -errno;
    q->active=0; *deliver=0;
    /* Application TRAP is delivered last under its original mask, registers
     * and disposition. No synthetic application signal was queued. */
    if (q->first) {
        info=take(q,&q->first,NULL);
        if (ptrace(PTRACE_SETSIGINFO,tid,NULL,&info)<0) return -errno;
        *deliver=info.si_signo;
    }
    return 1;
}
void md_signal_delivery_clear(struct md_signal_delivery *q) {
    while (q->first) {
        struct md_signal_delivery_node *n=q->first; q->first=n->next; free(n);
    }
    *q=(struct md_signal_delivery){0};
}
