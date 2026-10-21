#define _GNU_SOURCE
#include "task_checkpoint.h"
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#endif
enum { EMULATING=1, SKIPPED_EXIT, NATIVE_ENTRY, MARKER_INTERRUPT };
struct md_task_checkpoint {
    struct md_task_checkpoint *next;
    pid_t pid;
    int scoped,stage;
    uintptr_t marker;
};
static struct md_task_checkpoint *find(struct md_task_checkpoints *m,pid_t pid,int create) {
    struct md_task_checkpoint **bucket=&m->buckets[(unsigned)pid%MD_TASK_CHECKPOINT_BUCKETS];
    for (struct md_task_checkpoint *c=*bucket;c;c=c->next) if (c->pid==pid) return c;
    if (!create) return NULL;
    struct md_task_checkpoint *c=calloc(1,sizeof(*c));
    if (c) { c->pid=pid; c->next=*bucket; *bucket=c; ++m->count; }
    return c;
}
static int trace(struct md_task_checkpoints *m,int request,pid_t pid,void *address,void *data) {
    return m->trace(request,pid,address,data)<0 ? -errno : 0;
}
static int regs(struct md_task_checkpoints *m,pid_t pid,int request,struct user_pt_regs *r) {
    struct iovec io={r,sizeof(*r)};
    return trace(m,request,pid,(void *)NT_PRSTATUS,&io);
}
static void forget(struct md_task_checkpoints *m,pid_t pid) {
    struct md_task_checkpoint **at=&m->buckets[(unsigned)pid%MD_TASK_CHECKPOINT_BUCKETS];
    while (*at && (*at)->pid!=pid) at=&(*at)->next;
    if (*at) { struct md_task_checkpoint *c=*at; *at=c->next; free(c); --m->count; }
}
long md_task_checkpoint_trace(struct md_task_checkpoints *m,int request,pid_t pid,void *address,void *data) {
    struct md_task_checkpoint *c=NULL;
    if (request==PTRACE_SETREGSET && (uintptr_t)address==NT_PRSTATUS && data) {
        struct iovec *io=data;
        if (io->iov_len>=sizeof(struct user_pt_regs)) {
            struct user_pt_regs *r=io->iov_base;
            int scoped=m->begin && r->pc>=m->begin && r->pc<m->end;
            c=find(m,pid,scoped);
            if (scoped && !c) { errno=ENOMEM; return -1; }
            long result=m->trace(request,pid,address,data);
            if (result>=0 && c) { c->scoped=scoped; c->stage=0; }
            return result;
        }
    }
    if (request==PTRACE_CONT) {
        c=find(m,pid,0);
        if (c && (c->stage==SKIPPED_EXIT || c->stage==NATIVE_ENTRY)) request=PTRACE_SYSCALL;
        else if (c && c->stage!=MARKER_INTERRUPT && c->scoped && m->restricted(pid)) {
            request=PTRACE_SYSEMU; c->stage=EMULATING;
        }
    } else if (request==PTRACE_SYSCALL || request==PTRACE_SINGLESTEP || request==PTRACE_SYSEMU) {
        c=find(m,pid,0);
        if (c) c->stage=0;
    }
    return m->trace(request,pid,address,data);
}
static int marker(struct md_task_checkpoints *m,struct md_task_checkpoint *c,pid_t pid,
        uintptr_t pc,int emulated) {
    if (!emulated) {
        /* A TRACE checkpoint is already past filter evaluation. -1 is the
         * documented post-TRACE cancellation, not a new filtered syscall. */
        int number=-1; struct iovec io={&number,sizeof(number)};
        int error=trace(m,PTRACE_SETREGSET,pid,(void *)NT_ARM_SYSTEM_CALL,&io);
        if (error) return error;
    }
    c->marker=pc-4; c->stage=MARKER_INTERRUPT;
    int error=trace(m,PTRACE_INTERRUPT,pid,NULL,NULL);
    if (!error) error=trace(m,PTRACE_CONT,pid,NULL,NULL);
    return error ? error : 1;
}
int md_task_checkpoint_event(struct md_task_checkpoints *m,pid_t pid,int *status) {
    if (WIFEXITED(*status) || WIFSIGNALED(*status)) { forget(m,pid); return 0; }
    if (!WIFSTOPPED(*status)) return 0;
    unsigned event=(unsigned)*status>>16;
    int signal=WSTOPSIG(*status);
    struct md_task_checkpoint *c=find(m,pid,0);
    if (event==PTRACE_EVENT_EXEC) {
        forget(m,pid);
        c=find(m,pid,1); if (!c) return -ENOMEM;
        c->scoped=1;
        return 0;
    }
    if (event==PTRACE_EVENT_SECCOMP) {
        if (m->begin && (!c || !c->scoped)) return 0;
        unsigned long cookie;
        int error=trace(m,PTRACE_GETEVENTMSG,pid,NULL,&cookie);
        if (error || (cookie!=MD_INTERCEPT_CHECKPOINT && (!c || !c->scoped))) return error;
        struct user_pt_regs r;
        error=regs(m,pid,PTRACE_GETREGSET,&r); if (error) return error;
        if (cookie!=MD_INTERCEPT_CHECKPOINT && !m->marker(r.pc)) return 0;
        c=find(m,pid,1); if (!c) return -ENOMEM;
        return marker(m,c,pid,r.pc,0);
    }
    if (!c || !c->stage) return 0;
    if (c->stage==MARKER_INTERRUPT) {
        if (event!=PTRACE_EVENT_STOP || signal!=SIGTRAP) return 0;
        struct user_pt_regs r;
        int error=regs(m,pid,PTRACE_GETREGSET,&r); if (error) return error;
        if (r.pc!=c->marker+4) return -EPROTO;
        r.pc=c->marker;
        error=regs(m,pid,PTRACE_SETREGSET,&r); if (error) return error;
        c->stage=0;
        *status=(MD_TASK_CHECKPOINT_EVENT<<16)|(SIGTRAP<<8)|0x7f;
        return 0;
    }
    if (event || signal!=(SIGTRAP|0x80)) return 0;
    struct ptrace_syscall_info info={0};
    int error=trace(m,PTRACE_GET_SYSCALL_INFO,pid,(void *)sizeof(info),&info);
    if (error) return error;
    if (c->stage==SKIPPED_EXIT) {
        if (info.op!=PTRACE_SYSCALL_INFO_EXIT) return -EPROTO;
        c->stage=NATIVE_ENTRY;
        error=trace(m,PTRACE_SYSCALL,pid,NULL,NULL);
    } else if (c->stage==NATIVE_ENTRY) {
        if (info.op!=PTRACE_SYSCALL_INFO_ENTRY) return -EPROTO;
        c->stage=EMULATING;
        error=trace(m,PTRACE_SYSEMU,pid,NULL,NULL);
    } else {
        if (info.op!=PTRACE_SYSCALL_INFO_ENTRY) return -EPROTO;
        struct user_pt_regs r;
        error=regs(m,pid,PTRACE_GETREGSET,&r); if (error) return error;
        /* Exact registered sites distinguish markers from native calls, even
         * when x8 is a register-copy payload rather than a syscall number. */
        if (m->marker(r.pc)) return marker(m,c,pid,r.pc,1);
        r.pc-=4;
        error=regs(m,pid,PTRACE_SETREGSET,&r); if (error) return error;
        c->stage=SKIPPED_EXIT;
        error=trace(m,PTRACE_SYSCALL,pid,NULL,NULL);
    }
    return error ? error : 1;
}
void md_task_checkpoints_clear(struct md_task_checkpoints *m) {
    for (unsigned i=0;i<MD_TASK_CHECKPOINT_BUCKETS;++i)
        while (m->buckets[i]) forget(m,m->buckets[i]->pid);
}
