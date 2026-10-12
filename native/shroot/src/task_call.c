#define _GNU_SOURCE
#include "task_call.h"
#include "interception.h"
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

enum { SKIPPING=1, CALLING, REENTERING, RESTORING, EXIT_REENTERING, EXIT_SKIPPING, COMPLETE };
_Static_assert((int)MD_TASK_CALL_USER==PTRACE_SYSCALL_INFO_NONE
    && (int)MD_TASK_CALL_ENTRY==PTRACE_SYSCALL_INFO_ENTRY
    && (int)MD_TASK_CALL_EXIT==PTRACE_SYSCALL_INFO_EXIT
    && (int)MD_TASK_CALL_SECCOMP==PTRACE_SYSCALL_INFO_SECCOMP,"ptrace boundary values");
static int trace(struct md_task_call *f,int request,void *address,void *data) {
    return f->trace(request,f->actor,address,data)<0 ? -errno : 0;
}
static int regs(struct md_task_call *f,int request,struct user_pt_regs *r) {
    struct iovec span={r,sizeof(*r)};
    return trace(f,request,(void *)NT_PRSTATUS,&span);
}
static int info(struct md_task_call *f,struct ptrace_syscall_info *out) {
    memset(out,0,sizeof(*out));
    return trace(f,PTRACE_GET_SYSCALL_INFO,(void *)sizeof(*out),out);
}
static int number(struct md_task_call *f,int value) {
    struct iovec span={&value,sizeof(value)};
    return trace(f,PTRACE_SETREGSET,(void *)NT_ARM_SYSTEM_CALL,&span);
}
static int invoke(struct md_task_call *f) {
    struct user_pt_regs call={.pc=f->call,.sp=f->saved.sp};
    call.regs[8]=f->arguments.number;
    memcpy(call.regs,f->arguments.value,sizeof(f->arguments.value));
    int error=regs(f,PTRACE_SETREGSET,&call);
    if (!error) { f->stage=CALLING; error=trace(f,PTRACE_CONT,NULL,NULL); }
    return error;
}
int md_task_call_begin(struct md_task_call *f,long (*operation)(int,pid_t,void *,void *),
        pid_t actor,enum md_task_call_boundary boundary,const struct user_pt_regs *resume,
        uintptr_t call,uintptr_t returned,const struct md_task_call_arguments *arguments) {
    if (!f || !operation || actor<=0 || !resume || !arguments || !call
            || returned!=call+4 || boundary<MD_TASK_CALL_USER || boundary>MD_TASK_CALL_SECCOMP) return -EINVAL;
    if (f->stage) return -EBUSY;
    *f=(struct md_task_call){.trace=operation,.actor=actor,.boundary=boundary,
        .saved=*resume,.call=call,.returned=returned,.arguments=*arguments};
    struct ptrace_syscall_info observed;
    int error=info(f,&observed);
    if (!error && (unsigned)boundary!=observed.op) error=-EINVAL;
    if (!error && (boundary==MD_TASK_CALL_ENTRY || boundary==MD_TASK_CALL_SECCOMP)
            && (resume->pc<4 || observed.instruction_pointer!=resume->pc)) error=-EINVAL;
    if (!error && boundary==MD_TASK_CALL_EXIT) {
        long value=(long)resume->regs[0];
        /* orig_x0 is kernel-private at a restart exit. Do not replace its
         * continuation with guessed arguments; let that exit progress first. */
        if (value==-512 || value==-513 || value==-514 || value==-516) error=-EAGAIN;
        else if (resume->pc<4) error=-EINVAL;
    }
    if (!error) error=trace(f,PTRACE_GETSIGMASK,(void *)sizeof(f->mask),&f->mask);
    if (error) { *f=(struct md_task_call){0}; return error; }
    uint64_t blocked=~UINT64_C(0);
    error=trace(f,PTRACE_SETSIGMASK,(void *)sizeof(blocked),&blocked);
    if (error) { *f=(struct md_task_call){0}; return error; }
    f->stage=SKIPPING;
    if (boundary==MD_TASK_CALL_ENTRY || boundary==MD_TASK_CALL_SECCOMP) {
        error=number(f,-1);
        if (!error) error=trace(f,PTRACE_SYSCALL,NULL,NULL);
        return error;
    }
    return invoke(f);
}
static int finish(struct md_task_call *f,int restore) {
    int error=restore ? regs(f,PTRACE_SETREGSET,&f->saved) : 0;
    if (!error) error=trace(f,PTRACE_SETSIGMASK,(void *)sizeof(f->mask),&f->mask);
    if (!error) f->stage=COMPLETE;
    return error ? error : 1;
}
int md_task_call_again(struct md_task_call *f,const struct md_task_call_arguments *arguments) {
    if (!f || f->stage!=COMPLETE || !arguments) return -EINVAL;
    uint64_t blocked=~UINT64_C(0);
    int error=trace(f,PTRACE_SETSIGMASK,(void *)sizeof(blocked),&blocked);
    if (error) return error;
    f->arguments=*arguments; f->stage=SKIPPING;
    if (f->boundary==MD_TASK_CALL_ENTRY || f->boundary==MD_TASK_CALL_SECCOMP) {
        error=number(f,-1);
        if (!error) error=trace(f,PTRACE_SYSCALL,NULL,NULL);
        return error;
    }
    return invoke(f);
}
int md_task_call_event(struct md_task_call *f,int status) {
    if (!f || !f->stage || f->stage==COMPLETE) return -EINVAL;
    if (WIFEXITED(status) || WIFSIGNALED(status)) return -ESRCH;
    if (!WIFSTOPPED(status)) return -EPROTO;
    unsigned event=(unsigned)status>>16;
    int signal=WSTOPSIG(status);
    struct user_pt_regs current;
    int error=regs(f,PTRACE_GETREGSET,&current);
    if (error) return error;
    if (f->stage==SKIPPING || f->stage==REENTERING || f->stage==EXIT_REENTERING || f->stage==EXIT_SKIPPING) {
        if (event || signal!=(SIGTRAP|0x80)) return -EPROTO;
        struct ptrace_syscall_info observed;
        error=info(f,&observed); if (error) return error;
        if (f->stage==SKIPPING) {
            if (observed.op!=PTRACE_SYSCALL_INFO_EXIT) return -EPROTO;
            return invoke(f);
        }
        if (f->stage==EXIT_SKIPPING) {
            if (observed.op!=PTRACE_SYSCALL_INFO_EXIT) return -EPROTO;
            error=number(f,(int)f->saved.regs[8]);
            return error ? error : finish(f,1);
        }
        if (observed.op!=PTRACE_SYSCALL_INFO_ENTRY || observed.entry.nr!=f->saved.regs[8]
                || current.pc!=f->saved.pc
                || memcmp(observed.entry.args,f->saved.regs,sizeof(observed.entry.args))) return -EPROTO;
        if (f->stage==EXIT_REENTERING) {
            error=number(f,-1); if (error) return error;
            f->stage=EXIT_SKIPPING;
            return trace(f,PTRACE_SYSCALL,NULL,NULL);
        }
        if (f->boundary==MD_TASK_CALL_ENTRY) return finish(f,0);
        f->stage=RESTORING;
        return trace(f,PTRACE_CONT,NULL,NULL);
    }
    if (event==PTRACE_EVENT_SECCOMP) {
        unsigned long cookie;
        error=trace(f,PTRACE_GETEVENTMSG,NULL,&cookie); if (error) return error;
        if (f->stage==RESTORING) {
            if (current.pc!=f->saved.pc || current.regs[8]!=f->saved.regs[8]
                    || memcmp(current.regs,f->saved.regs,6*sizeof(current.regs[0]))) return -EPROTO;
            f->cookie=cookie; return finish(f,0);
        }
        if (f->stage!=CALLING || cookie!=MD_INTERCEPT_TASK || current.pc!=f->returned
                || current.regs[8]!=(unsigned long)f->arguments.number
                || memcmp(current.regs,f->arguments.value,sizeof(f->arguments.value))) return -EPROTO;
        return trace(f,PTRACE_CONT,NULL,NULL);
    }
    if (f->stage!=CALLING || event || signal!=SIGTRAP || current.pc!=f->returned) return -EPROTO;
    f->result=(long)current.regs[0];
    if (f->boundary==MD_TASK_CALL_USER) return finish(f,1);
    struct user_pt_regs replay=f->saved; replay.pc-=4;
    error=regs(f,PTRACE_SETREGSET,&replay); if (error) return error;
    f->stage=f->boundary==MD_TASK_CALL_EXIT ? EXIT_REENTERING : REENTERING;
    return trace(f,PTRACE_SYSCALL,NULL,NULL);
}
