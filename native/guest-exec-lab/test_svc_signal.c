#define _GNU_SOURCE
#include "svc_signal.h"
#include "svc_payload.h"
#include "svc_patch.h"
#include <assert.h>
#include <elf.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

extern uint32_t prefix_original[],prefix_call[],prefix_return[],signal_step[];
__asm__(".text\n.balign 4\n.global prefix_original,prefix_call,prefix_return,signal_step\n"
    "prefix_original:\nldr x5,[x9]\nmov x8,#172\nsvc #0\nret\n"
    "prefix_call:\nbl prefix_original\nprefix_return:\nbl prefix_finished\nbrk #0\n"
    "signal_step:\nnop\nbrk #0\n");
static void *bad;
static uint64_t good=42;
static volatile sig_atomic_t faults,signals;
static unsigned asynchronous;

static void received(int number,siginfo_t *info,void *context) {
    ucontext_t *u=context;
    if (number!=SIGUSR1 || info->si_pid!=getppid() || info->si_code!=SI_TKILL
            || (u->uc_mcontext.sp>=MD_SVC_POOL_BASE && u->uc_mcontext.sp<MD_SVC_PAYLOAD_STATE)) _exit(80);
    ++signals;
}
static void fault(int number,siginfo_t *info,void *context) {
    ucontext_t *u=context;
    if (number!=SIGSEGV || info->si_addr!=bad || u->uc_mcontext.pc!=(uintptr_t)prefix_original
            || u->uc_mcontext.regs[5]!=0x5678 || u->uc_mcontext.regs[30]!=(uintptr_t)prefix_return
            || !sigismember(&u->uc_sigmask,SIGTRAP) || sigismember(&u->uc_sigmask,SIGUSR1)) _exit(81);
    ++faults; u->uc_mcontext.regs[9]=(uintptr_t)&good;
    assert(!raise(SIGSTOP));
}
static void unexpected(int number) { (void)number; _exit(82); }
__attribute__((noreturn)) void prefix_finished(void) {
    assert(faults==1 && signals==(sig_atomic_t)asynchronous);
    for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i)
        assert(!*(uint64_t *)(MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE));
    sigset_t mask; assert(!sigprocmask(SIG_SETMASK,NULL,&mask));
    assert(sigismember(&mask,SIGTRAP) && !sigismember(&mask,SIGUSR1));
    struct sigaction action; assert(!sigaction(SIGTRAP,NULL,&action) && action.sa_handler==unexpected);
    _exit(0);
}
static int stopped(pid_t pid,int number) {
    int status; assert(waitpid(pid,&status,0)==pid && WIFSTOPPED(status) && WSTOPSIG(status)==number);
    return status;
}
static void regs(pid_t pid,int request,struct user_pt_regs *value) {
    struct iovec io={value,sizeof(*value)};
    assert(!ptrace(request,pid,(void *)NT_PRSTATUS,&io));
}
int main(void) {
    alarm(15); assert(!setenv("MD_SVC_SIGNAL_PROOF","1",1));
    size_t page=(size_t)sysconf(_SC_PAGESIZE),size=MD_SVC_PAYLOAD_STATE-MD_SVC_POOL_BASE+MD_SVC_PAYLOAD_SIZE;
    assert(mmap((void *)MD_SVC_POOL_BASE,size,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void *)MD_SVC_POOL_BASE);
    bad=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(bad!=MAP_FAILED);
    uintptr_t hint=((uintptr_t)main+0x2000000)&~(page-1);
    void *code=mmap((void *)hint,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(code!=MAP_FAILED);
    struct md_svc_payload_state *state=(void *)MD_SVC_PAYLOAD_STATE;
    struct md_svc_signal_window *w=&state->window;
    uint32_t replacement;
    assert(!md_svc_edge_plan((uintptr_t)prefix_call,*prefix_call,(uintptr_t)prefix_original,
        prefix_original,3,(uintptr_t)code,(uintptr_t)unexpected,MD_SVC_POOL_BASE,code,page,&replacement,&w->edge));
    w->magic=MD_SVC_SIGNAL_MAGIC; w->begin=(uintptr_t)code; w->end=w->begin+md_svc_edge_size();
    __builtin___clear_cache(code,(char *)code+page); assert(!mprotect(code,page,PROT_READ|PROT_EXEC));
    for (asynchronous=0;asynchronous<2;++asynchronous) {
        pid_t pid=fork(); assert(pid>=0);
        if (!pid) {
            struct sigaction action={.sa_sigaction=fault,.sa_flags=SA_SIGINFO};
            sigemptyset(&action.sa_mask); assert(!sigaction(SIGSEGV,&action,NULL));
            action.sa_sigaction=received; assert(!sigaction(SIGUSR1,&action,NULL));
            action.sa_handler=unexpected; action.sa_flags=0; assert(!sigaction(SIGTRAP,&action,NULL));
            sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGTRAP);
            assert(!sigprocmask(SIG_SETMASK,&mask,NULL));
            assert(!ptrace(PTRACE_TRACEME,0,NULL,NULL) && !raise(SIGSTOP)); _exit(83);
        }
        stopped(pid,SIGSTOP);
        uint64_t original_mask;
        assert(!ptrace(PTRACE_GETSIGMASK,pid,(void *)sizeof(original_mask),&original_mask));
        assert((original_mask&(UINT64_C(1)<<(SIGTRAP-1)))
            && !(original_mask&(UINT64_C(1)<<(SIGUSR1-1))));
        struct user_hwdebug_state debug,before;
        struct iovec io={&before,sizeof(before)};
        assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_ARM_HW_BREAK,&io));
        unsigned count=before.dbg_info&255;
        assert(count>=4 && count<=16);
        /* A kernel SET/GET round trip canonicalizes unused control words.
         * Retain a real unrelated breakpoint too, not merely empty slots. */
        before.dbg_regs[count-1].addr=(uintptr_t)prefix_call;
        before.dbg_regs[count-1].ctrl=(15u<<5)|(2u<<1)|1u;
        io.iov_len=offsetof(struct user_hwdebug_state,dbg_regs)+count*sizeof(before.dbg_regs[0]);
        assert(!ptrace(PTRACE_SETREGSET,pid,(void *)NT_ARM_HW_BREAK,&io));
        io.iov_len=sizeof(before);
        assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_ARM_HW_BREAK,&io));
        /* Inject a precise stopped boundary inside the real generated prefix;
         * the production signal owner must handle both drain and delivery. */
        struct user_pt_regs r; regs(pid,PTRACE_GETREGSET,&r);
        r.pc=w->edge.stub+w->edge.prefix_offset; r.regs[5]=0x5678;
        r.regs[9]=(uintptr_t)bad; r.regs[30]=(uintptr_t)prefix_return;
        regs(pid,PTRACE_SETREGSET,&r);
        uintptr_t slot=MD_SVC_POOL_BASE+(((r.sp^(r.sp>>16))>>8)&63)*MD_SVC_SLOT_SIZE;
        assert(!ptrace(PTRACE_POKEDATA,pid,(void *)slot,(void *)1));
        struct md_signal_delivery queue={0}; int deliver=0;
        if (asynchronous) {
            assert(!syscall(SYS_tgkill,pid,pid,SIGUSR1) && !ptrace(PTRACE_CONT,pid,NULL,NULL));
            int status=stopped(pid,SIGUSR1);
            assert(md_svc_signal_event(pid,status,&deliver,&queue)==1 && !deliver);
        } else assert(md_svc_signal_drain(pid,w,0)==1);
        assert(md_svc_signal_pending(pid));
        uint64_t effective;
        assert(!ptrace(PTRACE_GETSIGMASK,pid,(void *)sizeof(effective),&effective));
        uint64_t logical=md_svc_signal_saved_mask(pid,effective);
        assert(logical==original_mask);
        uint64_t nested=logical|(UINT64_C(1)<<(SIGUSR2-1));
        effective=md_svc_signal_mask(pid,nested);
        assert(md_svc_signal_saved_mask(pid,effective)==nested);
        effective=md_svc_signal_mask(pid,logical);
        assert((effective&(UINT64_C(1)<<(SIGUSR1-1))) && !(effective&(UINT64_C(1)<<(SIGTRAP-1))));
        assert(!ptrace(PTRACE_SETSIGMASK,pid,(void *)sizeof(effective),&effective));
        assert(!ptrace(PTRACE_CONT,pid,NULL,NULL));
        int status=stopped(pid,SIGSEGV);
        assert(md_svc_signal_event(pid,status,&deliver,&queue)==1 && deliver==SIGSEGV);
        assert(!md_svc_signal_pending(pid) && !!queue.first==!!asynchronous);
        regs(pid,PTRACE_GETREGSET,&r); assert(r.pc==(uintptr_t)prefix_original);
        io=(struct iovec){&debug,sizeof(debug)};
        assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_ARM_HW_BREAK,&io));
        assert(!memcmp(&debug,&before,io.iov_len));
        assert(!ptrace(PTRACE_CONT,pid,NULL,(void *)(intptr_t)deliver)); stopped(pid,SIGSTOP);
        assert(!md_signal_delivery_publish(&queue,pid,(uintptr_t)signal_step));
        assert(!ptrace(queue.active ? PTRACE_SINGLESTEP : PTRACE_CONT,pid,NULL,NULL));
        while (waitpid(pid,&status,0)==pid && WIFSTOPPED(status)) {
            deliver=WSTOPSIG(status);
            if (queue.active) assert(md_signal_delivery_event(&queue,pid,deliver,&deliver)==1);
            else assert(deliver==SIGUSR1);
            assert(!ptrace(queue.active ? PTRACE_SINGLESTEP : PTRACE_CONT,pid,NULL,(void *)(intptr_t)deliver));
        }
        assert(WIFEXITED(status) && !WEXITSTATUS(status) && !queue.first && !queue.active);
        md_signal_delivery_clear(&queue); md_svc_signal_forget(pid);
    }
    puts("PASS SVC prefix fault: pending drain/signal, original PC/LR/mask, edited retry, debug state and frame release");
}
