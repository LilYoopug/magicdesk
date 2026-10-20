#define _GNU_SOURCE
#include "signal_delivery.h"
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <asm/ptrace.h>
#include <unistd.h>
extern char delivery_step[];
__asm__(".text\n.balign 4\n.global delivery_step\ndelivery_step:\nnop\nbrk #0\n");

static siginfo_t original(int signal) {
    siginfo_t info={.si_signo=signal,.si_code=SI_TKILL};
    info.si_pid=12345; info.si_uid=54321;
    return info;
}
static void unexpected(int signal) { (void)signal; _exit(90); }
static uintptr_t pc(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec io={&regs,sizeof(regs)};
    assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io));
    return regs.pc;
}
static void child(unsigned round,int traced) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set,SIGUSR1); sigaddset(&set,SIGTRAP); sigaddset(&set,SIGURG);
    assert(!sigprocmask(SIG_BLOCK,&set,NULL));
    struct sigaction action={.sa_handler=unexpected};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGTRAP,&action,NULL));
    if (round>=2) {
        struct rlimit limit;
        assert(!getrlimit(RLIMIT_SIGPENDING,&limit)); limit.rlim_cur=0;
        assert(!setrlimit(RLIMIT_SIGPENDING,&limit));
    }
    if (traced) {
        assert(!ptrace(PTRACE_TRACEME,0,NULL,NULL));
        if (round==1) assert(!raise(SIGURG));
        assert(!raise(SIGSTOP));
    } else assert(!raise(SIGUSR1) && !raise(SIGTRAP));
    unsigned count=round==1 || round==3 ? 3 : 2,seen=0;
    int fd=round>=2 ? signalfd(-1,&set,SFD_CLOEXEC|SFD_NONBLOCK) : -1;
    if (round>=2) assert(fd>=0);
    for (unsigned i=0;i<count;++i) {
        int number,code; pid_t sender; uid_t uid;
        if (fd>=0) {
            struct signalfd_siginfo info;
            assert(read(fd,&info,sizeof(info))==sizeof(info));
            number=info.ssi_signo; code=info.ssi_code; sender=info.ssi_pid; uid=info.ssi_uid;
        } else {
            siginfo_t info;
            struct timespec bound={.tv_sec=1};
            assert(sigtimedwait(&set,&info,&bound)>0);
            number=info.si_signo; code=info.si_code; sender=info.si_pid; uid=info.si_uid;
        }
        if (round>=2) {
            /* Native standard-signal allocation failure also yields SI_USER
             * with zero sender; no userspace implementation can recover
             * information the kernel could not store. Keep delivery itself. */
            assert(code==SI_USER && !sender && !uid);
        } else {
            assert(code==SI_TKILL);
            if (number==SIGURG) assert(round==1 && sender==getpid() && uid==getuid());
            else assert((number==SIGUSR1 || number==SIGTRAP) && sender==12345 && uid==54321);
        }
        assert(!(seen&(1u<<number))); seen|=1u<<number;
    }
    assert((seen&((1u<<SIGTRAP)|(1u<<SIGUSR1)))==((1u<<SIGTRAP)|(1u<<SIGUSR1)));
    if (fd>=0) assert(!close(fd));
    assert(!sigaction(SIGTRAP,NULL,&action) && action.sa_handler==unexpected);
    _exit(0);
}
int main(void) {
    alarm(15);
    pid_t native=fork(); assert(native>=0);
    if (!native) child(2,0);
    int native_status;
    assert(waitpid(native,&native_status,0)==native && WIFEXITED(native_status) && !WEXITSTATUS(native_status));
    for (unsigned round=0;round<4;++round) {
        pid_t pid=fork(); assert(pid>=0);
        if (!pid) child(round,1);
        int status;
        assert(waitpid(pid,&status,0)==pid && WIFSTOPPED(status) && WSTOPSIG(status)==SIGSTOP);
        uintptr_t stopped=pc(pid);
        struct md_signal_delivery q={0};
        siginfo_t info=original(SIGUSR1);
        assert(!md_signal_delivery_hold(&q,&info));
        info.si_pid=11111; assert(!md_signal_delivery_hold(&q,&info));
        info=original(SIGTRAP); assert(!md_signal_delivery_hold(&q,&info));
        assert(!md_signal_delivery_publish(&q,pid,(uintptr_t)delivery_step));
        assert(!md_signal_delivery_publish(&q,pid,(uintptr_t)delivery_step));
        if (round==3) {
            assert(!syscall(SYS_tgkill,pid,pid,SIGURG));
            assert(!syscall(SYS_tgkill,pid,pid,SIGTRAP));
        }
        assert(!ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL));
        unsigned stops=0;
        while (waitpid(pid,&status,0)==pid && WIFSTOPPED(status)) {
            assert(q.active && ++stops<=3);
            siginfo_t observed; assert(!ptrace(PTRACE_GETSIGINFO,pid,NULL,&observed));
            if (observed.si_code>0) assert(pc(pid)==(uintptr_t)delivery_step+4);
            int deliver=0;
            assert(md_signal_delivery_event(&q,pid,WSTOPSIG(status),&deliver)==1);
            if (!q.active) assert(pc(pid)==stopped);
            assert(!ptrace(q.active ? PTRACE_SINGLESTEP : PTRACE_CONT,pid,NULL,(void *)(intptr_t)deliver));
        }
        assert(WIFEXITED(status) && !WEXITSTATUS(status) && stops==(round==3 ? 3u : 2u));
        assert(!q.first && !q.last && !q.active);
        md_signal_delivery_clear(&q);
    }
    struct md_signal_delivery q={0};
    siginfo_t info=original(SIGKILL);
    assert(md_signal_delivery_hold(&q,&info)==-EINVAL);
    info=original(SIGSTOP); assert(md_signal_delivery_hold(&q,&info)==-EINVAL);
    info=original(SIGRTMIN); assert(md_signal_delivery_hold(&q,&info)==-EINVAL);
    info=original(SIGTRAP); info.si_code=TRAP_BRKPT;
    assert(md_signal_delivery_hold(&q,&info)==-EINVAL);
    info=original(SIGUSR1); assert(!md_signal_delivery_hold(&q,&info));
    md_signal_delivery_clear(&q); assert(!q.first && !q.last && !q.active);
    puts("PASS signal delivery: exact kernel info, coalescing, sigwait/signalfd, no guest execution, exhausted queue");
}
