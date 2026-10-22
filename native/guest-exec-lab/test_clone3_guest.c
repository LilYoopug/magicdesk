#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/sched.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/futex.h>
#include <stdatomic.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t expected_mask;
static void mask_unchanged(void) {
    uint64_t mask=0;
    assert(!syscall(SYS_rt_sigprocmask,SIG_SETMASK,NULL,&mask,sizeof(mask)));
    assert(mask==expected_mask);
}
static void reaped(pid_t child) {
    int status; pid_t result;
    do result=waitpid(child,&status,0); while (result<0 && errno==EINTR);
    assert(result==child && status==0);
    mask_unchanged();
}
extern long clone_stack(struct clone_args *,size_t,void (*)(void));
__asm__(".text\n.global clone_stack\n.type clone_stack,%function\nclone_stack:\n"
    "stp x19,x30,[sp,#-16]!\nmov x19,x2\nmov x8,#435\nsvc #0\n"
    "cbnz x0,1f\nblr x19\nmov x0,#0\nmov x8,#93\nsvc #0\nbrk #0\n"
    "1: ldp x19,x30,[sp],#16\nret\n.size clone_stack,.-clone_stack\n");
static atomic_int stack_child_ran;
static void on_stack(void) {
    mask_unchanged(); atomic_store_explicit(&stack_child_ran,1,memory_order_release);
}
static void stack_cases(void) {
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    for (unsigned i=0;i<2;++i) {
        struct clone_args a={.flags=CLONE_VM|(i ? CLONE_VFORK|CLONE_FILES : 0),
            .exit_signal=SIGCHLD,.stack=(uintptr_t)stack,.stack_size=65536};
        stack_child_ran=0;
        long child=clone_stack(&a,sizeof(a),on_stack);
        assert(child>0); reaped((pid_t)child); assert(stack_child_ran);
    }
    int tid=-1;
    struct clone_args thread={.flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND|CLONE_FILES
        |CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID,.parent_tid=(uintptr_t)&tid,.child_tid=(uintptr_t)&tid,
        .stack=(uintptr_t)stack,.stack_size=65536};
    stack_child_ran=0;
    long child=clone_stack(&thread,sizeof(thread),on_stack);
    assert(child>0);
    /* EVENT_WAIT: kernel clear_child_tid releases the stack after thread exit;
     * the process alarm bounds a missing wake or incorrect TID publication. */
    for (;;) {
        int value=__atomic_load_n(&tid,__ATOMIC_ACQUIRE);
        if (!value) break;
        assert(value==child);
        long result=syscall(SYS_futex,&tid,FUTEX_WAIT,value,NULL,NULL,0);
        assert(!result || (result==-1 && (errno==EAGAIN || errno==EINTR)));
    }
    assert(atomic_load_explicit(&stack_child_ran,memory_order_acquire));
    assert(!munmap(stack,65536));
}
static volatile sig_atomic_t signal_count;
static void interrupted(int signal) {
    (void)signal;
    int saved=errno;
    int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if (fd>=0) close(fd);
    ++signal_count; errno=saved;
}
static void signal_cases(void) {
    struct sigaction action={.sa_handler=interrupted},previous;
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGUSR1,&action,&previous));
    int channel[2]; assert(!pipe(channel));
    pid_t parent=getpid(),sender=fork(); assert(sender>=0);
    if (!sender) {
        close(channel[1]); char byte;
        while (read(channel[0],&byte,1)==1) assert(!kill(parent,SIGUSR1));
        close(channel[0]); _exit(0);
    }
    close(channel[0]);
    for (unsigned i=0;i<64;++i) {
        assert(write(channel[1],"x",1)==1);
        struct clone_args args={.exit_signal=SIGCHLD};
        long child=syscall(SYS_clone3,&args,sizeof(args));
        if (!child) { mask_unchanged(); _exit(0); }
        assert(child>0); reaped((pid_t)child);
    }
    close(channel[1]); reaped(sender);
    assert(signal_count && !sigaction(SIGUSR1,&previous,NULL));
}
static void denied_case(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        struct sock_fprog filter={sizeof(code)/sizeof(*code),code};
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        assert(!prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter));
        struct clone_args args={.exit_signal=SIGCHLD};
        assert(syscall(SYS_clone3,&args,sizeof(args))==-1 && errno==EPERM);
        mask_unchanged();
        _exit(0);
    }
    reaped(child);
}
static void fork_case(unsigned long flags,int protected) {
    int parent=-1,child_tid=-1,pidfd=-1;
    struct clone_args args={.flags=flags,.exit_signal=SIGCHLD,
        .parent_tid=(uintptr_t)&parent,.child_tid=(uintptr_t)&child_tid,.pidfd=(uintptr_t)&pidfd};
    struct clone_args before=args;
    if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
    long child=syscall(SYS_clone3,&args,sizeof(args));
    assert(child>=0 && !memcmp(&args,&before,sizeof(args)));
    mask_unchanged();
    if (!child) {
        pid_t self=(pid_t)syscall(SYS_getpid);
        if (flags&CLONE_NEWPID) assert(self==1);
        if (flags&CLONE_CHILD_SETTID) assert(child_tid==self);
        _exit(0);
    }
    if (flags&CLONE_PARENT_SETTID) assert(parent==child);
    if (flags&CLONE_PIDFD) {
        assert(pidfd>=0 && (fcntl(pidfd,F_GETFD)&FD_CLOEXEC));
        struct pollfd p={pidfd,POLLIN,0};
        assert(poll(&p,1,5000)==1 && (p.revents&POLLIN));
        siginfo_t info={0};
        assert(!waitid(P_PIDFD,pidfd,&info,WEXITED|WNOWAIT));
        assert(info.si_pid==child && info.si_status==0);
        assert(!close(pidfd));
    }
    reaped((pid_t)child);
    if (protected) assert(!prctl(PR_SET_DUMPABLE,1));
}
int main(int argc,char **argv) {
    alarm(60);
    sigset_t block,previous;
    sigemptyset(&block); sigaddset(&block,SIGUSR2);
    assert(!sigprocmask(SIG_BLOCK,&block,&previous));
    assert(!syscall(SYS_rt_sigprocmask,SIG_SETMASK,NULL,&expected_mask,sizeof(expected_mask)));
    int probe=argc==2 && !strcmp(argv[1],"--probe");
    int native=argc==2 && !strcmp(argv[1],"--native");
    struct clone_args args={.exit_signal=SIGCHLD};
    long child=syscall(SYS_clone3,&args,sizeof(args));
    if (!child) _exit(0);
    if (child<0) {
        int error=errno;
        printf("clone3: errno=%d (%s)\n",error,strerror(error));
        return probe ? 0 : 1;
    }
    reaped((pid_t)child);
    if (probe) { puts("PASS clone3 fork/wait"); return 0; }
    assert(syscall(SYS_clone3,&args,0)==-1 && errno==EINVAL);
    assert(syscall(SYS_clone3,(void *)1,sizeof(args))==-1 && errno==EFAULT);
    struct clone_args invalid={.flags=CLONE_SIGHAND,.exit_signal=SIGCHLD};
    assert(syscall(SYS_clone3,&invalid,sizeof(invalid))==-1 && errno==EINVAL);
    mask_unchanged();
    struct { struct clone_args args; unsigned long extra; } extended={.args=args,.extra=1};
    assert(syscall(SYS_clone3,&extended,sizeof(extended))==-1 && errno==E2BIG);
    extended.extra=0;
    child=syscall(SYS_clone3,&extended,sizeof(extended));
    if (!child) _exit(0);
    assert(child>0); reaped((pid_t)child);
    stack_cases();
    signal_cases();
    denied_case();
    for (int protected=0;protected<2;++protected) {
        fork_case(0,protected);
        fork_case(CLONE_PARENT_SETTID|CLONE_CHILD_SETTID,protected);
        fork_case(CLONE_PIDFD|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID,protected);
        if (!native) fork_case(CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET
            |CLONE_PIDFD|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID,protected);
    }
    puts("PASS clone3 fork, TIDs, pidfd, protected callers and namespace lifecycle");
    assert(!sigprocmask(SIG_SETMASK,&previous,NULL));
    return 0;
}
