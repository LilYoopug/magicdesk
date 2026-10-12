#define _GNU_SOURCE
#include "fd_filter_program.h"
#include "task_filter.h"
#include "task_quiesce.h"
#include "interception.h"
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char remote_call[],remote_return[];
extern void remote_pause(void);
extern char remote_paused[];
__asm__(".text\n.global remote_call\nremote_call:\nsvc #0\n"
    ".global remote_return\nremote_return:\nbrk #0\n"
    ".global remote_pause\nremote_pause:\n.global remote_paused\nremote_paused:\nbrk #0\nret\n");
struct shared {
    struct md_task_filter_image image;
    int waiting,completed,first_error;
    pid_t sibling;
    int signal_epoll;
    struct epoll_event signal_event;
};
static struct user_pt_regs get(pid_t pid) {
    struct user_pt_regs r; struct iovec io={&r,sizeof(r)};
    assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io)); return r;
}
static int stop(pid_t pid) {
    /* EVENT_WAIT: exact tracee stop/exit; fixture alarm bounds failure. */
    int status; pid_t got;
    do { got=waitpid(pid,&status,__WALL); } while (got<0 && errno==EINTR);
    assert(got==pid); return status;
}
static void child(int start,int reader,int ep,struct shared *shared,int denied,int reading,int protected) {
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    char byte; assert(read(start,&byte,1)==1);
    if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGUSR1);
    assert(!sigprocmask(SIG_SETMASK,&mask,NULL));
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getpgid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOKEY),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_seccomp,0,1),
        BPF_STMT(BPF_RET|BPF_K,denied>0 ? SECCOMP_RET_ERRNO|EPERM : SECCOMP_RET_TRACE|MD_INTERCEPT_TASK),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    shared->waiting=1;
    struct epoll_event event={0};
    int n=reading ? (int)read(reader,&byte,1) : epoll_wait(ep,&event,1,-1);
    shared->first_error=n<0 ? errno : 0;
    if (!reading) {
        if (n<0 && errno==EINTR) n=epoll_wait(ep,&event,1,-1);
        assert(n==1 && event.data.u64==123);
        assert(read(reader,&byte,1)==1);
    }
    assert(n==1 && byte=='q');
    assert(!sigprocmask(SIG_SETMASK,NULL,&mask) && sigismember(&mask,SIGUSR1)==1
        && sigismember(&mask,SIGUSR2)==0);
    assert(syscall(SYS_getpgid,0)==-1 && errno==ENOKEY);
    shared->completed=1; _exit(0);
}
static long trace(int request,pid_t pid,void *address,void *data) {
    return ptrace(request,pid,address,data);
}
static void install_at(pid_t pid,int fd,struct shared *shared,const struct user_pt_regs *saved,
        long expected,enum md_task_call_boundary boundary,int retry_thread) {
    struct md_fd_filter_gates gates={(uintptr_t)remote_return,0,0};
    struct md_task_filter call={0};
    assert(!md_task_filter_begin(&call,trace,pid,boundary,saved,
        (uintptr_t)remote_call,(uintptr_t)remote_return,&shared->image,(uintptr_t)&shared->image,
        MD_FD_SELECTOR_PROC,fd,&gates));
    int ready;
    do { ready=md_task_filter_event(&call,stop(pid)); } while (!ready);
    if (retry_thread) {
        assert(ready==1 && call.task.result==-EPERM && !md_task_filter_retry_thread(&call));
        do { ready=md_task_filter_event(&call,stop(pid)); } while (!ready);
    }
    assert(ready==1 && call.task.result==expected);
    struct ptrace_syscall_info info={0};
    assert(ptrace(PTRACE_GET_SYSCALL_INFO,pid,sizeof(info),&info)>0 && info.op==(unsigned)boundary);
    if (boundary==MD_TASK_CALL_EXIT) assert(info.exit.rval==(long)saved->regs[0]);
    if (boundary==MD_TASK_CALL_SECCOMP)
        assert(call.task.cookie==(expected ? 123 : MD_INTERCEPT_PROC));
}
static void install(pid_t pid,int fd,struct shared *shared,const struct user_pt_regs *saved,long expected) {
    install_at(pid,fd,shared,saved,expected,MD_TASK_CALL_USER,0);
}
static int run(int denied,int reading,int protected) {
    struct shared *shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(shared!=MAP_FAILED);
    int start[2],data[2]; assert(!pipe2(start,O_CLOEXEC) && !pipe2(data,O_CLOEXEC));
    int ep=epoll_create1(EPOLL_CLOEXEC); assert(ep>=0);
    struct epoll_event event={.events=EPOLLIN,.data.u64=123};
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,data[0],&event));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) child(start[0],data[0],ep,shared,denied,reading,protected);
    assert(!ptrace(PTRACE_SEIZE,pid,0,(void *)(PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACESECCOMP|PTRACE_O_EXITKILL)));
    assert(!ptrace(PTRACE_INTERRUPT,pid,0,0));
    assert(WIFSTOPPED(stop(pid)));
    assert(write(start[1],"s",1)==1);
    /* Observe the intended wait's entry rather than a timed settling delay. */
    for (;;) {
        assert(!ptrace(PTRACE_SYSCALL,pid,0,0));
        int status=stop(pid); assert(WIFSTOPPED(status));
        struct user_pt_regs r=get(pid);
        if (shared->waiting && r.regs[8]==(reading ? SYS_read : SYS_epoll_pwait)
                && (long)r.regs[0]==(reading ? data[0] : ep)) break;
    }
    assert(!ptrace(PTRACE_CONT,pid,0,0));
    struct md_task_quiesce *barrier=md_task_quiesce_new(trace); assert(barrier);
    assert(!md_task_quiesce_add(barrier,pid,0,PTRACE_CONT) && !md_task_quiesce_stop(barrier));
    int status=stop(pid); assert(WIFSTOPPED(status));
    assert(!md_task_quiesce_event(barrier,pid,status,NULL) && md_task_quiesce_ready(barrier));
    struct md_task_quiesce_stop boundary;
    assert(!md_task_quiesce_borrow(barrier,pid,&boundary) && boundary.kind==MD_TASK_QUIESCE_SYNTHETIC);
    struct user_pt_regs saved=get(pid);
    assert((unsigned)status>>16==PTRACE_EVENT_STOP);
    if (denied>=0) install(pid,data[0],shared,&saved,denied ? -EPERM : 0);
    assert(write(data[1],"q",1)==1);
    assert(!md_task_quiesce_return(barrier,pid) && !md_task_quiesce_release(barrier));
    assert(!md_task_quiesce_take(barrier,&status,NULL));
    md_task_quiesce_destroy(barrier);
    unsigned intercepted=0;
    for (;;) {
        status=stop(pid);
        if (WIFEXITED(status)) break;
        assert(WIFSTOPPED(status) && (unsigned)status>>16==PTRACE_EVENT_SECCOMP);
        unsigned long cookie; assert(!ptrace(PTRACE_GETEVENTMSG,pid,0,&cookie));
        struct user_pt_regs r=get(pid);
        assert(cookie==MD_INTERCEPT_PROC && r.regs[8]==SYS_read && (int)r.regs[0]==data[0]);
        ++intercepted;
        assert(!ptrace(PTRACE_CONT,pid,0,0));
    }
    assert(!WEXITSTATUS(status) && shared->completed && intercepted==(denied==0 ? 1u : 0u));
    int first_error=shared->first_error;
    close(ep); close(start[0]); close(start[1]); close(data[0]); close(data[1]);
    assert(!munmap(shared,sizeof(*shared)));
    return first_error;
}
struct sibling {
    struct shared *shared;
    int ready,release,reader,divergent;
};
static void *sibling(void *context) {
    struct sibling *s=context;
    if (s->divergent) {
        struct sock_filter code[]={BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        struct sock_fprog p={1,code};
        assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p));
    }
    s->shared->sibling=(pid_t)syscall(SYS_gettid);
    assert(write(s->ready,"r",1)==1);
    char byte;
    /* EVENT_WAIT: the owner returns from remote admission before releasing
     * this sibling; fixture alarm bounds a failed admission continuation. */
    assert(read(s->release,&byte,1)==1 && byte=='r');
    assert(read(s->reader,&byte,1)==1 && byte=='q');
    return NULL;
}
static void group(int divergent,int protected) {
    struct shared *shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(shared!=MAP_FAILED);
    int start[2],data[2],ready[2],release[2];
    assert(!pipe2(start,O_CLOEXEC) && !pipe2(data,O_CLOEXEC)
        && !pipe2(ready,O_CLOEXEC) && !pipe2(release,O_CLOEXEC));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
        char byte; assert(read(start[0],&byte,1)==1);
        if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        struct sibling s={shared,ready[1],release[0],data[0],divergent};
        pthread_t thread; assert(!pthread_create(&thread,NULL,sibling,&s));
        assert(read(ready[0],&byte,1)==1 && byte=='r');
        remote_pause();
        assert(write(release[1],"r",1)==1);
        assert(read(data[0],&byte,1)==1 && byte=='q');
        assert(!pthread_join(thread,NULL));
        shared->completed=1; _exit(0);
    }
    assert(!ptrace(PTRACE_SEIZE,pid,0,(void *)(PTRACE_O_TRACECLONE|PTRACE_O_TRACESECCOMP|PTRACE_O_EXITKILL)));
    assert(write(start[1],"s",1)==1);
    pid_t other=0;
    for (;;) {
        /* EVENT_WAIT: clone, newborn or exact owner pause. No sampling delay. */
        int status; pid_t got=waitpid(-1,&status,__WALL); assert(got>0 && WIFSTOPPED(status));
        unsigned event=(unsigned)status>>16;
        if (got==pid && !event && WSTOPSIG(status)==SIGTRAP) {
            struct user_pt_regs r=get(pid); assert(r.pc==(uintptr_t)remote_paused);
            break;
        }
        if (event==PTRACE_EVENT_CLONE) {
            unsigned long tid; assert(!ptrace(PTRACE_GETEVENTMSG,got,0,&tid));
            assert(got==pid && !other); other=(pid_t)tid;
        } else assert(event==PTRACE_EVENT_STOP);
        assert(!ptrace(PTRACE_CONT,got,0,0));
    }
    assert(other>0 && shared->sibling==other);
    struct user_pt_regs saved=get(pid); saved.pc+=4;
    install(pid,data[0],shared,&saved,divergent ? other : 0);
    assert(write(data[1],"qq",2)==2);
    assert(!ptrace(PTRACE_CONT,pid,0,0));
    unsigned intercepted=0,exited=0;
    while (exited<2) {
        int status; pid_t got=waitpid(-1,&status,__WALL);
        assert(got==pid || got==other);
        if (WIFEXITED(status)) { assert(!WEXITSTATUS(status)); ++exited; continue; }
        assert(WIFSTOPPED(status) && (unsigned)status>>16==PTRACE_EVENT_SECCOMP);
        struct user_pt_regs r=get(got); unsigned long cookie;
        assert(!ptrace(PTRACE_GETEVENTMSG,got,0,&cookie));
        assert(cookie==MD_INTERCEPT_PROC && r.regs[8]==SYS_read && (int)r.regs[0]==data[0]);
        ++intercepted; assert(!ptrace(PTRACE_CONT,got,0,0));
    }
    assert(shared->completed && intercepted==(divergent ? 0u : 2u));
    close(start[0]); close(start[1]); close(data[0]); close(data[1]);
    close(ready[0]); close(ready[1]); close(release[0]); close(release[1]);
    assert(!munmap(shared,sizeof(*shared)));
}
static void pending_call(int boundary,int denied,int protected) {
    struct shared *shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(shared!=MAP_FAILED);
    int start[2],data[2]; assert(!pipe2(start,O_CLOEXEC) && !pipe2(data,O_CLOEXEC|O_NONBLOCK));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        char byte; assert(read(start[0],&byte,1)==1);
        if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_write,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|123),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_seccomp,0,1),
            BPF_STMT(BPF_RET|BPF_K,denied ? SECCOMP_RET_ERRNO|EPERM : SECCOMP_RET_TRACE|MD_INTERCEPT_TASK),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
        };
        struct sock_fprog p={sizeof(code)/sizeof(*code),code};
        assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p));
        shared->waiting=1;
        assert(write(data[1],"q",1)==1);
        shared->completed=1; _exit(0);
    }
    assert(!ptrace(PTRACE_SEIZE,pid,0,(void *)(PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACESECCOMP|PTRACE_O_EXITKILL)));
    assert(!ptrace(PTRACE_INTERRUPT,pid,0,0)); assert(WIFSTOPPED(stop(pid)));
    assert(write(start[1],"s",1)==1);
    struct user_pt_regs saved;
    int original_status;
    for (;;) {
        assert(!ptrace(PTRACE_SYSCALL,pid,0,0));
        int status=stop(pid); assert(WIFSTOPPED(status));
        struct ptrace_syscall_info info={0};
        assert(ptrace(PTRACE_GET_SYSCALL_INFO,pid,sizeof(info),&info)>0);
        saved=get(pid);
        if (shared->waiting && saved.regs[8]==SYS_write && info.op==boundary) { original_status=status; break; }
    }
    struct md_task_quiesce *barrier=md_task_quiesce_new(trace); assert(barrier);
    assert(!md_task_quiesce_add(barrier,pid,1,0));
    struct rusage usage={.ru_maxrss=123};
    assert(!md_task_quiesce_event(barrier,pid,original_status,&usage));
    struct md_task_quiesce_stop borrowed;
    assert(!md_task_quiesce_borrow(barrier,pid,&borrowed)
        && borrowed.kind==MD_TASK_QUIESCE_EVENT && borrowed.status==original_status);
    install_at(pid,data[1],shared,&saved,denied==1 ? -EPERM : 0,boundary,denied==2);
    assert(!md_task_quiesce_return(barrier,pid) && !md_task_quiesce_release(barrier));
    int replay;
    assert(md_task_quiesce_take(barrier,&replay,&usage)==pid && replay==original_status && usage.ru_maxrss==123);
    assert(!md_task_quiesce_take(barrier,&replay,NULL)); md_task_quiesce_destroy(barrier);
    for (;;) {
        assert(!ptrace(PTRACE_CONT,pid,0,0));
        int status=stop(pid);
        if (WIFEXITED(status)) { assert(!WEXITSTATUS(status)); break; }
        assert(boundary==PTRACE_SYSCALL_INFO_ENTRY && (unsigned)status>>16==PTRACE_EVENT_SECCOMP);
    }
    char byte[2]; assert(shared->completed && read(data[0],byte,2)==1 && byte[0]=='q');
    assert(read(data[0],byte,2)==-1 && errno==EAGAIN);
    close(start[0]); close(start[1]); close(data[0]); close(data[1]);
    assert(!munmap(shared,sizeof(*shared)));
}
static void task_context(int protected) {
    struct shared *shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(shared!=MAP_FAILED);
    int start[2]; assert(!pipe2(start,O_CLOEXEC));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        char byte; assert(read(start[0],&byte,1)==1);
        if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
        sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGUSR1);
        assert(!sigprocmask(SIG_BLOCK,&mask,NULL));
        int signal=signalfd(-1,&mask,SFD_NONBLOCK|SFD_CLOEXEC); assert(signal>=0);
        int ep=epoll_create1(EPOLL_CLOEXEC); assert(ep>=0);
        struct epoll_event event={.events=EPOLLIN,.data.u64=0xfdeede};
        assert(!epoll_ctl(ep,EPOLL_CTL_ADD,signal,&event));
        shared->signal_epoll=ep;
        assert(!raise(SIGUSR1));
        remote_pause();
        struct signalfd_siginfo info;
        assert(read(signal,&info,sizeof(info))==sizeof(info) && info.ssi_signo==SIGUSR1);
        assert(!sigprocmask(SIG_SETMASK,NULL,&mask) && sigismember(&mask,SIGUSR1)==1
            && sigismember(&mask,SIGUSR2)==0);
        shared->completed=1; _exit(0);
    }
    assert(!ptrace(PTRACE_SEIZE,pid,0,(void *)PTRACE_O_EXITKILL));
    assert(write(start[1],"s",1)==1);
    int status=stop(pid); assert(WIFSTOPPED(status) && WSTOPSIG(status)==SIGTRAP);
    struct user_pt_regs saved=get(pid); assert(saved.pc==(uintptr_t)remote_paused); saved.pc+=4;
    struct md_task_call call={0};
    struct md_task_call_arguments args={SYS_epoll_pwait,
        {(unsigned long)shared->signal_epoll,(uintptr_t)&shared->signal_event,1,0,0,8}};
    assert(!md_task_call_begin(&call,trace,pid,MD_TASK_CALL_USER,&saved,
        (uintptr_t)remote_call,(uintptr_t)remote_return,&args));
    int ready;
    do { ready=md_task_call_event(&call,stop(pid)); } while (!ready);
    assert(ready==1 && call.result==1 && shared->signal_event.events==EPOLLIN
        && shared->signal_event.data.u64==0xfdeede);
    args=(struct md_task_call_arguments){SYS_getpid,{0}};
    assert(!md_task_call_again(&call,&args));
    do { ready=md_task_call_event(&call,stop(pid)); } while (!ready);
    assert(ready==1 && call.result==pid);
    struct user_pt_regs restored=get(pid); assert(!memcmp(&restored,&saved,sizeof(saved)));
    assert(!ptrace(PTRACE_CONT,pid,0,0));
    status=stop(pid); assert(WIFEXITED(status) && !WEXITSTATUS(status) && shared->completed);
    close(start[0]); close(start[1]); assert(!munmap(shared,sizeof(*shared)));
}
static void caught_signal(int signal) { assert(signal==SIGUSR2); }
static void restart_exit(int protected) {
    struct shared *shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(shared!=MAP_FAILED);
    int start[2],data[2]; assert(!pipe2(start,O_CLOEXEC) && !pipe2(data,O_CLOEXEC));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        char byte; assert(read(start[0],&byte,1)==1);
        if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
        struct sigaction action={.sa_handler=caught_signal,.sa_flags=SA_RESTART};
        sigemptyset(&action.sa_mask); assert(!sigaction(SIGUSR2,&action,NULL));
        shared->waiting=1;
        assert(read(data[0],&byte,1)==1 && byte=='q');
        shared->completed=1; _exit(0);
    }
    assert(!ptrace(PTRACE_SEIZE,pid,0,(void *)(PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACESECCOMP|PTRACE_O_EXITKILL)));
    assert(!ptrace(PTRACE_INTERRUPT,pid,0,0)); assert(WIFSTOPPED(stop(pid)));
    assert(write(start[1],"s",1)==1);
    for (;;) {
        assert(!ptrace(PTRACE_SYSCALL,pid,0,0)); assert(WIFSTOPPED(stop(pid)));
        struct ptrace_syscall_info info={0};
        assert(ptrace(PTRACE_GET_SYSCALL_INFO,pid,sizeof(info),&info)>0);
        if (shared->waiting && info.op==PTRACE_SYSCALL_INFO_ENTRY
                && info.entry.nr==SYS_read && (int)info.entry.args[0]==data[0]) break;
    }
    assert(!kill(pid,SIGUSR2));
    assert(!ptrace(PTRACE_SYSCALL,pid,0,0));
    int status=stop(pid); assert(WIFSTOPPED(status) && WSTOPSIG(status)==(SIGTRAP|0x80));
    struct user_pt_regs saved=get(pid);
    assert((long)saved.regs[0]==-512);
    uint64_t before,after;
    assert(!ptrace(PTRACE_GETSIGMASK,pid,(void *)sizeof(before),&before));
    struct md_task_filter call={0};
    struct md_fd_filter_gates gates={(uintptr_t)remote_return,0,0};
    assert(md_task_filter_begin(&call,trace,pid,MD_TASK_CALL_EXIT,&saved,
        (uintptr_t)remote_call,(uintptr_t)remote_return,&shared->image,(uintptr_t)&shared->image,
        MD_FD_SELECTOR_PROC,data[0],&gates)==-EAGAIN && !call.task.stage);
    struct user_pt_regs unchanged=get(pid); assert(!memcmp(&saved,&unchanged,sizeof(saved)));
    assert(!ptrace(PTRACE_GETSIGMASK,pid,(void *)sizeof(after),&after) && before==after);
    assert(!ptrace(PTRACE_CONT,pid,0,0));
    status=stop(pid); assert(WIFSTOPPED(status) && WSTOPSIG(status)==SIGUSR2);
    assert(write(data[1],"q",1)==1);
    assert(!ptrace(PTRACE_CONT,pid,0,SIGUSR2));
    status=stop(pid); assert(WIFEXITED(status) && !WEXITSTATUS(status) && shared->completed);
    close(start[0]); close(start[1]); close(data[0]); close(data[1]);
    assert(!munmap(shared,sizeof(*shared)));
}
int main(void) {
    alarm(30);
    for (int protected=0;protected<2;++protected) for (int reading=0;reading<2;++reading) {
        int baseline=run(-1,reading,protected);
        /* Linux restarts pipe reads, but epoll returns EINTR after the native
         * ptrace interrupt itself. Admission must preserve both outcomes. */
        assert(baseline==(reading ? 0 : EINTR));
        assert(run(0,reading,protected)==baseline && run(1,reading,protected)==baseline);
    }
    for (int protected=0;protected<2;++protected) for (int divergent=0;divergent<2;++divergent)
        group(divergent,protected);
    for (int protected=0;protected<2;++protected) for (int denied=0;denied<3;++denied)
        for (int boundary=PTRACE_SYSCALL_INFO_ENTRY;boundary<=PTRACE_SYSCALL_INFO_SECCOMP;++boundary)
            pending_call(boundary,denied,protected);
    for (int protected=0;protected<2;++protected) restart_exit(protected);
    for (int protected=0;protected<2;++protected) task_context(protected);
    puts("PASS remote FD filter: protected tasks, native interrupt/restart, signal masks and seccomp policy");
    puts("PASS group FD filter: TSYNC reaches every sibling; incompatible filter leaves both unchanged");
    puts("PASS FD filter continuation: syscall entry, seccomp and exit execute the original write exactly once");
    puts("PASS restart-exit admission: unchanged registers/mask, deferred installation and native signal restart");
    puts("PASS task-context call: protected signalfd readiness, repeated syscall and exact register/mask restoration");
    return 0;
}
