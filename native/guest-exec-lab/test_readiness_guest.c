#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/close_range.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <time.h>

static void byte_read(int fd) {
    char c;
    ssize_t n;
    do n=read(fd,&c,1); while (n<0 && errno==EINTR);
    if (n!=1) fprintf(stderr,"byte read fd=%d result=%zd errno=%d\n",fd,n,errno);
    assert(n==1);
}
static void byte_write(int fd) { assert(write(fd,"x",1)==1); }
static volatile sig_atomic_t signalled;
static void on_signal(int number) { assert(number==SIGUSR1); signalled=1; }
static void signal_wait(int ep) {
    struct sigaction action={.sa_handler=on_signal}; sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1,&action,NULL));
    sigset_t blocked,saved,after;
    sigemptyset(&blocked); sigaddset(&blocked,SIGUSR1);
    assert(!sigprocmask(SIG_BLOCK,&blocked,&saved));
    assert(!raise(SIGUSR1));
    struct epoll_event out;
    assert(epoll_pwait(ep,&out,1,1000,&saved)==-1 && errno==EINTR && signalled);
    assert(!sigprocmask(SIG_SETMASK,NULL,&after) && sigismember(&after,SIGUSR1)==1);
    assert(!sigprocmask(SIG_SETMASK,&saved,NULL));
    puts("PASS mixed epoll: atomic signal mask, EINTR and restoration");
}
static void signal_ready(int ep) {
    sigset_t blocked,saved,after;
    sigemptyset(&blocked); sigaddset(&blocked,SIGUSR1);
    assert(!sigprocmask(SIG_BLOCK,&blocked,&saved));
    signalled=0;
    for (unsigned i=0;i<2;++i) {
        assert(!sethostname(i ? "ready-signal-b" : "ready-signal-a",14));
        assert(!raise(SIGUSR1));
        struct epoll_event out={0};
        assert(epoll_pwait(ep,&out,1,1000,&saved)==1 && out.data.u64==42 && (out.events&EPOLLERR));
        assert(!sigprocmask(SIG_SETMASK,NULL,&after) && sigismember(&after,SIGUSR1)==1);
        assert(!epoll_wait(ep,&out,1,0));
    }
    assert(!sigprocmask(SIG_SETMASK,&saved,NULL) && signalled);
    puts("PASS mixed epoll: ready virtual event with pending signal, single consumption and mask restoration");
}
static void signal_descriptor(int ep) {
    sigset_t blocked,saved;
    sigemptyset(&blocked); sigaddset(&blocked,SIGUSR2);
    assert(!sigprocmask(SIG_BLOCK,&blocked,&saved));
    int fd=signalfd(-1,&blocked,SFD_CLOEXEC|SFD_NONBLOCK); assert(fd>=0);
    struct epoll_event event={.events=EPOLLIN,.data.u64=44},out;
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,fd,&event));
    assert(!raise(SIGUSR2));
    assert(epoll_wait(ep,&out,1,0)==1 && out.data.u64==44 && (out.events&EPOLLIN));
    struct signalfd_siginfo info;
    assert(read(fd,&info,sizeof(info))==sizeof(info) && info.ssi_signo==SIGUSR2);
    assert(!epoll_wait(ep,&out,1,0));
    int go[2]; assert(!pipe2(go,O_CLOEXEC));
    pid_t owner=getpid(),child=fork(); assert(child>=0);
    if (!child) { byte_read(go[0]); assert(!kill(owner,SIGUSR2)); _exit(0); }
    byte_write(go[1]);
    assert(epoll_wait(ep,&out,1,3000)==1 && out.data.u64==44 && (out.events&EPOLLIN));
    assert(read(fd,&info,sizeof(info))==sizeof(info) && info.ssi_signo==SIGUSR2);
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(go[0]); close(go[1]);
    assert(!epoll_ctl(ep,EPOLL_CTL_DEL,fd,NULL)); close(fd);
    assert(!sigprocmask(SIG_SETMASK,&saved,NULL));
    puts("PASS mixed epoll: task-affine signalfd readiness and process-signal wake");
}
static void virtual_wake(int ep) {
    int go[2]; assert(!pipe2(go,O_CLOEXEC));
    pid_t child=fork(); assert(child>=0);
    if (!child) { byte_read(go[0]); assert(!sethostname("wake-virtual",12)); _exit(0); }
    byte_write(go[1]);
    struct epoll_event out={0};
    errno=0;
    int result=epoll_wait(ep,&out,1,3000),error=errno;
    if (result!=1 || out.data.u64!=42 || !(out.events&EPOLLERR))
        fprintf(stderr,"virtual wake: result=%d errno=%d events=%#x data=%llu\n",result,error,
            out.events,(unsigned long long)out.data.u64);
    assert(result==1 && out.data.u64==42 && (out.events&EPOLLERR));
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(go[0]); close(go[1]);
    assert(!epoll_wait(ep,&out,1,0));
    puts("PASS mixed epoll: virtual source wakes a caller-context native wait");
}
static void shared_owner(int protected) {
    int fd=open("/proc/sys/kernel/hostname",O_RDONLY|O_CLOEXEC),ep=epoll_create1(EPOLL_CLOEXEC);
    int go[2],ready[2]; assert(fd>=0 && ep>=0 && !pipe2(go,O_CLOEXEC) && !pipe2(ready,O_CLOEXEC));
    int alias=dup(ep); assert(alias>=0);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        if (protected) assert(!prctl(PR_SET_DUMPABLE,0,0,0,0));
        byte_write(ready[1]); byte_read(go[0]);
        struct epoll_event event;
        assert(epoll_wait(alias,&event,1,0)==1 && event.data.u64==84 && (event.events&EPOLLERR));
        assert(!epoll_wait(alias,&event,1,0));
        _exit(0);
    }
    byte_read(ready[0]);
    struct epoll_event event={.events=0,.data.u64=84};
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,fd,&event));
    assert(!sethostname(protected ? "protected-owner" : "shared-owner",protected ? 15 : 12));
    byte_write(go[1]);
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(go[0]); close(go[1]); close(ready[0]); close(ready[1]); close(alias); close(ep); close(fd);
    printf("PASS epoll cross-owner activation protected=%d\n",protected);
}

static void deny_seccomp(void) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_seccomp,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
}
struct table_holder_context { int fd; pid_t parent; };
static int table_holder(void *context) {
    const struct table_holder_context *owner=context;
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=owner->parent) return 0;
    /* EVENT_WAIT: parent finishes its assertions; parent death kills the
     * keeper so a failed test does not wait for the outer launch deadline. */
    byte_read(owner->fd);
    return 0;
}
static int64_t now_ms(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static int loan_slot(int ep,int other) {
    char path[64],name[128];
    for (int fd=3;fd<128;++fd) if (fd!=ep && fd!=other) {
        snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
        ssize_t n=readlink(path,name,sizeof(name)-1);
        if (n<0) continue;
        name[n]=0;
        if (!strcmp(name,"anon_inode:[eventpoll]")) return fd;
    }
    return -1;
}
static int await_loan(int ep,int other,int present) {
    int64_t end=now_ms()+5000;
    /* EVENT_WAIT: observe an actual installed/retired epoll alias, not a
     * guessed settling delay. The deadline fails an absent lifecycle event. */
    do {
        int fd=loan_slot(ep,other);
        if ((fd>=0)==present) return fd;
        sched_yield();
    } while (now_ms()<end);
    assert(!"epoll loan lifecycle deadline"); return -1;
}
struct race_context { int ep,event,other,ready,mode; pid_t parent; };
static int race_mutator(void *opaque) {
    struct race_context *c=opaque;
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=c->parent) return 0;
    int slot=await_loan(c->ep,c->other,1);
    if (c->mode==0) assert(dup3(c->event,slot,O_CLOEXEC)==slot);
    if (c->mode==1) assert(!syscall(SYS_close_range,slot,slot,0));
    if (c->mode==2) assert(dup3(c->other,c->ep,O_CLOEXEC)==c->ep);
    if (c->mode==3) {
        pid_t child=fork(); assert(child>=0);
        if (!child) { assert(loan_slot(c->ep,c->other)<0); _exit(0); }
        int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    }
    if (c->mode==5) {
        assert(!unshare(CLONE_FILES));
        assert(loan_slot(c->ep,c->other)<0);
    }
    if (c->mode==6) assert(!syscall(SYS_close_range,slot,slot,CLOSE_RANGE_CLOEXEC));
    assert(write(c->ready,&slot,sizeof(slot))==sizeof(slot));
    uint64_t one=1; assert(write(c->event,&one,sizeof(one))==sizeof(one));
    return 0;
}
static int race_waiter(void *opaque) {
    struct race_context *c=opaque;
    struct epoll_event out;
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=c->parent) return 0;
    byte_write(c->ready);
    epoll_wait(c->ep,&out,1,-1);
    assert(!"killed waiter returned"); return 0;
}
static void shared_races(int fd) {
    for (int mode=0;mode<7;++mode) {
        int ep=epoll_create1(EPOLL_CLOEXEC),event=eventfd(0,EFD_CLOEXEC),other=epoll_create1(EPOLL_CLOEXEC);
        int ready[2]; assert(ep>=0 && event>=0 && other>=0 && !pipe2(ready,O_CLOEXEC));
        struct epoll_event e={.events=0,.data.u64=42},out;
        assert(!epoll_ctl(ep,EPOLL_CTL_ADD,fd,&e));
        e=(struct epoll_event){.events=EPOLLIN,.data.u64=43};
        assert(!epoll_ctl(ep,EPOLL_CTL_ADD,event,&e));
        void *stack=malloc(65536); assert(stack);
        struct race_context c={ep,event,other,ready[1],mode,getpid()};
        pid_t child=clone(mode==4 ? race_waiter : race_mutator,(char *)stack+65536,CLONE_FILES|SIGCHLD,&c);
        assert(child>0);
        if (mode==4) {
            byte_read(ready[0]);
            await_loan(ep,other,1);
            assert(!kill(child,SIGKILL));
        } else {
            int count=epoll_wait(ep,&out,1,10000);
            if (count!=1) fprintf(stderr,"race mode=%d count=%d errno=%d\n",mode,count,errno);
            assert(count==1 && out.data.u64==43);
            int slot; assert(read(ready[0],&slot,sizeof(slot))==sizeof(slot));
            if (!mode) { assert(fcntl(slot,F_GETFD)==FD_CLOEXEC); close(slot); }
        }
        int status; assert(waitpid(child,&status,0)==child);
        assert(mode==4 ? WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL : WIFEXITED(status) && !WEXITSTATUS(status));
        await_loan(ep,other,0);
        free(stack); close(ep); close(event); close(other); close(ready[0]); close(ready[1]);
        printf("PASS shared epoll custody mode=%d: exact queue and no retained alias\n",mode);
    }
}
static void mixed(int filtered,int shared) {
    assert(!unshare(CLONE_NEWNS|CLONE_NEWUTS));
    assert(!mount("proc","/proc","proc",0,NULL));
    if (filtered) deny_seccomp();
    int fd=open("/proc/sys/kernel/hostname",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    int ep=epoll_create1(EPOLL_CLOEXEC),event=eventfd(0,EFD_CLOEXEC); assert(ep>=0 && event>=0);
    struct epoll_event e={.events=0,.data.u64=42},out[4];
    puts("READY virtual ADD");
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,fd,&e));
    puts("READY virtual ADD completed");
    e=(struct epoll_event){.events=EPOLLIN,.data.u64=43};
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,event,&e));
    int holder_pipe[2]={-1,-1}; void *holder_stack=NULL; pid_t holder=0;
    struct table_holder_context holder_context={0};
    if (shared) {
        assert(!pipe2(holder_pipe,O_CLOEXEC));
        holder_stack=malloc(65536); assert(holder_stack);
        holder_context=(struct table_holder_context){holder_pipe[0],getpid()};
        holder=clone(table_holder,(char *)holder_stack+65536,CLONE_FILES|SIGCHLD,&holder_context);
        assert(holder>0);
    }
    assert(!epoll_wait(ep,out,4,0));
    uint64_t one=1; assert(write(event,&one,sizeof(one))==sizeof(one));
    assert(epoll_wait(ep,out,4,0)==1 && out[0].data.u64==43);
    assert(read(event,&one,sizeof(one))==sizeof(one));
    assert(!sethostname("epoll-test",10));
    assert(epoll_wait(ep,out,4,0)==1 && out[0].data.u64==42 && (out[0].events&EPOLLERR));
    assert(!epoll_wait(ep,out,4,0));
    pid_t child=fork(); assert(child>=0);
    if (!child) { assert(write(event,&one,sizeof(one))==sizeof(one)); _exit(0); }
    assert(epoll_wait(ep,out,4,3000)==1 && out[0].data.u64==43);
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(read(event,&one,sizeof(one))==sizeof(one));
    assert(!epoll_wait(ep,out,4,1));
    virtual_wake(ep);
    e.data.u64=42;
    assert(!epoll_ctl(ep,EPOLL_CTL_MOD,event,&e));
    assert(write(event,&one,sizeof(one))==sizeof(one) && !sethostname("equal-data",10));
    assert(epoll_wait(ep,out,2,0)==2 && out[0].data.u64==42 && out[1].data.u64==42
        && ((out[0].events|out[1].events)&(EPOLLIN|EPOLLERR))==(EPOLLIN|EPOLLERR));
    assert(read(event,&one,sizeof(one))==sizeof(one));
    signal_wait(ep);
    signal_ready(ep);
    signal_descriptor(ep);
    if (shared) {
        byte_write(holder_pipe[1]);
        assert(waitpid(holder,&status,0)==holder && WIFEXITED(status) && !WEXITSTATUS(status));
        close(holder_pipe[0]); close(holder_pipe[1]); free(holder_stack);
        /* The following scenarios own their epoll queues independently. */
        close(ep); ep=-1; close(event); event=-1;
        shared_races(fd);
    }
    if (ep>=0) {
        assert(!epoll_ctl(ep,EPOLL_CTL_DEL,fd,NULL));
        assert(!epoll_ctl(ep,EPOLL_CTL_DEL,event,NULL));
    }
    close(ep); close(fd); close(event);
    puts("PASS mixed epoll: virtual hostname, native eventfd, fork, blocking wait and timeout");
    shared_owner(0); shared_owner(1);
}
static void close_filtered(int retirement_denied) {
    assert(!unshare(CLONE_NEWNS|CLONE_NEWUTS));
    assert(!mount("proc","/proc","proc",0,NULL));
    int fd=open("/proc/sys/kernel/hostname",O_RDONLY|O_CLOEXEC),ep=epoll_create1(EPOLL_CLOEXEC);
    int release[2]; assert(fd>=0 && ep>=0 && !pipe2(release,O_CLOEXEC));
    struct epoll_event e={.data.u64=42},out;
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,fd,&e));
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_close,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_close_range,0,1),
        BPF_STMT(BPF_RET|BPF_K,retirement_denied ? SECCOMP_RET_ERRNO|EPERM : SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog policy={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&policy));
    void *stack=malloc(65536); assert(stack);
    struct table_holder_context c={release[0],getpid()};
    pid_t peer=clone(table_holder,(char *)stack+65536,CLONE_FILES|SIGCHLD,&c); assert(peer>0);
    assert(!epoll_wait(ep,&out,1,0));
    assert(!retirement_denied);
    assert(!sethostname("close-policy",12));
    assert(epoll_wait(ep,&out,1,0)==1 && out.data.u64==42);
    assert(loan_slot(ep,-1)<0);
    assert(close(ep)==-1 && errno==EPERM);
    byte_write(release[1]);
    int status; assert(waitpid(peer,&status,0)==peer && WIFEXITED(status) && !WEXITSTATUS(status));
    free(stack);
    puts("PASS mixed epoll: denied close retains application policy; exact close_range retirement");
}

static int filter_probe(void) {
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_epoll_pwait,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,UINT_MAX,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program={sizeof(filter)/sizeof(*filter),filter};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    long result=syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&program);
    if (result) {
        printf("FAIL readiness selector admission result=%ld errno=%d\n",result,errno);
        errno=0;
        result=prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program,0,0);
        printf("PROBE per-thread prctl filter result=%ld errno=%d\n",result,errno);
        return 1;
    }
    struct epoll_event event;
    assert(syscall(SYS_epoll_pwait,-1,&event,1,0,NULL,8)==-1 && errno==EACCES);
    int ep=epoll_create1(EPOLL_CLOEXEC); assert(ep>=0);
    assert(!syscall(SYS_epoll_pwait,ep,&event,1,0,NULL,8));
    close(ep);
    puts("PASS readiness selector admission under inherited service filters");
    return 0;
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);
    if (argc==2 && !strcmp(argv[1],"--mixed")) { mixed(0,0); return 0; }
    if (argc==2 && !strcmp(argv[1],"--filtered")) { mixed(1,0); return 0; }
    if (argc==2 && !strcmp(argv[1],"--shared")) { mixed(0,1); return 0; }
    if (argc==2 && !strcmp(argv[1],"--shared-filtered")) { mixed(1,1); return 0; }
    if (argc==2 && !strcmp(argv[1],"--close-filtered")) { close_filtered(0); return 0; }
    if (argc==2 && !strcmp(argv[1],"--retire-filtered")) { close_filtered(1); return 0; }
    assert(argc>=2 && !strcmp(argv[1],"--filter"));
    int result=filter_probe();
    if (result || argc==2) return result;
    execv(argv[2],argv+2);
    perror("readiness exec");
    return 1;
}
