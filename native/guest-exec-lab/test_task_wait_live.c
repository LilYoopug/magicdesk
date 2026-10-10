#define _GNU_SOURCE
#include "task_wait.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned calls, general, directed, misses;
pid_t __real_wait4(pid_t, int *, int, struct rusage *);
pid_t __wrap_wait4(pid_t pid, int *status, int options, struct rusage *usage) {
    calls++;
    if (pid==-1) general++; else directed++;
    pid_t result=__real_wait4(pid,status,options,usage);
    if (!result) misses++;
    return result;
}
int main(void) {
    enum { CHILDREN=24, REQUESTS=128 };
    sigset_t mask;
    sigemptyset(&mask); sigaddset(&mask,SIGCHLD);
    assert(!sigprocmask(SIG_BLOCK,&mask,NULL));
    int fd=signalfd(-1,&mask,SFD_CLOEXEC|SFD_NONBLOCK);
    assert(fd>=0);
    pid_t children[CHILDREN];
    unsigned seen[CHILDREN]={0};
    pid_t parent=getpid();
    struct timespec started,ended;
    assert(!clock_gettime(CLOCK_MONOTONIC,&started));
    alarm(30);
    for (unsigned i=0;i<CHILDREN;i++) {
        children[i]=fork(); assert(children[i]>=0);
        if (!children[i]) {
            assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
            assert(!ptrace(PTRACE_TRACEME,0,0,0));
            raise(SIGSTOP);
            for (unsigned j=0;j<REQUESTS;j++) syscall(SYS_getpid);
            _exit(20+i);
        }
    }
    struct md_task_wait state={0};
    unsigned exited=0, stops=0, empty=0;
    while (exited<CHILDREN) {
        struct signalfd_siginfo info[8];
        ssize_t bytes;
        do { bytes=read(fd,info,sizeof(info)); } while (bytes<0 && errno==EINTR);
        assert((bytes<0 && errno==EAGAIN) || (bytes>0 && bytes%(ssize_t)sizeof(*info)==0));
        for (ssize_t i=0;i<bytes/(ssize_t)sizeof(*info);i++) {
            assert(info[i].ssi_signo==SIGCHLD);
            md_task_wait_hint(&state,(pid_t)info[i].ssi_pid);
        }
        int status;
        pid_t pid=md_task_wait_ready(&state,&status,NULL);
        if (pid<0 && errno==EINTR) continue;
        assert(pid>=0);
        if (!pid) {
            empty++;
            unsigned before=calls;
            for (unsigned i=0;i<32;i++) assert(!md_task_wait_ready(&state,&status,NULL));
            assert(calls==before);
            struct pollfd item={fd,POLLIN,0};
            /* EVENT_WAIT: blocked SIGCHLD invalidates the drained observation;
             * the alarm bounds missing notification or unreaped children. */
            int ready;
            do { ready=poll(&item,1,-1); } while (ready<0 && errno==EINTR);
            assert(ready==1 && (item.revents&POLLIN));
            continue;
        }
        unsigned i=0;
        while (i<CHILDREN && children[i]!=pid) i++;
        assert(i<CHILDREN);
        if (WIFEXITED(status)) {
            assert(WEXITSTATUS(status)==20+(int)i && seen[i]>=REQUESTS*2);
            children[i]=0; exited++; continue;
        }
        assert(WIFSTOPPED(status));
        if (!seen[i]) assert(!ptrace(PTRACE_SETOPTIONS,pid,0,
            PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL));
        seen[i]++; stops++;
        assert(!ptrace(PTRACE_SYSCALL,pid,0,0));
    }
    assert(stops>=CHILDREN*REQUESTS*2);
    alarm(0); close(fd);
    assert(!clock_gettime(CLOCK_MONOTONIC,&ended));
    double elapsed=ended.tv_sec-started.tv_sec+(ended.tv_nsec-started.tv_nsec)/1e9;
    printf("PASS live wait collection: children=%u stops=%u empty=%u calls=%u general=%u directed=%u misses=%u seconds=%.6f\n",
        exited,stops,empty,calls,general,directed,misses,elapsed);
    return 0;
}
