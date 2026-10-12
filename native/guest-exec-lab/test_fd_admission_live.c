#define _GNU_SOURCE
#include "fd_admission.h"
#include "control_epoll.h"
#include "task_filter.h"
#include "task_quiesce.h"
#include "interception.h"
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char admission_call[],admission_return[],admission_paused[];
extern void admission_pause(void);
__asm__(".text\n.global admission_call\nadmission_call:\nsvc #0\n"
    ".global admission_return\nadmission_return:\nbrk #0\n"
    ".global admission_pause\nadmission_pause:\n.global admission_paused\nadmission_paused:\nbrk #0\nret\n");
enum { ACTORS=3 };
struct shared {
    struct md_task_filter_image image;
    pid_t pids[ACTORS];
    int completed[ACTORS];
};
struct argument { struct shared *shared; int index,fd[2],denied,protected; };
static int actor(void *context) {
    struct argument *a=context;
    if (a->protected) assert(!prctl(PR_SET_DUMPABLE,0));
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getpgid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOKEY),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_seccomp,0,1),
        BPF_STMT(BPF_RET|BPF_K,a->denied && a->index==1 ? SECCOMP_RET_ERRNO|EPERM : SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    a->shared->pids[a->index]=getpid();
    admission_pause();
    for (unsigned i=0;i<2;++i) {
        struct epoll_event event;
        assert(!syscall(SYS_epoll_pwait,a->fd[i],&event,1,0,NULL,sizeof(uint64_t)));
    }
    assert(syscall(SYS_getpgid,0)==-1 && errno==ENOKEY);
    a->shared->completed[a->index]=1;
    return 0;
}
static long trace(int operation,pid_t pid,void *address,void *data) {
    return ptrace(operation,pid,address,data);
}
static struct user_pt_regs registers(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec data={&regs,sizeof(regs)};
    assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&data));
    return regs;
}
static pid_t event(pid_t pid,int *status) {
    /* EVENT_WAIT: tracee lifecycle or task-affine return; fixture alarm bounds failure. */
    pid_t result;
    do { result=waitpid(pid,status,__WALL); } while (result<0 && errno==EINTR);
    assert(result>0); return result;
}
static unsigned index_of(const struct shared *shared,pid_t pid) {
    for (unsigned i=0;i<ACTORS;++i) if (shared->pids[i]==pid) return i;
    assert(0); return 0;
}
static void publish(struct md_fd_origins *files,struct md_fd_object *object,int fd) {
    struct md_fd_origin_update update={0};
    assert(!md_fd_origins_prepare_object(files,object,0,&update));
    md_fd_origins_finish(&update,fd);
}
static void run(int denied,int protected) {
    struct shared *shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(shared!=MAP_FAILED);
    int start[2]; assert(!pipe2(start,O_CLOEXEC));
    int ep=epoll_create1(EPOLL_CLOEXEC); assert(ep>=0);
    int alias=fcntl(ep,F_DUPFD_CLOEXEC,ep+1); assert(alias>=0);
    pid_t first=fork(); assert(first>=0);
    if (!first) {
        char byte; assert(read(start[0],&byte,1)==1);
        void *stack=malloc(65536); assert(stack);
        struct argument args[ACTORS];
        for (unsigned i=0;i<ACTORS;++i) args[i]=(struct argument){shared,(int)i,{ep,alias},denied,protected};
        pid_t same=clone(actor,(char *)stack+65536,CLONE_FILES|SIGCHLD,&args[1]); assert(same>0);
        pid_t copy=fork(); assert(copy>=0);
        if (!copy) _exit(actor(&args[2]));
        assert(!actor(&args[0]));
        int status;
        assert(waitpid(same,&status,0)==same && WIFEXITED(status) && !WEXITSTATUS(status));
        assert(waitpid(copy,&status,0)==copy && WIFEXITED(status) && !WEXITSTATUS(status));
        free(stack); _exit(0);
    }
    assert(!ptrace(PTRACE_SEIZE,first,0,(void *)(PTRACE_O_TRACEFORK|PTRACE_O_TRACECLONE
        |PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACESECCOMP|PTRACE_O_EXITKILL)));
    assert(write(start[1],"s",1)==1);
    close(start[0]); close(start[1]); close(ep); close(alias);
    struct user_pt_regs continuations[ACTORS];
    unsigned stopped=0,births=0;
    while (stopped<ACTORS) {
        int status; pid_t pid=event(-1,&status);
        assert(WIFSTOPPED(status));
        unsigned kind=(unsigned)status>>16;
        if (!kind && WSTOPSIG(status)==SIGTRAP) {
            unsigned index=index_of(shared,pid);
            continuations[index]=registers(pid);
            assert(continuations[index].pc==(uintptr_t)admission_paused);
            continuations[index].pc+=4; ++stopped;
        } else {
            if (kind==PTRACE_EVENT_FORK || kind==PTRACE_EVENT_CLONE) ++births;
            else assert(kind==PTRACE_EVENT_STOP);
            assert(!ptrace(PTRACE_CONT,pid,0,0));
        }
    }
    assert(births==2 && shared->pids[0]==first);
    struct md_control_epoll *queue=md_control_epoll_new(); assert(queue);
    struct md_fd_object *object=md_control_epoll_object(queue);
    struct md_fd_origins *files=md_fd_origins_new(); assert(files);
    publish(files,object,ep); publish(files,object,alias);
    struct md_fd_origins *copy=md_fd_origins_fork(files,0); assert(copy);
    struct md_fd_selector *groups[ACTORS];
    assert(md_control_epoll_admit_begin(queue)==1);
    struct md_fd_admission *admission=md_fd_admission_new(object,1U<<MD_FD_SELECTOR_EPOLL); assert(admission);
    struct md_task_quiesce *barrier=md_task_quiesce_new(trace); assert(barrier);
    for (unsigned i=0;i<ACTORS;++i) {
        groups[i]=md_fd_selector_new(); assert(groups[i]);
        assert(!md_fd_admission_add(admission,i==2 ? copy : files,groups[i]));
        assert(!md_task_quiesce_add(barrier,shared->pids[i],1,0));
    }
    assert(!md_fd_admission_begin(admission,NULL) && md_fd_admission_prepare(admission)==1);
    assert(!md_fd_admission_seal(admission));
    unsigned installed[ACTORS]={0};
    struct md_fd_admission_request request;
    int next;
    while ((next=md_fd_admission_next(admission,&request))==1) {
        unsigned index=0;
        while (index<ACTORS && groups[index]!=request.group) ++index;
        assert(index<ACTORS);
        pid_t pid=shared->pids[index];
        struct md_task_quiesce_stop boundary;
        assert(!md_task_quiesce_borrow(barrier,pid,&boundary) && boundary.kind==MD_TASK_QUIESCE_HELD);
        struct md_task_filter call={0};
        struct md_fd_filter_gates gates={(uintptr_t)admission_return,0,0};
        assert(!md_task_filter_begin(&call,trace,pid,MD_TASK_CALL_USER,&continuations[index],
            (uintptr_t)admission_call,(uintptr_t)admission_return,&shared->image,(uintptr_t)&shared->image,
            request.kind,request.number,&gates));
        int ready;
        do { int status; event(pid,&status); ready=md_task_filter_event(&call,status); } while (!ready);
        assert(ready==1 && !md_task_quiesce_return(barrier,pid));
        int result=md_fd_admission_observed(admission,&request,call.task.result);
        if (result) { assert(denied && index==1 && result==-EPERM); break; }
        ++installed[index];
    }
    assert((denied && next==1) || (!denied && next==2));
    assert(installed[2]==2 && installed[1]==(denied ? 0U : 2U) && installed[0]==(denied ? 0U : 2U));
    assert(!md_control_epoll_admit_finish(queue,!denied));
    assert(md_fd_object_selectors(object)==(denied ? 0U
        : (1U<<MD_FD_SELECTOR_EPOLL)|(1U<<MD_FD_SELECTOR_EPOLL_TARGET)));
    assert(denied ? md_control_epoll_descriptor(queue)==-1 : md_control_epoll_descriptor(queue)>=0);
    md_fd_admission_release(admission);
    assert(!md_task_quiesce_release(barrier)); md_task_quiesce_destroy(barrier);
    for (unsigned i=0;i<ACTORS;++i) {
        struct iovec data={&continuations[i],sizeof(continuations[i])};
        assert(!ptrace(PTRACE_SETREGSET,shared->pids[i],(void *)NT_PRSTATUS,&data));
        assert(!ptrace(PTRACE_CONT,shared->pids[i],0,0));
    }
    unsigned observed[ACTORS]={0},exited=0;
    while (exited<ACTORS) {
        int status; pid_t pid=event(-1,&status);
        unsigned index=index_of(shared,pid);
        if (WIFEXITED(status)) { assert(!WEXITSTATUS(status)); ++exited; continue; }
        assert(WIFSTOPPED(status));
        unsigned kind=(unsigned)status>>16;
        if (kind==PTRACE_EVENT_SECCOMP) {
            unsigned long cookie;
            assert(!ptrace(PTRACE_GETEVENTMSG,pid,0,&cookie) && cookie==MD_INTERCEPT_READINESS);
            struct user_pt_regs regs=registers(pid);
            assert(regs.regs[8]==SYS_epoll_pwait && ((int)regs.regs[0]==ep || (int)regs.regs[0]==alias));
            ++observed[index];
        } else assert(!kind && WSTOPSIG(status)==SIGCHLD);
        assert(!ptrace(PTRACE_CONT,pid,0,kind ? 0 : SIGCHLD));
    }
    for (unsigned i=0;i<ACTORS;++i) {
        assert(shared->completed[i] && observed[i]==installed[i]);
        md_fd_selector_release(groups[i]);
    }
    md_fd_origins_release(files); md_fd_origins_release(copy); md_control_epoll_release(queue);
    assert(!munmap(shared,sizeof(*shared)));
}
void test_fd_admission_live(void) {
    for (int protected=0;protected<2;++protected)
        for (int denied=0;denied<2;++denied) run(denied,protected);
    puts("PASS live FD admission: shared/forked file tables, all alias owners, protected tasks and partial-denial rollback");
}
