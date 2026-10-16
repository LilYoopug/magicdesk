#define _GNU_SOURCE
#include "../shroot/src/cooperative_channel.h"
#include <assert.h>
#include <asm/ptrace.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d);
    unsigned count=0; struct dirent *entry;
    while ((entry=readdir(d))) if (entry->d_name[0]!='.') ++count;
    assert(!closedir(d)); return count;
}
static void stopped(pid_t child,int signal) {
    int status; assert(waitpid(child,&status,0)==child);
    assert(WIFSTOPPED(status) && WSTOPSIG(status)==signal);
}
/* Break at one instruction per child. Single-stepping an ldaxr/stlxr pair
 * would disturb the exclusive monitor instead of exercising the real gate. */
static void boundary(uintptr_t pc,int kind) {
    struct md_entry_native *n=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(n!=MAP_FAILED);
    int fd=open("/proc/self/exe",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    *n=(struct md_entry_native){.state=MD_NATIVE_READY,.number=SYS_openat,
        .args={AT_FDCWD,(uintptr_t)"/proc/self/exe",O_RDONLY|O_CLOEXEC}};
    if (kind==1) { n->number=SYS_close; n->args[0]=fd; }
    if (kind==2) { n->number=SYS_fcntl; n->args[0]=fd; n->args[1]=F_SETFD; n->args[2]=0; }
    if (kind==3) n->args[1]=(uintptr_t)"/proc/self/not-a-file";
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        alarm(5);
        unsigned before=descriptors();
        assert(!ptrace(PTRACE_TRACEME,0,NULL,NULL));
        assert(!raise(SIGSTOP));
        md_cooperative_native(n);
        unsigned state=atomic_load(&n->state);
        assert(state==MD_NATIVE_DONE || state==MD_NATIVE_CANCELLED);
        if (state==MD_NATIVE_CANCELLED) {
            assert(n->result==-EINTR && descriptors()==before);
            assert(fcntl(fd,F_GETFD)==FD_CLOEXEC);
        } else if (!kind) {
            assert(n->result>=0 && descriptors()==before+1);
            assert(fcntl(n->result,F_GETFD)==FD_CLOEXEC);
            assert(!close(n->result));
        } else if (kind==1) {
            assert(!n->result && descriptors()==before-1);
            assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
        } else if (kind==2) {
            assert(!n->result && descriptors()==before && !fcntl(fd,F_GETFD));
        } else assert(n->result==-ENOENT && descriptors()==before);
        _exit(0);
    }
    stopped(child,SIGSTOP);
    uintptr_t word=pc&~(uintptr_t)7;
    errno=0; unsigned long saved=ptrace(PTRACE_PEEKTEXT,child,(void *)word,NULL); assert(!errno);
    unsigned shift=(pc-word)*8;
    unsigned long patched=(saved&~(UINT64_C(0xffffffff)<<shift))|(UINT64_C(0xd4200000)<<shift);
    assert(!ptrace(PTRACE_POKETEXT,child,(void *)word,(void *)patched));
    assert(!ptrace(PTRACE_CONT,child,NULL,NULL)); stopped(child,SIGTRAP);
    struct user_pt_regs regs; struct iovec io={&regs,sizeof(regs)};
    assert(!ptrace(PTRACE_GETREGSET,child,(void *)NT_PRSTATUS,&io) && regs.pc==pc);
    unsigned state=atomic_load(&n->state); long result=n->result;
    int completion=md_native_stopped(state,regs.pc,regs.regs[0],(uintptr_t)md_cooperative_native,
        (uintptr_t)md_cooperative_native_call,(uintptr_t)md_cooperative_native_end,&result);
    assert(completion==MD_NATIVE_DONE || completion==MD_NATIVE_CANCELLED);
    if (state==MD_NATIVE_RUNNING) {
        regs.regs[0]=result; regs.pc=(uintptr_t)md_cooperative_native_end;
        assert(!ptrace(PTRACE_SETREGSET,child,(void *)NT_PRSTATUS,&io));
    }
    n->result=result; atomic_store(&n->state,completion);
    assert(!ptrace(PTRACE_POKETEXT,child,(void *)word,(void *)saved));
    assert(!ptrace(PTRACE_CONT,child,NULL,NULL));
    int status; assert(waitpid(child,&status,0)==child);
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        fprintf(stderr,"native boundary kind=%d offset=%zu state=%u status=%#x\n",kind,pc-(uintptr_t)md_cooperative_native,state,status);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!close(fd) && !munmap(n,4096));
}
static struct md_entry_channel channel;
static pthread_barrier_t phase;
static atomic_int wake_requested;
static void barrier(void) {
    /* EVENT_WAIT: fixture peer reaches its protocol phase; alarm bounds failure. */
    int r=pthread_barrier_wait(&phase); assert(!r || r==PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *retire(void *unused) {
    (void)unused;
    for (unsigned i=0;i<1000;++i) {
        barrier(); assert(!md_entry_native_retire(&channel,1,MD_ENTRY_COMPLETED,42)); barrier();
    }
    return NULL;
}
static void retirement(void) {
    atomic_store(&channel.state,MD_ENTRY_NATIVE);
    assert(md_entry_native_retire(&channel,1,MD_ENTRY_COMPLETED,42)==1);
    assert(atomic_load(&channel.state)==MD_ENTRY_RESPONSE && channel.result==42 && channel.receipt==1);
    atomic_store(&channel.state,MD_ENTRY_RETIRING);
    assert(!md_entry_native_retire(&channel,1,MD_ENTRY_COMPLETED,42));
    assert(atomic_load(&channel.state)==MD_ENTRY_IDLE);
    pthread_t peer; assert(!pthread_barrier_init(&phase,NULL,2));
    assert(!pthread_create(&peer,NULL,retire,NULL));
    for (unsigned i=0;i<1000;++i) {
        channel.sequence=1; atomic_store(&channel.state,MD_ENTRY_RETIRING); barrier();
        channel.sequence=2; channel.call.number=SYS_close; channel.call.args[0]=i;
        unsigned state=i%2 ? MD_ENTRY_REQUEST : MD_ENTRY_FD_REQUEST;
        atomic_store_explicit(&channel.state,state,memory_order_seq_cst); barrier();
        assert(atomic_load(&channel.state)==state && channel.sequence==2);
        assert(channel.call.number==SYS_close && channel.call.args[0]==i);
    }
    assert(!pthread_join(peer,NULL) && !pthread_barrier_destroy(&phase));
    puts("PASS native retirement: synchronous receipt, idle owner and 1000 next-request publication races");
}
static void *publish(void *unused) {
    (void)unused;
    for (unsigned i=0;i<2000;++i) {
        barrier();
        if (i&1) atomic_store_explicit(&channel.state,MD_ENTRY_REQUEST,memory_order_seq_cst);
        else {
            atomic_store_explicit(&channel.native.state,MD_NATIVE_DONE,memory_order_release);
            atomic_thread_fence(memory_order_seq_cst);
        }
        atomic_store(&wake_requested,!atomic_load_explicit(&channel.awake,memory_order_seq_cst));
        barrier();
    }
    return NULL;
}
static void park_handoff(void) {
    assert(!pthread_barrier_init(&phase,NULL,2));
    pthread_t peer; assert(!pthread_create(&peer,NULL,publish,NULL));
    for (unsigned i=0;i<2000;++i) {
        atomic_store(&channel.state,MD_ENTRY_IDLE); atomic_store(&channel.native.state,MD_NATIVE_EMPTY);
        atomic_store(&channel.awake,1); atomic_store(&wake_requested,0);
        barrier(); unsigned pending=md_entry_prepare_wait(&channel); barrier();
        assert((pending&(i&1 ? MD_ENTRY_PENDING_CALL : MD_ENTRY_PENDING_NATIVE)) || atomic_load(&wake_requested));
    }
    assert(!pthread_join(peer,NULL) && !pthread_barrier_destroy(&phase));
    puts("PASS worker park: 2000 concurrent request/completion handoffs cannot lose both readiness and wake");
}
int main(void) {
    alarm(30); unsigned count=0;
    park_handoff();
    for (int kind=0;kind<4;++kind)
        for (uintptr_t pc=(uintptr_t)md_cooperative_native;pc<=(uintptr_t)md_cooperative_native_end;pc+=4) {
            boundary(pc,kind); ++count;
        }
    long result=0;
    for (long restart=-516;restart<=-512;++restart) {
        assert(md_native_stopped(MD_NATIVE_RUNNING,108,restart,100,104,120,&result)==MD_NATIVE_CANCELLED);
        assert(result==-EINTR);
    }
    assert(md_native_stopped(MD_NATIVE_RUNNING,108,-EINTR,100,104,120,&result)==MD_NATIVE_DONE);
    assert(result==-EINTR);
    assert(md_native_stopped(MD_NATIVE_RUNNING,99,0,100,104,120,&result)==-EPROTO);
    assert(md_native_stopped(MD_NATIVE_RUNNING,121,0,100,104,120,&result)==-EPROTO);
    retirement();
    printf("PASS native journal: %u exact instruction stops, real FD effects, cancellation and restart classification\n",count);
    return 0;
}
