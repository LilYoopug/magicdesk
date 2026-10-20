#define _GNU_SOURCE
#include "svc_payload.h"
#include <assert.h>
#include <errno.h>
#include <elf.h>
#include <inttypes.h>
#include <linux/ptrace.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static const uint32_t program[]={0xd28009e8,0xd4000001,0xd65f03c0};
static uint32_t *code;
static size_t page;
static int writable;
static char **arguments;
static void *execute(void *unused) {
    (void)unused;
    execl(arguments[0],arguments[0],arguments[1],"executed",NULL); assert(0); return NULL;
}
static md_entry_step_fn original_try;
static unsigned entered,released,mapped;
static int semaphore=-1;
static enum md_entry_outcome paused_try(struct md_entry_client *client,struct md_entry_call *call) {
    __atomic_store_n(&entered,1,__ATOMIC_RELEASE);
    if (semaphore>=0) {
        struct sembuf take={.sem_op=-1};
        long result=syscall(SYS_semop,semaphore,&take,1);
        if (result) perror("lifecycle blocked semop");
        assert(!result);
    } else while (!__atomic_load_n(&released,__ATOMIC_ACQUIRE)) __asm__ volatile("yield");
    return original_try(client,call);
}
static long invoke(void) {
    struct stat st;
    long result=((long (*)(long,const char *,void *,long))code)(-100,"/",&st,0);
    assert(!result && S_ISDIR(st.st_mode)); return result;
}
static void populate(void) {
    memcpy(code,program,sizeof(program));
    __builtin___clear_cache((char *)code,(char *)code+sizeof(program));
    assert(!mprotect(code,page,PROT_READ|PROT_EXEC|(writable ? PROT_WRITE : 0)));
}
static int change(void *unused) {
    (void)unused;
    assert(!mprotect(code,page,PROT_READ|PROT_WRITE));
    assert(!memcmp(code,program,sizeof(program)));
    populate(); invoke(); return 0;
}
static void joined(pid_t pid) {
    int status;
    assert(pid>0 && waitpid(pid,&status,0)==pid && WIFEXITED(status) && !WEXITSTATUS(status));
}
static void *invoker(void *unused) { (void)unused; invoke(); return NULL; }
static void *mapper(void *unused) {
    (void)unused;
    assert(!mprotect(code,page,PROT_READ|PROT_EXEC));
    __atomic_store_n(&mapped,1,__ATOMIC_RELEASE); return NULL;
}
static void drain(struct md_svc_payload_state *state,int die,int ipc) {
    if (ipc) {
        semaphore=(int)syscall(SYS_semget,IPC_PRIVATE,1,IPC_CREAT|0600);
        assert(semaphore>=0 && !syscall(SYS_semctl,semaphore,0,SETVAL,0));
    }
    const struct md_entry_api *saved=state->api;
    struct md_entry_api api=*saved;
    original_try=api.try_syscall; api.try_syscall=paused_try; state->api=&api;
    pthread_t worker,writer;
    assert(!pthread_create(&worker,NULL,invoker,NULL));
    while (!__atomic_load_n(&entered,__ATOMIC_ACQUIRE)) sched_yield();
    if (ipc) {
        long waiting;
        do { waiting=syscall(SYS_semctl,semaphore,0,GETNCNT,0); assert(waiting>=0); }
        while (!waiting);
    }
    assert(!pthread_create(&writer,NULL,mapper,NULL));
    while (__atomic_load_n(code,__ATOMIC_ACQUIRE)!=program[0]) sched_yield();
    assert(!__atomic_load_n(&mapped,__ATOMIC_ACQUIRE));
    if (die) { puts("PASS SVC lifecycle: death while draining"); fflush(stdout); _exit(0); }
    __atomic_store_n(&released,1,__ATOMIC_RELEASE);
    if (ipc) {
        struct sembuf give={.sem_op=1};
        assert(!syscall(SYS_semop,semaphore,&give,1));
    }
    assert(!pthread_join(worker,NULL) && !pthread_join(writer,NULL));
    assert(mapped); state->api=saved;
    if (ipc) assert(!syscall(SYS_semctl,semaphore,0,IPC_RMID,0));
}
static void debugger(void) {
    int ready[2]; assert(!pipe(ready));
    pid_t parent=getpid(),pid=fork(); assert(pid>=0);
    if (!pid) {
        assert(!close(ready[0]));
        long attached=ptrace(PTRACE_SEIZE,parent,NULL,(void *)PTRACE_O_TRACESYSGOOD);
        if (attached) perror("lifecycle PTRACE_SEIZE");
        assert(!attached);
        assert(!ptrace(PTRACE_INTERRUPT,parent,NULL,NULL));
        int status;
        assert(waitpid(parent,&status,0)==parent && WIFSTOPPED(status));
        struct user_pt_regs regs; struct iovec io={&regs,sizeof(regs)};
        assert(!ptrace(PTRACE_GETREGSET,parent,(void *)NT_PRSTATUS,&io));
        assert(!(regs.sp>=MD_SVC_POOL_BASE && regs.sp<MD_SVC_PAYLOAD_STATE));
        errno=0; unsigned long word=ptrace(PTRACE_PEEKTEXT,parent,code,NULL);
        assert(!errno && (uint32_t)word==program[0] && (uint32_t)(word>>32)==program[1]);
        assert(!ptrace(PTRACE_POKETEXT,parent,code,(void *)word));
        assert(!ptrace(PTRACE_DETACH,parent,NULL,NULL));
        assert(write(ready[1],"x",1)==1); _exit(0);
    }
    assert(!close(ready[1]));
    char byte; assert(read(ready[0],&byte,1)==1); assert(!close(ready[0]));
    joined(pid); assert(code[0]==program[0]); invoke();
}
int main(int argc,char **argv) {
    assert(argc>=3); alarm(30); page=(size_t)sysconf(_SC_PAGESIZE);
    if (!strcmp(argv[2],"executed")) {
        unsigned char resident;
        errno=0;
        assert(mincore((void *)MD_SVC_PAYLOAD_STATE,page,&resident)==-1 && errno==ENOMEM);
        puts("PASS SVC lifecycle: exec discarded old payload"); return 0;
    }
    uintptr_t hint=((uintptr_t)main+0x2000000)&~(page-1);
    writable=!strcmp(argv[2],"writable");
    int shared=!strcmp(argv[2],"shared");
    code=mmap((void *)hint,page,PROT_READ|PROT_WRITE,(shared ? MAP_SHARED : MAP_PRIVATE)|MAP_ANONYMOUS,-1,0);
    assert(code!=MAP_FAILED); populate();
    for (unsigned i=0;i<1024;++i) invoke();
    struct md_svc_payload_state *state=(void *)MD_SVC_PAYLOAD_STATE;
    if (writable || shared) {
        assert(!state->window.magic && !state->completed && !memcmp(code,program,sizeof(program)));
        puts("PASS SVC lifecycle: mutable mapping declined"); return 0;
    }
    assert(state->window.magic==MD_SVC_SIGNAL_MAGIC && state->window.edge.call==(uintptr_t)code);
    assert(code[0]==state->window.replacement && code[0]!=program[0]);
    const char *mode=argv[2];
    if (!strcmp(mode,"protect")) change(NULL);
    else if (!strcmp(mode,"drain") || !strcmp(mode,"drain-death") || !strcmp(mode,"drain-ipc"))
        drain(state,!strcmp(mode,"drain-death"),!strcmp(mode,"drain-ipc"));
    else if (!strcmp(mode,"debugger")) debugger();
    else if (!strcmp(mode,"pid-namespace")) {
        for (unsigned i=0;i<4;++i) {
            pid_t owner=fork(); assert(owner>=0);
            if (!owner) {
                assert(!unshare(CLONE_NEWPID));
                pid_t init=fork(); assert(init>=0);
                if (!init) {
                    assert(getpid()==1 && syscall(SYS_gettid)==1);
                    uint64_t before=state->completed;
                    for (unsigned call=0;call<64;++call) invoke();
                    assert(state->completed==before+64); _exit(0);
                }
                joined(init); _exit(0);
            }
            joined(owner);
        }
        invoke(); change(NULL);
    }
    else if (!strcmp(mode,"fork")) {
        pid_t pid=fork(); assert(pid>=0);
        if (!pid) _exit(change(NULL));
        joined(pid);
        assert(code[0]==state->window.replacement); invoke(); change(NULL);
    } else if (!strcmp(mode,"clone-vm") || !strcmp(mode,"vfork")) {
        void *stack=mmap(NULL,1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(stack!=MAP_FAILED);
        joined(clone(change,(char *)stack+1024*1024,CLONE_VM|SIGCHLD
            |(!strcmp(mode,"vfork") ? CLONE_VFORK : 0),NULL));
        assert(code[0]==program[0]); invoke(); assert(!munmap(stack,1024*1024));
    } else if (!strcmp(mode,"remap")) {
        void *destination=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(destination!=MAP_FAILED);
        code=mremap(code,page,page,MREMAP_FIXED|MREMAP_MAYMOVE,destination);
        assert(code==destination && !memcmp(code,program,sizeof(program))); invoke();
    } else if (!strcmp(mode,"unmap") || !strcmp(mode,"replace")) {
        if (!strcmp(mode,"unmap")) assert(!munmap(code,page));
        assert(mmap(code,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==code);
        assert(!code[0]); populate(); invoke();
    } else if (!strcmp(mode,"discard")) {
        assert(!madvise(code,page,MADV_DONTNEED) && !code[0]);
        assert(!mprotect(code,page,PROT_READ|PROT_WRITE)); populate(); invoke();
    } else if (!strcmp(mode,"exec")) {
        execl(argv[0],argv[0],argv[1],"executed",NULL); assert(0);
    } else if (!strcmp(mode,"thread-exec")) {
        arguments=argv; pthread_t worker;
        assert(!pthread_create(&worker,NULL,execute,NULL));
        pthread_join(worker,NULL); assert(0);
    } else assert(0 && "unknown lifecycle mode");
    assert(!munmap(code,page));
    printf("PASS SVC lifecycle: %s, completed=%" PRIu64 "\n",mode,state->completed);
}
