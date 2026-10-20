#define _GNU_SOURCE
#include "svc_patch.h"
#include "cooperative_entry.h"
#include "svc_borrowed.h"
#include "svc_edge.h"
#include <asm/hwcap.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <ucontext.h>

struct frame { uint64_t x[31],nzcv,fpcr,fpsr,complete,fallback; unsigned char q[512]; };
_Static_assert(sizeof(struct frame)==800,"assembly frame");
extern long md_svc_lab_raw(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,long);
extern char md_svc_lab_call[],md_svc_lab_stub[],md_svc_lab_context_return[];
extern char md_svc_lab_integer_stub[];
extern char md_svc_lab_borrowed_stub[];
extern char md_svc_lab_pair_stub[];
extern void md_svc_lab_context(const struct frame *,struct frame *);
extern long md_svc_lab_small_stack(void *,const char *,struct stat *);
extern long md_svc_lab_edge_raw(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,long);
extern uint32_t md_svc_lab_work_edge[],md_svc_lab_context_edge[],md_svc_lab_small_edge[],md_svc_lab_tls_edge[];
extern char md_svc_lab_load_call[];
extern uint32_t md_svc_lab_fault_edge[];
extern long md_svc_lab_load_stack(void *);
static const struct md_entry_api *api;
static _Thread_local _Alignas(64) struct md_entry_client client;
static _Thread_local unsigned long completed,declined;
static char path[4096];
static int edge_mode;
static unsigned single_register;
static struct md_svc_edge edges[5];
static struct { long tid; struct md_entry_client *client; unsigned long completed; } detached;

/* The fixture has a pthread TLS contract. It does NOT establish that an
 * arbitrary executable has one; the separate census records zero-TLS calls. */
static int invoke_client(struct md_entry_client *owner,struct md_entry_call *call) {
    if (!api || !md_entry_offered(api,call->number,MD_ENTRY_ORDINARY)) return 0;
    enum md_entry_outcome outcome=api->try_syscall(owner,call);
    for (;;) {
        md_entry_step_fn next=call->next;
        if (outcome==MD_ENTRY_DECLINED) return 0;
        if (outcome==MD_ENTRY_COMPLETED) return 1;
        if (outcome==MD_ENTRY_KERNEL_CALL) {
            /* A revoked/filtered channel has no pending effect. Execute the
             * application's original SVC, not a helper syscall or new IP. */
            if (!next) return 0;
            assert(call->kernel);
            call->result=call->kernel(call->number,call->args);
        } else if (outcome==MD_ENTRY_NATIVE_EFFECT) {
            assert(call->effect && next); call->effect(call->effect_context);
        } else {
            /* UNKNOWN cannot be replayed. The lab deliberately has no libc
             * cancellation/unwind integration and never advertises it. */
            assert(0 && "unhandled cooperative outcome");
        }
        assert(next); outcome=next(owner,call);
    }
}
static int invoke(struct md_entry_call *call) { return invoke_client(&client,call); }
int md_svc_lab_dispatch(struct frame *f) {
    struct md_entry_call call={.number=(int)f->x[8],
        .args={f->x[0],f->x[1],f->x[2],f->x[3],f->x[4],f->x[5]}};
    uintptr_t tls;
    __asm__ volatile("mrs %0,tpidr_el0" : "=r"(tls));
    if (!tls) {
        /* Controlled no-TLS fixture, with the owner prepared before entry.
         * This is NOT a task-discovery policy: filtered unknown callers must
         * not acquire identity through an unconditionally executed gettid. */
        register long tid __asm__("x0");
        register long nr __asm__("x8")=SYS_gettid;
        __asm__ volatile("svc #0" : "=r"(tid) : "r"(nr) : "memory","cc");
        if (tid!=detached.tid) __builtin_trap();
        if (!invoke_client(detached.client,&call)) return 0;
        f->x[0]=(uint64_t)call.result; ++detached.completed; return 1;
    }
    if (!invoke(&call)) { ++declined; return 0; }
    f->x[0]=(uint64_t)call.result; ++completed; return 1;
}
static long source(long nr,uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
    struct md_entry_call call={.number=(int)nr,.args={a,b,c,d}};
    if (invoke(&call)) { ++completed; return call.result; }
    ++declined; return md_svc_lab_raw(a,b,c,d,0,0,nr);
}
static long raw(long nr,uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
    if (edge_mode) return md_svc_lab_edge_raw(a,b,c,d,0,0,nr);
    return md_svc_lab_raw(a,b,c,d,0,0,nr);
}
static void borrowed_pool(void) {
    assert(getauxval(AT_HWCAP)&HWCAP_ATOMICS);
    size_t size=MD_SVC_SLOT_SIZE*MD_SVC_SLOT_COUNT;
    void *base=(void *)MD_SVC_POOL_BASE;
    assert(mmap(base,size,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==base);
    for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i) {
        char *slot=(char *)base+i*MD_SVC_SLOT_SIZE;
        assert(!mprotect(slot,16384,PROT_READ|PROT_WRITE));
        assert(!mprotect(slot+32768,32768,PROT_READ|PROT_WRITE));
    }
}
static void replace_instruction(uintptr_t site,uint32_t instruction) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uintptr_t base=site&~(page-1);
    void *copy=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(copy!=MAP_FAILED);
    memcpy(copy,(void *)base,page);
    *(uint32_t *)((char *)copy+site-base)=instruction;
    __builtin___clear_cache(copy,(char *)copy+page);
    assert(!mprotect(copy,page,PROT_READ|PROT_EXEC));
    /* The fixture owns an isolated text page and has not started peers yet.
     * Anonymous publication also avoids Android's file-backed execmod ban. */
    assert(mremap(copy,page,page,MREMAP_MAYMOVE|MREMAP_FIXED,(void *)base)==(void *)base);
}
static void patch(int integer,int borrowed) {
    uintptr_t site=(uintptr_t)md_svc_lab_call-(borrowed==2 ? 8 : 4);
    uint32_t branch;
    void *stub=borrowed==2 ? md_svc_lab_pair_stub : borrowed ? md_svc_lab_borrowed_stub
        : integer ? md_svc_lab_integer_stub : md_svc_lab_stub;
    if (borrowed) borrowed_pool();
    assert(!md_svc_branch(site,(uintptr_t)stub,&branch));
    replace_instruction(site,branch);
}
static void patch_edges(void) {
    borrowed_pool();
    size_t page=(size_t)sysconf(_SC_PAGESIZE),size=md_svc_edge_size();
    assert(size*5<=page);
    unsigned char *code=mmap((void *)0x3000000,page,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(code==(void *)0x3000000);
    uint32_t *calls[]={md_svc_lab_work_edge,md_svc_lab_context_edge,md_svc_lab_small_edge,
        md_svc_lab_tls_edge,md_svc_lab_fault_edge};
    uint32_t replacements[5];
    for (unsigned i=0;i<5;++i) {
        uint32_t instruction=*calls[i];
        int64_t relative=(int64_t)((uint64_t)(instruction&0x03ffffff)<<38)>>36;
        uintptr_t callee=(uintptr_t)calls[i]+relative;
        const uint32_t *prefix=(const void *)callee;
        size_t count=0;
        while (count<17 && prefix[count]!=0xd4000001) ++count;
        assert(count<17);
        assert(!md_svc_edge_plan((uintptr_t)calls[i],instruction,callee,prefix,count+1,
            (uintptr_t)(code+i*size),(uintptr_t)md_svc_lab_dispatch,MD_SVC_POOL_BASE,code+i*size,size,&replacements[i],&edges[i]));
    }
    __builtin___clear_cache((char *)code,(char *)code+page);
    assert(!mprotect(code,page,PROT_READ|PROT_EXEC));
    for (unsigned i=0;i<5;++i) replace_instruction((uintptr_t)calls[i],replacements[i]);
}
static void *fault_page;
static size_t fault_page_size;
static volatile sig_atomic_t prefix_faults;
static void prefix_fault(int number,siginfo_t *info,void *context) {
    ucontext_t *uc=context;
    uintptr_t original=md_svc_edge_prefix_pc(&edges[4],uc->uc_mcontext.pc);
    if (number!=SIGSEGV || original!=edges[4].callee+20 || info->si_addr!=fault_page
            || uc->uc_mcontext.regs[4]!=0x4567 || uc->uc_mcontext.regs[5]!=0x5678
            || uc->uc_mcontext.regs[30]!=edges[4].call+4) _exit(97);
    uintptr_t sp=uc->uc_mcontext.sp;
    unsigned index=(unsigned)((sp^(sp>>16))>>8)&63;
    uintptr_t *lock=(void *)(MD_SVC_POOL_BASE+index*MD_SVC_SLOT_SIZE);
    if (!__atomic_load_n(lock,__ATOMIC_ACQUIRE)) _exit(96);
    __atomic_store_n(lock,0,__ATOMIC_RELEASE);
    uc->uc_mcontext.pc=original;
    if (mprotect(fault_page,fault_page_size,PROT_READ|PROT_WRITE)) _exit(95);
    ++prefix_faults;
}
static void edge_fault(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *area=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(area!=MAP_FAILED);
    void *alternate=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(alternate!=MAP_FAILED);
    stack_t old,stack={.ss_sp=alternate,.ss_size=65536};
    assert(!sigaltstack(&stack,&old));
    struct stat st;
    uint64_t *sp=(void *)(area+page-48);
    sp[1]=SYS_newfstatat; sp[2]=AT_FDCWD; sp[3]=(uintptr_t)path; sp[4]=(uintptr_t)&st; sp[5]=0;
    fault_page=area+page; fault_page_size=page;
    assert(!mprotect(fault_page,page,PROT_NONE));
    struct sigaction saved,action={.sa_sigaction=prefix_fault,.sa_flags=SA_SIGINFO|SA_ONSTACK};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGSEGV,&action,&saved));
    assert(!md_svc_lab_load_stack(sp) && st.st_size==4 && prefix_faults==1);
    for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i)
        assert(!*(uintptr_t *)(MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE));
    assert(!sigaction(SIGSEGV,&saved,NULL) && !sigaltstack(&old,NULL));
    assert(!munmap(alternate,65536) && !munmap(area,2*page));
    puts("PASS SVC edge fault: original PC, old destination registers, LR, retry and frame release");
}
static void context_number(uint64_t number,int success) {
    struct frame before={0},after={0}; struct stat st;
    for (unsigned i=0;i<31;++i) before.x[i]=UINT64_C(0x1234000087650000)+i;
    for (unsigned i=0;i<512;++i) before.q[i]=(unsigned char)(i*29+7);
    before.x[0]=AT_FDCWD; before.x[1]=(uintptr_t)path; before.x[2]=(uintptr_t)&st;
    before.x[3]=0; before.x[6]=number; before.x[8]=number;
    before.x[7]=0;
    before.x[30]=(uintptr_t)md_svc_lab_context_return;
    if (single_register && single_register!=8)
        before.x[single_register==9 ? 10 : 9]=before.x[single_register];
    before.nzcv=0xa0000000; before.fpcr=0; before.fpsr=0x10;
    md_svc_lab_context(&before,&after);
    if (success) assert(!after.x[0] && st.st_size==4);
    else assert((int64_t)after.x[0]<0);
    for (unsigned i=1;i<31;++i) assert(before.x[i]==after.x[i]);
    assert(before.nzcv==after.nzcv && before.fpcr==after.fpcr && before.fpsr==after.fpsr);
    assert(!memcmp(before.q,after.q,sizeof(before.q)));
}
static void context(void) { context_number(SYS_newfstatat,1); }
static void single_registers(void) {
    borrowed_pool();
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uintptr_t base=0x3000000;
    uint32_t original=*md_svc_lab_context_edge;
    for (unsigned reg=1;reg<=29;++reg) {
        unsigned char *code=mmap((void *)base,page,PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
        assert(code==(void *)base);
        uint32_t prefix=reg==8 ? 0xd28009e8 : 0xaa0003e0|((reg==9 ? 10u : 9u)<<16)|reg;
        uint32_t instructions[]={prefix,0xd4000001,0xd65f03c0};
        memcpy(code,instructions,sizeof(instructions));
        uint32_t branch,replacement;
        struct md_svc_edge entry;
        assert(!md_svc_single_plan(base+4,prefix,base+64,(uintptr_t)md_svc_lab_dispatch,MD_SVC_POOL_BASE,
            code+64,page-64,&replacement,&entry));
        __builtin___clear_cache((char *)code,(char *)code+page);
        assert(!mprotect(code,page,PROT_READ|PROT_EXEC));
        assert(!md_svc_branch((uintptr_t)md_svc_lab_context_edge,base,&branch));
        replace_instruction((uintptr_t)md_svc_lab_context_edge,branch|0x80000000);
        single_register=reg;
        context();
        replace_instruction(base,replacement);
        unsigned long count=completed;
        for (unsigned i=0;i<32;++i) context();
        if (api) assert(completed==count+32);
        assert(!munmap(code,page));
    }
    single_register=0;
    replace_instruction((uintptr_t)md_svc_lab_context_edge,original);
    puts("PASS SVC register entries: x1..x29, GPR/NZCV/SIMD preservation and actual completion");
}
static void busy_slots(int pair) {
    for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i) {
        uintptr_t *slot=(void *)(MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE);
        slot[0]=i+1; slot[1]=UINT64_MAX-i;
    }
    unsigned long start=completed;
    context();
    assert(completed==start);
    for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i) {
        uintptr_t *slot=(void *)(MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE);
        assert(slot[0] && (!pair || slot[0]==i+1));
        assert(slot[1]==UINT64_MAX-i); slot[0]=0;
    }
    context_number(0,0); context_number(UINT64_MAX,0); context_number(UINT64_MAX-1,0);
    puts("PASS SVC borrowed: busy frames untouched; zero and all-ones last register restored");
}
static void filter(unsigned flags,unsigned action) {
    uintptr_t ip=(uintptr_t)md_svc_lab_call+4;
    uintptr_t other=(uintptr_t)md_svc_lab_load_call+4;
    assert((ip>>32)==(other>>32));
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_gettid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_newfstatat,0,6),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(ip>>32),0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)ip,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)other,0,2),
        BPF_STMT(BPF_RET|BPF_K,action),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,flags,&program));
}
static pthread_barrier_t rendezvous;
static void barrier(void) {
    int r=pthread_barrier_wait(&rendezvous); assert(!r || r==PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *filtered(void *unused) {
    (void)unused;
    context(); filter(0,SECCOMP_RET_ERRNO|EACCES); barrier();
    struct stat st;
    for (unsigned i=0;i<512;++i) assert(raw(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0)==-EACCES);
    barrier(); return NULL;
}
static void *synchronized_peer(void *unused) {
    (void)unused; context(); barrier(); barrier();
    struct stat st;
    assert(raw(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0)==-EACCES);
    return NULL;
}
static volatile sig_atomic_t signals,signal_error;
static void nested_signal(int number) {
    (void)number; ++signals;
    struct stat st;
    if (raw(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0) || st.st_size!=4) signal_error=1;
}
static void signal_stress(void) {
    struct sigaction action={.sa_handler=nested_signal};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGPROF,&action,NULL));
    struct itimerval timer={.it_interval={0,1000},.it_value={0,1000}};
    assert(!setitimer(ITIMER_PROF,&timer,NULL));
    for (unsigned i=0;i<8192 || signals<8;++i) {
        assert(i<1048576 && !signal_error);
        context();
    }
    timer=(struct itimerval){0}; assert(!setitimer(ITIMER_PROF,&timer,NULL));
    assert(signals && !signal_error);
    printf("PASS SVC signals: %d asynchronous deliveries with nested metadata calls\n",signals);
}
static void trapped(int number,siginfo_t *info,void *context) {
    (void)context;
    if (number!=SIGSYS || (info->si_call_addr!=md_svc_lab_call+4
            && info->si_call_addr!=md_svc_lab_load_call+4)) _exit(99);
    _exit(0);
}
extern long md_svc_lab_without_tls(void *,const char *,struct stat *);
static void small_stack(int patched,int borrowed) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    void *area=mmap(NULL,2*page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(area!=MAP_FAILED && !mprotect((char *)area+page,page,PROT_READ|PROT_WRITE));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct stat st;
        client=(struct md_entry_client){0};
        detached.tid=syscall(SYS_gettid); detached.client=&client;
        long r=borrowed ? md_svc_lab_without_tls((char *)area+page,path,&st)
            : md_svc_lab_small_stack((char *)area+page+16,path,&st);
        if (api && borrowed && detached.completed!=1) _exit(98);
        _exit(r || st.st_size!=4 ? 1 : 0);
    }
    int status; assert(waitpid(child,&status,0)==child);
    if (patched) assert(WIFSIGNALED(status) && WTERMSIG(status)==SIGSEGV);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!munmap(area,2*page));
    printf("SVC_STACK {\"patched\":%s,\"borrowed\":%s,\"zeroTls\":%s,\"guardFault\":%s}\n",
        patched || borrowed ? "true" : "false",borrowed ? "true" : "false",
        borrowed ? "true" : "false",patched ? "true" : "false");
}
static void checks(void) {
    context();
    signal_stress();
    assert(!pthread_barrier_init(&rendezvous,NULL,2));
    pthread_t peer; assert(!pthread_create(&peer,NULL,filtered,NULL));
    barrier(); unsigned long start=completed;
    for (unsigned i=0;i<512;++i) context();
    if (api) assert(completed-start==512);
    barrier(); assert(!pthread_join(peer,NULL)); pthread_barrier_destroy(&rendezvous);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        client=(struct md_entry_client){0}; context();
        assert(!pthread_barrier_init(&rendezvous,NULL,2));
        pthread_t second; assert(!pthread_create(&second,NULL,synchronized_peer,NULL));
        barrier(); filter(SECCOMP_FILTER_FLAG_TSYNC,SECCOMP_RET_ERRNO|EACCES); barrier();
        struct stat st;
        assert(raw(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0)==-EACCES);
        assert(!pthread_join(second,NULL));
        _exit(0);
    }
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    for (unsigned trap=0;trap<2;++trap) {
        child=fork(); assert(child>=0);
        if (!child) {
            client=(struct md_entry_client){0};
            struct sigaction action={.sa_sigaction=trapped,.sa_flags=SA_SIGINFO};
            sigemptyset(&action.sa_mask); assert(!sigaction(SIGSYS,&action,NULL));
            filter(0,trap ? SECCOMP_RET_TRAP : SECCOMP_RET_ERRNO|EACCES);
            struct stat st;
            assert(raw(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0)==-EACCES);
            _exit(trap ? 98 : 0);
        }
        assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    }
    puts("PASS SVC gate: GPR, SIMD, NZCV, FPCR/FPSR; mixed thread filters, original IP, denied gettid, TSYNC and fork");
}
static uint64_t now(void) {
    struct timespec ts; assert(!clock_gettime(CLOCK_MONOTONIC,&ts));
    return (uint64_t)ts.tv_sec*1000000000+ts.tv_nsec;
}
int main(int argc,char **argv) {
    assert(argc>=3); alarm(120);
    api=(void *)getauxval(MD_AT_COOPERATIVE);
    if (api) assert(md_entry_api_valid(api));
    assert(snprintf(path,sizeof(path),"%s/svc-file",argv[1])<(int)sizeof(path));
    int fd=open(path,O_CREAT|O_RDWR|O_TRUNC,0600); assert(fd>=0 && write(fd,"test",4)==4 && !close(fd));
    if (!strcmp(argv[2],"single-check")) { single_registers(); return 0; }
    int integer=!strcmp(argv[2],"integer") || !strcmp(argv[2],"integer-check");
    int borrowed=!strcmp(argv[2],"borrowed") || !strcmp(argv[2],"borrowed-check") || !strcmp(argv[2],"stack-borrowed");
    edge_mode=!strcmp(argv[2],"edge") || !strcmp(argv[2],"edge-check") || !strcmp(argv[2],"stack-edge");
    if (!strcmp(argv[2],"pair") || !strcmp(argv[2],"pair-check") || !strcmp(argv[2],"stack-pair")) borrowed=2;
    int patched=borrowed || integer || !strcmp(argv[2],"patch") || !strcmp(argv[2],"check") || !strcmp(argv[2],"stack-patch");
    if (patched) patch(integer,borrowed);
    if (edge_mode) patch_edges();
    if (!strcmp(argv[2],"stack-borrowed") || !strcmp(argv[2],"stack-pair") || !strcmp(argv[2],"stack-edge")) { small_stack(0,1); return 0; }
    if (!strcmp(argv[2],"stack-patch") || !strcmp(argv[2],"stack-base")) { small_stack(patched,0); return 0; }
    if (!strcmp(argv[2],"check") || !strcmp(argv[2],"integer-check") || !strcmp(argv[2],"borrowed-check")
            || !strcmp(argv[2],"pair-check") || !strcmp(argv[2],"edge-check")) {
        if (borrowed) busy_slots(borrowed==2);
        if (edge_mode) edge_fault();
        checks(); return 0;
    }
    long (*call)(long,uint64_t,uint64_t,uint64_t,uint64_t)=!strcmp(argv[2],"source") ? source : raw;
    const char *workload=argc>3 ? argv[3] : "stat";
    unsigned count=argc>4 ? (unsigned)strtoul(argv[4],NULL,10) : 32768;
    int sandbox=argc>5 && !strcmp(argv[5],"sandbox");
    char temporary[4096],renamed[4096];
    assert(snprintf(temporary,sizeof(temporary),"%s/svc-new",argv[1])<(int)sizeof(temporary));
    assert(snprintf(renamed,sizeof(renamed),"%s/svc-renamed",argv[1])<(int)sizeof(renamed));
    struct stat st;
    for (unsigned i=0;i<128;++i) assert(!call(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0));
    if (sandbox) {
        /* Real kernel filter, including an IP check and forbidden helper
         * syscall. Revocation must occur before entering the measured loop. */
        filter(0,SECCOMP_RET_ALLOW);
        completed=declined=0;
    }
    uint64_t begin=now();
    for (unsigned i=0;i<count;++i) {
        if (!strcmp(workload,"stat")) assert(!call(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0));
        else if (!strcmp(workload,"opens")) {
            long file=call(SYS_openat,AT_FDCWD,(uintptr_t)path,O_RDONLY,0); assert(file>=0);
            assert(!call(SYS_close,(unsigned long)file,0,0,0));
        } else if (!strcmp(workload,"mutations")) {
            long file=call(SYS_openat,AT_FDCWD,(uintptr_t)temporary,O_WRONLY|O_CREAT|O_EXCL,0600);
            assert(file>=0 && !call(SYS_close,(unsigned long)file,0,0,0));
            assert(!call(SYS_renameat,AT_FDCWD,(uintptr_t)temporary,AT_FDCWD,(uintptr_t)renamed));
            assert(!call(SYS_unlinkat,AT_FDCWD,(uintptr_t)renamed,0,0));
        } else assert(0 && "unknown workload");
    }
    uint64_t elapsed=now()-begin;
    if (!strcmp(workload,"mutations")) {
        assert(stat(temporary,&st)<0 && errno==ENOENT);
        assert(stat(renamed,&st)<0 && errno==ENOENT);
    }
    printf("SVC_BENCH {\"mode\":\"%s\",\"workload\":\"%s\",\"provider\":%s,\"sandbox\":%s,\"iterations\":%u,"
        "\"ns\":%" PRIu64 ",\"completed\":%lu,\"declined\":%lu}\n",
        argv[2],workload,api ? "true" : "false",sandbox ? "true" : "false",count,elapsed,completed,declined);
    return 0;
}
