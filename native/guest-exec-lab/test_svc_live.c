#define _GNU_SOURCE
#include "svc_direct.h"
#include "svc_patch.h"
#include "svc_payload.h"
#include "svc_live_body.h"
#include "svc_text.h"
#include "svc_filter.h"
#include "interception.h"
#include <asm/hwcap.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <limits.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

struct frame { uint64_t x[31],nzcv,fpcr,fpsr,complete,fallback; unsigned char q[512]; };
extern unsigned char md_svc_lab_call[],md_svc_lab_context_return[],md_svc_live_miss[];
extern unsigned char md_svc_live_declined[],md_svc_live_busy[];
extern void md_svc_lab_context(const struct frame *,struct frame *);
extern long md_svc_lab_without_tls(void *,const char *,struct stat *);
extern long md_svc_lab_raw(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,long);
__asm__(".text\n.balign 4\n.global md_svc_live_miss\nmd_svc_live_miss:\nbrk #0x4d53\nb .\n");
__asm__(".text\n.balign 4\n.global md_svc_live_declined\nmd_svc_live_declined:\nbrk #0x4d54\nb .\n");
__asm__(".text\n.balign 4\n.global md_svc_live_busy\nmd_svc_live_busy:\nbrk #0x4d55\nb .\n");
static char path[4096];
static int memfd;
static unsigned retired,writing,stop,ready;
static uint64_t native_completed,misses;
static unsigned publications;
static uint64_t miss_reasons[3];
static uint32_t branches[2];
static uint32_t mapping_branches[2];
static const uintptr_t mapping_sites[2]={0x3400000,0x3420000};
static uintptr_t mapped_function;
static void *fixture_stacks;
static _Thread_local _Alignas(64) void *fixture_stack;
static unsigned mapping_faults,mapping_changes,mapping_replacements;
static struct md_svc_text *fault_text;
static struct md_svc_text main_text={.fd=-1};
static struct md_svc_text file_text={.fd=-1};
extern unsigned char md_svc_live_open[],md_svc_live_close[],md_svc_live_rename[],md_svc_live_unlink[];
static unsigned char *const file_entries[]={md_svc_live_open,md_svc_live_close,md_svc_live_rename,md_svc_live_unlink};
static const long file_numbers[]={SYS_openat,SYS_close,SYS_renameat,SYS_unlinkat};
static uint32_t file_branches[4];
static unsigned char *code;
static struct md_svc_payload_state *payload;
static uint64_t progress[8];
static volatile sig_atomic_t async_traps,filtering,traps_during_filter;
static unsigned sender_stop,sender_ready;
static pid_t receiver,group;
struct body_context {
    unsigned block,entered;
    uintptr_t callback;
    struct md_svc_payload_state *state;
};
static struct md_svc_live_body live_body;
static struct body_context body_context;
static uint64_t body_calls,body_fallbacks;
static unsigned body_done,body_reclaims;
static uintptr_t entry_witness_pc;
static uint32_t entry_witness_branch;
static unsigned entry_waiting,entry_block=1;
static uintptr_t cold_signal_pc;
static volatile sig_atomic_t cold_signal_seen;
extern const unsigned char md_svc_live_body_begin[],md_svc_live_body_end[];
extern long md_svc_live_stack_call(void *,uintptr_t,const char *,struct stat *);
extern void md_svc_live_context_call(void *,const struct frame *,struct frame *);
static void fixture_stack_select(unsigned index) {
    if (fixture_stacks) fixture_stack=(char *)fixture_stacks+index*65536+16384+index*512;
}
static long raw_call(long number,const uint64_t *args) {
    register long r0 __asm__("x0")=args[0],r1 __asm__("x1")=args[1],r2 __asm__("x2")=args[2];
    register long r3 __asm__("x3")=args[3],r4 __asm__("x4")=args[4],r5 __asm__("x5")=args[5];
    register long nr __asm__("x8")=number;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r3),"r"(r4),"r"(r5),"r"(nr) : "memory","cc");
    return r0;
}
int md_svc_lab_dispatch(void *unused) { (void)unused; __builtin_trap(); }
static int direct_dispatch(uint64_t *regs,struct md_svc_payload_state *state) {
    if (!__atomic_load_n(&state->admitted,__ATOMIC_ACQUIRE)) return 0;
    if (state->api) return md_svc_payload_dispatch(regs,state);
    regs[0]=raw_call((long)regs[8],regs);
    __atomic_fetch_add(&native_completed,1,__ATOMIC_RELAXED);
    return 1;
}
static int lifetime_dispatch(uint64_t *regs,struct md_svc_payload_state *state) {
    uintptr_t entry;
    void *context;
    if (!md_svc_live_body_acquire(&live_body,&entry,&context)) {
        __atomic_fetch_add(&body_fallbacks,1,__ATOMIC_RELAXED);
        return direct_dispatch(regs,state);
    }
    int result=((int (*)(uint64_t *,void *))entry)(regs,context);
    __atomic_fetch_add(&body_calls,1,__ATOMIC_RELAXED);
    md_svc_live_body_release(&live_body);
    return result;
}
static void write_site(uintptr_t site,uint32_t word) {
    /* This tests Linux's four-byte forced write plus its executable-page cache
     * maintenance. It is not an assertion that arbitrary kernel memcpy
     * implementations provide an atomic code-publication ABI. */
    assert(pwrite(memfd,&word,sizeof(word),(off_t)site)==sizeof(word));
}
static void store_instruction(uint32_t word) {
    if (main_text.writer) assert(!md_svc_text_publish(&main_text,(uintptr_t)md_svc_lab_call,word));
    else write_site((uintptr_t)md_svc_lab_call,word);
}
static void miss(int number,siginfo_t *info,void *context) {
    if (number==SIGTRAP && info->si_code<=0) {
        ++async_traps;
        if (filtering) ++traps_during_filter;
        return;
    }
    ucontext_t *uc=context;
    uintptr_t pc=uc->uc_mcontext.pc;
    if (number==SIGTRAP && info->si_code==TRAP_BRKPT && pc>=(uintptr_t)code+57344
            && pc<(uintptr_t)code+57344+4*16) {
        /* A benchmark must fail, not quietly measure a retired Base path.
         * Encode the site and cold-exit reason in its process exit status. */
        _exit(96+(int)(pc-(uintptr_t)code-57344)/4);
    }
    if (number==SIGTRAP && info->si_code==TRAP_BRKPT && pc==entry_witness_pc) {
        __atomic_store_n(&entry_waiting,1,__ATOMIC_RELEASE);
        /* EVENT_WAIT: a saved signal continuation precedes body acquisition.
         * The test releases it explicitly; alarm rejects a missing release. */
        while (__atomic_load_n(&entry_block,__ATOMIC_ACQUIRE)) {
            uint64_t args[]={(uintptr_t)&entry_block,FUTEX_WAIT_PRIVATE,1,0,0,0};
            long result=raw_call(SYS_futex,args);
            if (result && result!=-EAGAIN && result!=-EINTR) _exit(93);
        }
        uc->uc_mcontext.pc+=4;
        return;
    }
    if (number==SIGTRAP && info->si_code==TRAP_BRKPT && fault_text
            && pc>=(uintptr_t)code+32768 && pc<(uintptr_t)code+32780) {
        unsigned reason=(unsigned)(pc-(uintptr_t)code-32768)/4;
        __atomic_fetch_add(&miss_reasons[reason],1,__ATOMIC_RELAXED);
        if (md_svc_text_publish(fault_text,fault_text->address+4,UINT32_C(0xd4000001))) _exit(95);
        __atomic_store_n(&retired,1,__ATOMIC_RELEASE);
        __atomic_fetch_add(&misses,1,__ATOMIC_RELAXED);
        uc->uc_mcontext.pc=fault_text->address+4;
        return;
    }
    if (number!=SIGTRAP || info->si_code!=TRAP_BRKPT || (pc!=(uintptr_t)md_svc_live_miss
            && pc!=(uintptr_t)md_svc_live_declined && pc!=(uintptr_t)md_svc_live_busy)) _exit(90);
    unsigned reason=pc==(uintptr_t)md_svc_live_miss ? 0 : pc==(uintptr_t)md_svc_live_declined ? 1 : 2;
    __atomic_fetch_add(&miss_reasons[reason],1,__ATOMIC_RELAXED);
    /* Cold deoptimization, not a copied SVC at a different seccomp IP. The
     * fixture retires this site; it does not claim a dynamic-number cache yet. */
    __atomic_store_n(&retired,1,__ATOMIC_RELEASE);
    while (__atomic_load_n(&writing,__ATOMIC_ACQUIRE)) __asm__ volatile("yield");
    uint32_t original=UINT32_C(0xd4000001);
    uint64_t args[]={(uint64_t)memfd,(uintptr_t)&original,4,(uintptr_t)md_svc_lab_call,0,0};
    if (main_text.writer) {
        if (md_svc_text_publish(&main_text,(uintptr_t)md_svc_lab_call,original)) _exit(91);
    } else if (raw_call(SYS_pwrite64,args)!=4) _exit(91);
    __atomic_fetch_add(&misses,1,__ATOMIC_RELAXED);
    uc->uc_mcontext.pc=(uintptr_t)md_svc_lab_call;
}
static void alternate_stack(void) {
    void *area=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(area!=MAP_FAILED);
    stack_t stack={.ss_sp=area,.ss_size=65536};
    assert(!sigaltstack(&stack,NULL));
}
static void context(uint64_t number) {
    struct frame input={0},output={0};
    struct stat st;
    for (unsigned i=0;i<31;++i) input.x[i]=UINT64_C(0xabc00000)+i;
    for (unsigned i=0;i<sizeof(input.q);++i) input.q[i]=(unsigned char)(i*17+31);
    input.x[0]=AT_FDCWD; input.x[1]=(uintptr_t)path; input.x[2]=(uintptr_t)&st; input.x[3]=0;
    input.x[6]=number; input.nzcv=UINT64_C(0xa0000000); input.fpcr=UINT64_C(1)<<22;
    input.fpsr=UINT64_C(1)<<4;
    if (fixture_stack) md_svc_live_context_call(fixture_stack,&input,&output);
    else md_svc_lab_context(&input,&output);
    uint64_t args[]={AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0,0,0};
    input.x[0]=raw_call((long)number,args);
    input.x[7]=0; input.x[8]=number; input.x[30]=(uintptr_t)md_svc_lab_context_return;
    assert(!memcmp(&input,&output,sizeof(input)));
    if (number==SYS_newfstatat) assert(st.st_size==4);
}
static void publish(unsigned version) {
    __atomic_store_n(&writing,1,__ATOMIC_RELEASE);
    if (!__atomic_load_n(&retired,__ATOMIC_ACQUIRE)) {
        store_instruction(version ? branches[version-1] : UINT32_C(0xd4000001));
        ++publications;
    }
    __atomic_store_n(&writing,0,__ATOMIC_RELEASE);
}
static void *worker(void *argument) {
    unsigned index=(unsigned)(uintptr_t)argument;
    fixture_stack_select(index+1);
    alternate_stack();
    __atomic_fetch_add(&ready,1,__ATOMIC_RELEASE);
    while (!__atomic_load_n(&stop,__ATOMIC_ACQUIRE)) {
        context(SYS_newfstatat);
        __atomic_fetch_add(&progress[index],1,__ATOMIC_RELAXED);
    }
    stack_t stack;
    assert(!sigaltstack(NULL,&stack));
    stack_t disable={.ss_flags=SS_DISABLE}; assert(!sigaltstack(&disable,NULL));
    assert(!munmap(stack.ss_sp,stack.ss_size));
    return NULL;
}
static void prepare(int lifetime,int mappings,int entry,int files,int kernel,int signal_gate) {
    assert(getauxval(AT_HWCAP)&HWCAP_ATOMICS);
    size_t bytes=MD_SVC_POOL_SIZE+MD_SVC_PAYLOAD_SIZE;
    void *pool=mmap((void *)MD_SVC_POOL_BASE,bytes,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(pool==(void *)MD_SVC_POOL_BASE);
    for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i)
        assert(!mprotect((char *)pool+i*MD_SVC_SLOT_SIZE+16384,16384,PROT_NONE));
    payload=(void *)(MD_SVC_POOL_BASE+MD_SVC_POOL_SIZE);
    payload->api=(void *)getauxval(MD_AT_COOPERATIVE); payload->admitted=1;
    payload->selected_number=SYS_newfstatat;
    assert(!payload->api || md_entry_api_valid(payload->api));
    code=mmap((void *)0x3000000,65536,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(code==(void *)0x3000000);
    size_t size=signal_gate ? md_svc_direct_signal_size() : md_svc_direct_size();
    struct md_svc_direct_fallback exits={(uintptr_t)md_svc_live_miss,(uintptr_t)md_svc_live_declined,(uintptr_t)md_svc_live_busy};
    if (kernel) {
        uintptr_t cold=(uintptr_t)code+61440;
        assert(!md_svc_direct_kernel((uintptr_t)md_svc_lab_call,cold,(uint32_t *)cold));
        exits=(struct md_svc_direct_fallback){cold,cold,cold};
    }
    for (unsigned i=0;i<2;++i) {
        struct md_svc_direct_context c={(uintptr_t)md_svc_lab_call,(uintptr_t)(code+i*4096),
            MD_SVC_POOL_BASE,SYS_newfstatat};
        if (signal_gate) assert(!md_svc_direct_signal_plan(&c,(uintptr_t)direct_dispatch,exits,code+i*4096,4096,&branches[i]));
        else assert(!md_svc_direct_plan((uintptr_t)md_svc_lab_call,SYS_newfstatat,(uintptr_t)(code+i*4096),
            lifetime ? (uintptr_t)lifetime_dispatch : (uintptr_t)direct_dispatch,
            MD_SVC_POOL_BASE,exits,code+i*4096,4096,&branches[i]));
    }
    if (mappings) for (unsigned i=0;i<2;++i) {
        struct md_svc_direct_fallback mapping_exits={
            (uintptr_t)code+32768,(uintptr_t)code+32772,(uintptr_t)code+32776};
        assert(!md_svc_direct_plan(mapping_sites[i]+4,SYS_newfstatat,(uintptr_t)(code+(i+2)*4096),
            (uintptr_t)lifetime_dispatch,MD_SVC_POOL_BASE,mapping_exits,code+(i+2)*4096,4096,&mapping_branches[i]));
    }
    for (unsigned i=0;i<3;++i) {
        uint32_t trap=UINT32_C(0xd4200000)|((UINT32_C(0x4d53)+i)<<5);
        memcpy(code+32768+i*4,&trap,4);
    }
    if (entry) {
        entry_witness_pc=(uintptr_t)(code+24576);
        uint32_t trap=UINT32_C(0xd4200000)|(UINT32_C(0x4d56)<<5),unused;
        memcpy((void *)entry_witness_pc,&trap,4);
        assert(!md_svc_direct_plan((uintptr_t)md_svc_lab_call,SYS_newfstatat,entry_witness_pc+4,
            (uintptr_t)lifetime_dispatch,MD_SVC_POOL_BASE,exits,(void *)(entry_witness_pc+4),4092,&unused));
        assert(!md_svc_branch((uintptr_t)md_svc_lab_call,entry_witness_pc,&entry_witness_branch));
    }
    if (files) for (unsigned i=0;i<4;++i) {
        uintptr_t cold=(uintptr_t)code+57344+i*16;
        struct md_svc_direct_fallback file_exits={cold,cold+4,cold+8};
        for (unsigned reason=0;reason<3;++reason) {
            uint32_t trap=UINT32_C(0xd4200000)|((UINT32_C(0x4d53)+reason)<<5);
            memcpy((void *)(cold+reason*4),&trap,4);
        }
        struct md_svc_direct_context c={(uintptr_t)file_entries[i]+4,(uintptr_t)code+36864+i*4096,
            MD_SVC_POOL_BASE,(uint64_t)file_numbers[i]};
        if (signal_gate) assert(!md_svc_direct_signal_plan(&c,(uintptr_t)direct_dispatch,
            file_exits,code+36864+i*4096,4096,&file_branches[i]));
        else assert(!md_svc_direct_plan((uintptr_t)file_entries[i]+4,(uint64_t)file_numbers[i],
            (uintptr_t)code+36864+i*4096,lifetime ? (uintptr_t)lifetime_dispatch : (uintptr_t)direct_dispatch,
            MD_SVC_POOL_BASE,file_exits,code+36864+i*4096,4096,&file_branches[i]));
    }
    assert(size<=4096);
    __builtin___clear_cache((char *)code,(char *)code+65536);
    assert(!mprotect(code,65536,PROT_READ|PROT_EXEC));
    memfd=open("/proc/self/mem",O_RDWR|O_CLOEXEC); assert(memfd>=0);
    alternate_stack();
    struct sigaction action={.sa_sigaction=miss,.sa_flags=SA_SIGINFO|SA_ONSTACK};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGTRAP,&action,NULL));
}
static uint64_t now(void) {
    struct timespec ts; assert(!clock_gettime(CLOCK_MONOTONIC,&ts));
    return (uint64_t)ts.tv_sec*1000000000+ts.tv_nsec;
}
static void filter_projected_action(uintptr_t ip,int project,uint32_t action) {
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_gettid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_newfstatat,0,6),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(ip>>32),0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)ip,0,1),
        BPF_STMT(BPF_RET|BPF_K,action),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(instructions)/sizeof(*instructions),instructions};
    struct sock_filter projected[BPF_MAXINSNS];
    if (project) {
        struct md_svc_filter_alias alias={(uintptr_t)code+61444,ip};
        size_t written;
        assert(!md_svc_filter_project(instructions,program.len,&alias,1,projected,BPF_MAXINSNS,&written));
        program=(struct sock_fprog){(unsigned short)written,projected};
    }
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
}
static void filter_projected(uintptr_t ip,int project) {
    filter_projected_action(ip,project,SECCOMP_RET_ERRNO|EACCES);
}
static void filter_at(uintptr_t ip) { filter_projected(ip,0); }
static void filter(void) { filter_at((uintptr_t)md_svc_lab_call+4); }
static long call_stat(void) {
    struct stat st;
    uintptr_t target=__atomic_load_n(&mapped_function,__ATOMIC_ACQUIRE);
    typedef long (*raw_entry)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,long);
    raw_entry call=target ? (raw_entry)target : md_svc_lab_raw;
    long result=fixture_stack ? md_svc_live_stack_call(fixture_stack,(uintptr_t)call,path,&st)
        : call(AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0,0,0,SYS_newfstatat);
    if (!result) assert(st.st_size==4);
    return result;
}
static void cold_syscall(int filtered,int unsafe) {
    uint64_t prior=payload->api ? payload->completed : native_completed;
    sigset_t mask,before,observed;
    sigemptyset(&mask); sigaddset(&mask,SIGTRAP);
    assert(!pthread_sigmask(SIG_BLOCK,&mask,&before));
    if (filtered) {
        __atomic_store_n(&payload->admitted,0,__ATOMIC_RELEASE);
        filter_projected((uintptr_t)md_svc_lab_call+4,!unsafe);
        assert(call_stat()==-EACCES);
    } else {
        context((UINT64_C(1)<<40)|SYS_newfstatat);
        context(SYS_getpid);
        for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i)
            __atomic_store_n((uint64_t *)(MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE),1,__ATOMIC_RELEASE);
        context(SYS_newfstatat);
        for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i)
            __atomic_store_n((uint64_t *)(MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE),0,__ATOMIC_RELEASE);
        __atomic_store_n(&payload->admitted,0,__ATOMIC_RELEASE);
        context(SYS_newfstatat);
    }
    assert(!misses && !retired && prior==(payload->api ? payload->completed : native_completed));
    assert(!pthread_sigmask(SIG_SETMASK,NULL,&observed) && sigismember(&observed,SIGTRAP));
    struct sigaction action;
    assert(!sigaction(SIGTRAP,NULL,&action) && action.sa_sigaction==miss);
    /* An ignored trap is just as incompatible with an internal BRK as a
     * blocked one. The cold syscall must leave both cases entirely alone. */
    action.sa_handler=SIG_IGN;
    assert(!sigaction(SIGTRAP,&action,NULL));
    assert(filtered ? call_stat()==-EACCES : !call_stat());
    assert(!sigaction(SIGTRAP,NULL,&action) && action.sa_handler==SIG_IGN);
    action.sa_sigaction=miss;
    assert(!sigaction(SIGTRAP,&action,NULL));
    assert(!pthread_sigmask(SIG_SETMASK,&before,NULL));
    if (!filtered) {
        __atomic_store_n(&payload->admitted,1,__ATOMIC_RELEASE);
        context(SYS_newfstatat);
        assert((payload->api ? payload->completed : native_completed)==prior+1);
    }
    printf("SVC_COLD syscall=1 projectedFilter=%d blockedTrapPreserved=1 ignoredTrapPreserved=1 retired=0\n",filtered);
}
static void cold_signal(int number,siginfo_t *info,void *context) {
    ucontext_t *uc=context;
    if (number!=SIGSYS || info->si_code!=SYS_SECCOMP || info->si_syscall!=SYS_newfstatat
            || info->si_errno!=37 || (uintptr_t)info->si_call_addr!=cold_signal_pc
            || uc->uc_mcontext.pc!=cold_signal_pc) _exit(97);
    ++cold_signal_seen;
    uc->uc_mcontext.regs[0]=(uint64_t)-E2BIG;
}
static void cold_window(void) {
    payload->window=(struct md_svc_signal_window){
        .magic=MD_SVC_SIGNAL_MAGIC,.begin=(uintptr_t)code,.end=(uintptr_t)code+8192,
        .edge={.call=(uintptr_t)md_svc_lab_call,.svc=(uintptr_t)md_svc_lab_call,
            .callee=(uintptr_t)md_svc_lab_call,.frames=MD_SVC_POOL_BASE},
        .original=UINT32_C(0xd4000001),.replacement=branches[0],
        .kernel_alias=(uintptr_t)code+61440};
}
static void cold_trap(int unsafe) {
    cold_window();
    if (unsafe) payload->window.kernel_alias=0;
    cold_signal_pc=payload->api ? (uintptr_t)md_svc_lab_call+4 : (uintptr_t)code+61444;
    struct sigaction action={.sa_sigaction=cold_signal,.sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGSYS,&action,NULL));
    __atomic_store_n(&payload->admitted,0,__ATOMIC_RELEASE);
    filter_projected_action((uintptr_t)md_svc_lab_call+4,1,SECCOMP_RET_TRAP|37);
    assert(call_stat()==-E2BIG && cold_signal_seen==1 && !misses && !retired);
    printf("SVC_COLD_SIGSYS logicalContext=%d handlerResult=1 trapData=37\n",payload->api!=NULL);
}
static int cold_pipe[2],cold_restart_flag;
static unsigned cold_read_ready,cold_read_done,cold_read_boundary;
static long cold_read_result;
static char cold_read_byte;
static void cold_interrupt(int number,siginfo_t *info,void *context) {
    ucontext_t *uc=context;
    uintptr_t pc=uc->uc_mcontext.pc;
    (void)info;
    if (number!=SIGUSR1) _exit(97);
    if (pc!=(uintptr_t)md_svc_lab_call && pc!=(uintptr_t)md_svc_lab_call+4
            && pc!=(uintptr_t)code+61440 && pc!=(uintptr_t)code+61444) return;
    uintptr_t expected=payload->api ? (uintptr_t)md_svc_lab_call : (uintptr_t)code+61440;
    if (pc!=expected+(cold_restart_flag ? 0 : 4) || uc->uc_mcontext.regs[8]!=SYS_read
            || (long)uc->uc_mcontext.regs[0]!=(cold_restart_flag ? cold_pipe[0] : -EINTR)) _exit(97);
    __atomic_fetch_add(&cold_read_boundary,1,__ATOMIC_RELEASE);
}
static void cold_entry_filter(void) {
    uintptr_t ip=(uintptr_t)code+61444;
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(ip>>32),0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)ip,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_NATIVE),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(instructions)/sizeof(*instructions),instructions};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
}
static void cold_read_filter(int project) {
    uintptr_t ip=(uintptr_t)md_svc_lab_call+4;
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_read,0,7),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,cold_pipe[0],0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(ip>>32),0,2),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)ip,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(instructions)/sizeof(*instructions),instructions};
    struct sock_filter projected[BPF_MAXINSNS];
    if (project) {
        struct md_svc_filter_alias alias={(uintptr_t)code+61444,ip};
        size_t written;
        assert(!md_svc_filter_project(instructions,program.len,&alias,1,projected,BPF_MAXINSNS,&written));
        program=(struct sock_fprog){(unsigned short)written,projected};
    }
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
}
static void *cold_reader(void *unused) {
    (void)unused;
    __atomic_store_n(&cold_read_ready,1,__ATOMIC_RELEASE);
    cold_read_result=md_svc_lab_raw(cold_pipe[0],(uintptr_t)&cold_read_byte,1,0,0,0,SYS_read);
    __atomic_store_n(&cold_read_done,1,__ATOMIC_RELEASE);
    return NULL;
}
static void cold_restart(int unsafe) {
    cold_window();
    if (unsafe==1) payload->window.kernel_alias=0;
    if (payload->api && unsafe!=1) cold_entry_filter();
    for (int restart=0;restart<2;++restart) {
        assert(!pipe(cold_pipe));
        /* The missing-context control has no application filter, so an
         * unrelated FD selector cannot mask its signal-context failure. */
        if (unsafe!=1) cold_read_filter(unsafe!=2);
        cold_restart_flag=restart; cold_read_ready=0; cold_read_done=0; cold_read_boundary=0;
        struct sigaction action={.sa_sigaction=cold_interrupt,.sa_flags=SA_SIGINFO|(restart ? SA_RESTART : 0)};
        sigemptyset(&action.sa_mask); assert(!sigaction(SIGUSR1,&action,NULL));
        pthread_t reader; assert(!pthread_create(&reader,NULL,cold_reader,NULL));
        /* EVENT_WAIT: signal a blocked raw read until its handler observes
         * the syscall boundary. alarm rejects a missing interruption. */
        while (!__atomic_load_n(&cold_read_ready,__ATOMIC_ACQUIRE)) sched_yield();
        while (!__atomic_load_n(&cold_read_boundary,__ATOMIC_ACQUIRE)) {
            assert(!__atomic_load_n(&cold_read_done,__ATOMIC_ACQUIRE));
            assert(!pthread_kill(reader,SIGUSR1));
            sched_yield();
        }
        if (restart) assert(write(cold_pipe[1],"r",1)==1);
        assert(!pthread_join(reader,NULL));
        assert(cold_read_result==(restart ? 1 : -EINTR));
        if (restart) assert(cold_read_byte=='r');
        assert(!close(cold_pipe[0]) && !close(cold_pipe[1]));
    }
    assert(!misses && !retired);
    printf("SVC_COLD_RESTART eintr=1 restarted=1 projectedFilter=1 logicalContext=%d\n",payload->api!=NULL);
}
static void *send_traps(void *unused) {
    (void)unused;
    __atomic_store_n(&sender_ready,1,__ATOMIC_RELEASE);
    while (!__atomic_load_n(&sender_stop,__ATOMIC_ACQUIRE)) {
        assert(!syscall(SYS_tgkill,group,receiver,SIGTRAP));
        sched_yield();
    }
    return NULL;
}
static void *body_mapping(void) {
    size_t page=(size_t)getpagesize(),size=(size_t)(md_svc_live_body_end-md_svc_live_body_begin);
    assert(size<page);
    void *memory=mmap((void *)0x3200000,page,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(memory==(void *)0x3200000);
    memcpy(memory,md_svc_live_body_begin,size);
    __builtin___clear_cache(memory,(char *)memory+size);
    assert(!mprotect(memory,page,PROT_READ|PROT_EXEC));
    return memory;
}
static void *body_waiter(void *unused) {
    (void)unused;
    fixture_stack_select(7);
    alternate_stack();
    assert(!call_stat());
    __atomic_store_n(&body_done,1,__ATOMIC_RELEASE);
    return NULL;
}
static void body_release_waiter(void) {
    __atomic_store_n(&body_context.block,0,__ATOMIC_RELEASE);
    assert(syscall(SYS_futex,&body_context.block,FUTEX_WAKE_PRIVATE,INT_MAX,NULL,NULL,0)>=0);
}
static void body_wait_drained(void) {
    /* EVENT_WAIT: actual in-flight calls release ownership after returning to
     * resident code; alarm fails a stalled operation. No peer patch rendezvous. */
    while (!md_svc_live_body_drained(&live_body)) sched_yield();
}
static void reclaim(int unsafe) {
    size_t page=(size_t)getpagesize();
    body_context=(struct body_context){.block=1,.callback=(uintptr_t)direct_dispatch,.state=payload};
    void *body=body_mapping();
    assert(!md_svc_live_body_publish(&live_body,(uintptr_t)body,&body_context));
    pthread_t held,peers[6];
    assert(!pthread_create(&held,NULL,body_waiter,NULL));
    /* EVENT_WAIT: a real futex operation entered the reclaimable code.
     * Its own completion, not a patch acknowledgment, releases that code. */
    while (!__atomic_load_n(&body_context.entered,__ATOMIC_ACQUIRE)) sched_yield();
    assert(md_svc_live_body_close(&live_body)==-EAGAIN && !md_svc_live_body_drained(&live_body));
    if (unsafe) {
        assert(!munmap(body,page));
        body_release_waiter();
        assert(!pthread_join(held,NULL));
        assert(0 && "early reclamation unexpectedly survived");
    }
    for (unsigned i=0;i<6;++i) assert(!pthread_create(&peers[i],NULL,worker,(void *)(uintptr_t)i));
    /* EVENT_WAIT: unrelated work must progress while retirement is pending. */
    for (unsigned i=0;i<6;++i)
        while (__atomic_load_n(&progress[i],__ATOMIC_RELAXED)<8) sched_yield();
    assert(!__atomic_load_n(&body_done,__ATOMIC_ACQUIRE) && !md_svc_live_body_drained(&live_body));
    body_release_waiter();
    assert(!pthread_join(held,NULL));
    body_wait_drained();
    for (unsigned generation=0;generation<256;++generation) {
        assert(!mprotect(body,page,PROT_NONE));
        /* Calls through the still-published entry must not touch the old body,
         * including an old branch fetched before admission was closed. */
        assert(!call_stat());
        assert(!munmap(body,page)); ++body_reclaims;
        body=body_mapping();
        assert(!md_svc_live_body_publish(&live_body,(uintptr_t)body,&body_context));
        assert(!call_stat());
        int result=md_svc_live_body_close(&live_body);
        assert(!result || result==-EAGAIN);
        body_wait_drained();
    }
    assert(!munmap(body,page)); ++body_reclaims;
    assert(!call_stat());
    __atomic_store_n(&stop,1,__ATOMIC_RELEASE);
    for (unsigned i=0;i<6;++i) assert(!pthread_join(peers[i],NULL));
    assert(!retired && !misses && body_calls>=257 && body_fallbacks>0);
    printf("SVC_RECLAIM bodies=%u calls=%" PRIu64 " fallback=%" PRIu64 " peerStops=0\n",
        body_reclaims,body_calls,body_fallbacks);
}
static void entry_lifetime(int unsafe) {
    size_t page=(size_t)getpagesize();
    body_context=(struct body_context){.callback=(uintptr_t)direct_dispatch,.state=payload};
    void *body=body_mapping();
    assert(!md_svc_live_body_publish(&live_body,(uintptr_t)body,&body_context));
    store_instruction(entry_witness_branch);
    pthread_t held;
    assert(!pthread_create(&held,NULL,body_waiter,NULL));
    /* EVENT_WAIT: observe the pre-acquisition continuation, not a delay. */
    while (!__atomic_load_n(&entry_waiting,__ATOMIC_ACQUIRE)) sched_yield();
    store_instruction(UINT32_C(0xd4000001));
    assert(!md_svc_live_body_close(&live_body) && md_svc_live_body_drained(&live_body));
    assert(!body_calls && !__atomic_load_n(&body_done,__ATOMIC_ACQUIRE));
    assert(!munmap(body,page)); ++body_reclaims;
    for (unsigned i=0;i<32;++i) assert(!call_stat());
    if (unsafe) assert(!munmap((void *)entry_witness_pc,page));
    __atomic_store_n(&entry_block,0,__ATOMIC_RELEASE);
    assert(syscall(SYS_futex,&entry_block,FUTEX_WAKE_PRIVATE,1,NULL,NULL,0)>=0);
    assert(!pthread_join(held,NULL));
    assert(!unsafe && body_done && !body_calls && body_fallbacks==2);
    printf("SVC_ENTRY signalContinuation=1 bodyReferences=0 bodyReclaims=%u residentFallback=1\n",body_reclaims);
}
extern unsigned char md_svc_mapping_retry[];
__asm__(".text\n.balign 4\n.global md_svc_mapping_retry\nmd_svc_mapping_retry:\nret\n");
static void mapping_fault(int number,siginfo_t *info,void *context) {
    ucontext_t *uc=context;
    uintptr_t pc=uc->uc_mcontext.pc;
    if (number!=SIGSEGV || info->si_code<=0
            || !((pc>=mapping_sites[0] && pc<mapping_sites[0]+16)
                || (pc>=mapping_sites[1] && pc<mapping_sites[1]+16))) _exit(92);
    __atomic_fetch_add(&mapping_faults,1,__ATOMIC_RELAXED);
    /* The application fixture deliberately executes its own disappearing
     * mapping. Native instruction faults are expected there, never in a
     * reclaimed internal gate/body. Retry at the ordinary caller boundary. */
    uc->uc_mcontext.regs[0]=(uint64_t)-EAGAIN;
    uc->uc_mcontext.pc=(uintptr_t)md_svc_mapping_retry;
}
static void *mapping_worker(void *argument) {
    unsigned index=(unsigned)(uintptr_t)argument;
    fixture_stack_select(index+1);
    alternate_stack();
    while (!__atomic_load_n(&stop,__ATOMIC_ACQUIRE)) {
        long value=call_stat();
        assert(!value || value==-EAGAIN);
        __atomic_fetch_add(&progress[index],1,__ATOMIC_RELAXED);
    }
    return NULL;
}
static int mapping_source(unsigned version) {
    size_t page=(size_t)getpagesize();
    uint32_t *image=calloc(1,page); assert(image);
    image[0]=UINT32_C(0xaa0603e8); /* mov x8,x6 */
    image[1]=UINT32_C(0xd4000001);
    image[2]=version ? UINT32_C(0xd503201f) : UINT32_C(0xd65f03c0);
    image[3]=UINT32_C(0xd65f03c0);
    int fd=memfd_create("svc-mapping-source",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    assert(fd>=0 && write(fd,image,page)==(ssize_t)page);
    assert(!fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL));
    free(image); return fd;
}
static void map_source(unsigned index,int fd,int flags) {
    assert(mmap((void *)mapping_sites[index],(size_t)getpagesize(),PROT_READ|PROT_EXEC,
        MAP_PRIVATE|flags,fd,0)==(void *)mapping_sites[index]);
    assert(*(uint32_t *)(mapping_sites[index]+4)==UINT32_C(0xd4000001));
}
static void replace_inaccessible_mapping(uintptr_t source,int fd) {
    size_t page=(size_t)getpagesize();
    void *snapshot=malloc(page),*verify=malloc(page); assert(snapshot && verify);
    /* This fixture owns a sealed source and excludes writes to the inaccessible
     * page, including /proc/mem and external writers. Readers keep running.
     * This is not a replacement protocol for concurrently writable mappings. */
    assert(pread(memfd,snapshot,page,(off_t)source)==(ssize_t)page);
    void *staging=mmap(NULL,page,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0);
    assert(staging!=MAP_FAILED);
    assert(pwrite(memfd,snapshot,page,(off_t)(uintptr_t)staging)==(ssize_t)page);
    assert(mremap(staging,page,page,MREMAP_MAYMOVE|MREMAP_FIXED,(void *)source)==(void *)source);
    assert(pread(memfd,verify,page,(off_t)source)==(ssize_t)page && !memcmp(snapshot,verify,page));
    free(snapshot); free(verify);
    ++mapping_replacements;
}
static void protections(void) {
    size_t page=(size_t)getpagesize();
    int fd=mapping_source(0);
    static const char *names[]={"clean","same-bytes","patched","restored","discarded","remapped","anonymous","replacement"};
    for (unsigned mode=0;mode<sizeof(names)/sizeof(*names);++mode) {
        uintptr_t source=mapping_sites[0];
        if (mode==6) {
            assert(mmap((void *)source,page,PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void *)source);
            assert(pread(fd,(void *)source,page,0)==(ssize_t)page);
            __builtin___clear_cache((char *)source,(char *)source+page);
            assert(!mprotect((void *)source,page,PROT_READ|PROT_EXEC));
        } else map_source(0,fd,MAP_FIXED_NOREPLACE);
        if (mode) write_site(source+4,mode==1 ? UINT32_C(0xd4000001) : UINT32_C(0xd503201f));
        if (mode==3) write_site(source+4,UINT32_C(0xd4000001));
        if (mode==4) {
            assert(!madvise((void *)source,page,MADV_DONTNEED));
            assert(*(uint32_t *)(source+4)==UINT32_C(0xd4000001));
        }
        if (mode==5) map_source(0,fd,MAP_FIXED);
        assert(!mprotect((void *)source,page,PROT_NONE));
        if (mode==7) replace_inaccessible_mapping(source,fd);
        int result=mprotect((void *)source,page,PROT_READ|PROT_EXEC);
        int error=result ? errno : 0;
        assert(!error || error==EACCES);
        if (mode==0 || mode==5 || mode==6 || mode==7) assert(!error);
        if (mode==7) {
            assert(*(uint32_t *)(source+4)==UINT32_C(0xd503201f));
            assert(!madvise((void *)source,page,MADV_DONTNEED));
            assert(*(uint32_t *)(source+4)==UINT32_C(0xd4000001));
        }
        printf("SVC_PROTECTION kind=%s restoreErrno=%d\n",names[mode],error);
        assert(!munmap((void *)source,page));
    }
    assert(!close(fd));
}
static void mapping_publish(struct md_svc_text *text,unsigned index,uint32_t instruction) {
    if (text->writer) assert(!md_svc_text_publish(text,mapping_sites[index]+4,instruction));
    else write_site(mapping_sites[index]+4,instruction);
}
static void map_mirror(struct md_svc_text *text,int source,unsigned index) {
    assert(!md_svc_text_prepare(text,source,0,mapping_sites[index],(size_t)getpagesize()));
    assert(!md_svc_text_map_new(text));
    assert(*(uint32_t *)(mapping_sites[index]+4)==UINT32_C(0xd4000001));
}
static void mappings(int unsafe_move,int mirror) {
    size_t page=(size_t)getpagesize();
    int sources[2]={mapping_source(0),mapping_source(1)};
    unsigned index=0,backing=0;
    struct md_svc_text text={.fd=-1};
    if (mirror) map_mirror(&text,sources[backing],index);
    else map_source(index,sources[backing],MAP_FIXED_NOREPLACE);
    mapping_publish(&text,index,mapping_branches[index]);
    __atomic_store_n(&mapped_function,mapping_sites[index],__ATOMIC_RELEASE);
    struct sigaction action={.sa_sigaction=mapping_fault,.sa_flags=SA_SIGINFO|SA_ONSTACK};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGSEGV,&action,NULL));
    if (unsafe_move) {
        assert(mremap((void *)mapping_sites[0],page,page,MREMAP_MAYMOVE|MREMAP_FIXED,
            (void *)mapping_sites[1])==(void *)mapping_sites[1]);
        __atomic_store_n(&mapped_function,mapping_sites[1],__ATOMIC_RELEASE);
        call_stat();
        assert(0 && "moving a live PC-relative branch unexpectedly survived");
    }
    body_context=(struct body_context){.callback=(uintptr_t)direct_dispatch,.state=payload};
    void *body=body_mapping();
    assert(!md_svc_live_body_publish(&live_body,(uintptr_t)body,&body_context));
    pthread_t peers[4];
    for (unsigned i=0;i<4;++i) assert(!pthread_create(&peers[i],NULL,mapping_worker,(void *)(uintptr_t)i));
    for (unsigned i=0;i<4;++i)
        while (__atomic_load_n(&progress[i],__ATOMIC_RELAXED)<8) sched_yield();
    for (unsigned generation=0;generation<160;++generation) {
        int result=md_svc_live_body_close(&live_body);
        assert(!result || result==-EAGAIN);
        body_wait_drained();
        uintptr_t source=mapping_sites[index];
        switch (generation%5) {
        case 0:
            assert(!mprotect((void *)source,page,PROT_NONE));
            assert(call_stat()==-EAGAIN);
            if (mirror) {
                /* No private write, so this must work without memory repair. */
                assert(!mprotect((void *)source,page,PROT_READ|PROT_EXEC));
            } else {
                /* Do not let Shroot's existing writer-quiescing memory repair
                 * make this no-peer-stop proof pass accidentally. */
                replace_inaccessible_mapping(source,sources[backing]);
            }
            break;
        case 1:
            if (mirror) mapping_publish(&text,index,UINT32_C(0xd4000001));
            assert(!madvise((void *)source,page,MADV_DONTNEED));
            assert(*(uint32_t *)(source+4)==UINT32_C(0xd4000001));
            break;
        case 2:
            backing=(generation/5)%2;
            map_source(index,sources[backing],MAP_FIXED);
            if (mirror) {
                md_svc_text_release(&text);
                assert(!md_svc_text_install(&text,sources[backing],0,source,page));
            }
            break;
        case 3:
            assert(!munmap((void *)source,page));
            assert(call_stat()==-EAGAIN);
            backing=(generation/5)%2;
            map_source(index,sources[backing],MAP_FIXED_NOREPLACE);
            if (mirror) {
                md_svc_text_release(&text);
                assert(!md_svc_text_install(&text,sources[backing],0,source,page));
            }
            break;
        case 4:
            /* Restore the position-dependent instruction before moving its
             * page. Old fetched branches can still use their resident entry. */
            mapping_publish(&text,index,UINT32_C(0xd4000001));
            index=1-index;
            assert(mremap((void *)source,page,page,MREMAP_MAYMOVE|MREMAP_FIXED,
                (void *)mapping_sites[index])==(void *)mapping_sites[index]);
            __atomic_store_n(&mapped_function,mapping_sites[index],__ATOMIC_RELEASE);
            if (mirror) text.address=mapping_sites[index];
            assert(*(uint32_t *)(mapping_sites[index]+4)==UINT32_C(0xd4000001));
            break;
        }
        mapping_publish(&text,index,mapping_branches[index]);
        ++mapping_changes;
        assert(!mprotect(body,page,PROT_NONE) && !munmap(body,page)); ++body_reclaims;
        body=body_mapping();
        assert(!md_svc_live_body_publish(&live_body,(uintptr_t)body,&body_context));
        assert(!call_stat());
    }
    __atomic_store_n(&stop,1,__ATOMIC_RELEASE);
    for (unsigned i=0;i<4;++i) assert(!pthread_join(peers[i],NULL));
    int result=md_svc_live_body_close(&live_body); assert(!result);
    assert(!munmap(body,page) && !munmap((void *)mapping_sites[index],page));
    assert(!close(sources[0]) && !close(sources[1]));
    md_svc_text_release(&text);
    printf("SVC_MAPPING mirror=%d changes=%u nativeFaults=%u replacements=%u bodies=%u calls=%" PRIu64 " fallback=%" PRIu64 " peerStops=0\n",
        mirror,mapping_changes,mapping_faults,mapping_replacements,body_reclaims,body_calls,body_fallbacks);
    fprintf(stderr,"SVC_MAPPING_CHECK retired=%u misses=%" PRIu64 " mismatch=%" PRIu64
        " declined=%" PRIu64 " busy=%" PRIu64 " calls=%" PRIu64 " faults=%u\n",
        retired,misses,miss_reasons[0],miss_reasons[1],miss_reasons[2],body_calls,mapping_faults);
    assert(!retired && !misses && mapping_faults>=64 && body_calls>=160);
}
static void mirror_fork(int shared) {
    size_t page=(size_t)getpagesize();
    int source=mapping_source(0);
    struct md_svc_text text={.fd=-1};
    map_mirror(&text,source,0);
    mapping_publish(&text,0,mapping_branches[0]);
    __atomic_store_n(&mapped_function,mapping_sites[0],__ATOMIC_RELEASE);
    pthread_t peers[4];
    for (unsigned i=0;i<4;++i) assert(!pthread_create(&peers[i],NULL,mapping_worker,(void *)(uintptr_t)i));
    for (unsigned i=0;i<4;++i)
        while (__atomic_load_n(&progress[i],__ATOMIC_RELAXED)<8) sched_yield();
    for (unsigned generation=0;generation<32;++generation) {
        struct md_svc_text child_text={.fd=-1};
        /* Serialized with publication, before fork. The child inherits both
         * prepared aliases; parent peers keep executing the current mapping. */
        if (!shared) assert(!md_svc_text_prepare(&child_text,text.fd,0,text.address,text.size));
        int ready_pipe[2],release_pipe[2];
        assert(!pipe2(ready_pipe,O_CLOEXEC) && !pipe2(release_pipe,O_CLOEXEC));
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            alarm(30);
            assert(!close(ready_pipe[0]) && !close(release_pipe[1]));
            if (!shared) {
                assert(!md_svc_text_activate(&child_text));
                md_svc_text_release(&text);
                text=child_text;
            }
            char token='r';
            assert(write(ready_pipe[1],&token,1)==1);
            /* EVENT_WAIT: parent publication is complete; alarm rejects a lost
             * handshake. This is fork ownership, not a peer patch rendezvous. */
            assert(read(release_pipe[0],&token,1)==1);
            if (*(uint32_t *)(mapping_sites[0]+4)!=mapping_branches[0]) _exit(94);
            assert(!mprotect((void *)mapping_sites[0],page,PROT_NONE));
            assert(!mprotect((void *)mapping_sites[0],page,PROT_READ|PROT_EXEC));
            for (unsigned i=0;i<64;++i) assert(!call_stat());
            mapping_publish(&text,0,UINT32_C(0xd4000001));
            assert(!call_stat());
            assert(!munmap((void *)mapping_sites[0],page));
            md_svc_text_release(&text);
            _exit(0);
        }
        md_svc_text_release(&child_text);
        assert(!close(ready_pipe[1]) && !close(release_pipe[0]));
        char token;
        assert(read(ready_pipe[0],&token,1)==1);
        mapping_publish(&text,0,UINT32_C(0xd4000001));
        assert(write(release_pipe[1],&token,1)==1);
        int status=0;
        assert(waitpid(child,&status,0)==child && WIFEXITED(status));
        if (shared && WEXITSTATUS(status)==94) _exit(94);
        assert(!WEXITSTATUS(status));
        assert(*(uint32_t *)(mapping_sites[0]+4)==UINT32_C(0xd4000001));
        assert(!call_stat());
        mapping_publish(&text,0,mapping_branches[0]);
        assert(!close(ready_pipe[0]) && !close(release_pipe[1]));
    }
    __atomic_store_n(&stop,1,__ATOMIC_RELEASE);
    for (unsigned i=0;i<4;++i) assert(!pthread_join(peers[i],NULL));
    assert(!munmap((void *)mapping_sites[0],page) && !close(source));
    md_svc_text_release(&text);
    assert(!retired && !misses && body_fallbacks>0);
    printf("SVC_MIRROR_FORK children=32 privatePublication=1 nativeProtection=1 peerStops=0\n");
}
static void mirror_filter(void) {
    size_t page=(size_t)getpagesize();
    int source=mapping_source(0);
    struct md_svc_text text={.fd=-1};
    map_mirror(&text,source,0);
    fault_text=&text;
    mapping_publish(&text,0,mapping_branches[0]);
    __atomic_store_n(&mapped_function,mapping_sites[0],__ATOMIC_RELEASE);
    assert(!call_stat());
    store_instruction(UINT32_C(0xd4000001));
    setvbuf(stdout,NULL,_IONBF,0);
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_pwrite64,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mprotect,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mmap,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mremap,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_memfd_create,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ftruncate,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    __atomic_store_n(&payload->admitted,0,__ATOMIC_RELEASE);
    filter_at(mapping_sites[0]+8);
    uint32_t word=UINT32_C(0xd4000001);
    assert(pwrite(memfd,&word,4,(off_t)(mapping_sites[0]+4))==-1 && errno==EPERM);
    assert(mprotect((void *)mapping_sites[0],page,PROT_READ|PROT_EXEC)==-1 && errno==EPERM);
    /* A branch fetched before admission was revoked reaches resident fallback.
     * The alias restores SVC even though remapping and forced writes are denied.
     * A copied SVC at any other IP kills the process under the second filter. */
    assert(call_stat()==-EACCES && retired && misses==1 && miss_reasons[1]==1);
    assert(call_stat()==-EACCES && misses==1);
    assert(*(uint32_t *)(mapping_sites[0]+4)==word);
    assert(!munmap((void *)mapping_sites[0],page) && !close(source));
    fault_text=NULL;
    md_svc_text_release(&text);
    printf("SVC_MIRROR_FILTER originalIP=1 deniedForcedWrite=1 deniedRemap=1 aliasRetirement=1\n");
}
static void mirror_denied(void) {
    size_t page=(size_t)getpagesize();
    int source=mapping_source(0);
    map_source(0,source,MAP_FIXED_NOREPLACE);
    struct md_svc_text text={.fd=-1};
    assert(md_svc_text_install(&text,source,0,mapping_sites[0]+1,page)==-EINVAL);
    assert(md_svc_text_install(&text,source,0,mapping_sites[0],SIZE_MAX)==-EINVAL);
    assert(md_svc_text_install(&text,source,UINT64_MAX,mapping_sites[0],page)==-EINVAL);
    assert(md_svc_text_install(&text,source,page,mapping_sites[0],page)==-EIO);
    assert(text.fd==-1 && !text.writer && !text.staging);
    assert(*(uint32_t *)(mapping_sites[0]+4)==UINT32_C(0xd4000001));
    assert(!md_svc_text_install(&text,source,0,mapping_sites[0],page));
    assert(md_svc_text_publish(&text,mapping_sites[0]+4,UINT32_C(0xd503201f))==-EINVAL);
    assert(md_svc_text_publish(&text,mapping_sites[0],UINT32_C(0xd4000001))==-EINVAL);
    assert(md_svc_text_publish(&text,mapping_sites[0]+page,UINT32_C(0xd4000001))==-EINVAL);
    assert(md_svc_text_publish(&text,mapping_sites[0]+5,UINT32_C(0xd4000001))==-EINVAL);
    uint32_t word=UINT32_C(0xd4000001);
    assert(pwrite(text.fd,&word,4,4)==-1 && errno==EPERM);
    assert(mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_SHARED,text.fd,0)==MAP_FAILED && errno==EPERM);
    md_svc_text_release(&text);
    map_source(0,source,MAP_FIXED);
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mremap,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    for (unsigned i=0;i<32;++i) {
        assert(md_svc_text_install(&text,source,0,mapping_sites[0],page)==-EPERM);
        assert(text.fd==-1 && !text.writer && !text.staging);
        assert(*(uint32_t *)(mapping_sites[0]+4)==UINT32_C(0xd4000001));
        assert(!mprotect((void *)mapping_sites[0],page,PROT_NONE));
        assert(!mprotect((void *)mapping_sites[0],page,PROT_READ|PROT_EXEC));
    }
    assert(!md_svc_text_prepare(&text,source,0,mapping_sites[0],page));
    assert(md_svc_text_map_new(&text)==-EEXIST);
    assert(*(uint32_t *)(mapping_sites[0]+4)==word);
    assert(!munmap((void *)mapping_sites[0],page));
    assert(!md_svc_text_map_new(&text));
    assert(!mprotect((void *)mapping_sites[0],page,PROT_NONE));
    assert(!mprotect((void *)mapping_sites[0],page,PROT_READ|PROT_EXEC));
    fault_text=&text;
    mapping_publish(&text,0,mapping_branches[0]);
    __atomic_store_n(&mapped_function,mapping_sites[0],__ATOMIC_RELEASE);
    for (unsigned i=0;i<128;++i) assert(!call_stat());
    assert(misses==(payload->api ? 1u : 0u) && retired==(payload->api ? 1u : 0u));
    if (payload->api) assert(miss_reasons[1]==1);
    mapping_publish(&text,0,word);
    assert(!munmap((void *)mapping_sites[0],page) && !close(source));
    md_svc_text_release(&text);
    fault_text=NULL;
    printf("SVC_MIRROR_DENIED unchanged=32 bounds=1 sourceRead=1 seals=1 eligibleWords=1 newMapping=1\n");
}
static void file_publish(int patched) {
    for (unsigned i=0;i<4;++i) {
        uintptr_t site=(uintptr_t)file_entries[i]+4;
        uint32_t word=patched ? file_branches[i] : UINT32_C(0xd4000001);
        if (file_text.writer) assert(!md_svc_text_publish(&file_text,site,word));
        else write_site(site,word);
    }
}
static long file_call(unsigned index,int callback,uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
    if (callback) {
        uint64_t regs[31]={a,b,c,d}; regs[8]=(uint64_t)file_numbers[index];
        assert(direct_dispatch(regs,payload));
        return (long)regs[0];
    }
    return ((long (*)(uint64_t,uint64_t,uint64_t,uint64_t))file_entries[index])(a,b,c,d);
}
static void file_step(int mutations,int callback,const char *temporary,const char *renamed) {
    long fd=file_call(0,callback,AT_FDCWD,(uintptr_t)(mutations ? temporary : path),
        mutations ? O_WRONLY|O_CREAT|O_EXCL : O_RDONLY,mutations ? 0600 : 0);
    assert(fd>=0 && !file_call(1,callback,(uint64_t)fd,0,0,0));
    if (mutations) {
        assert(!file_call(2,callback,AT_FDCWD,(uintptr_t)temporary,AT_FDCWD,(uintptr_t)renamed));
        assert(!file_call(3,callback,AT_FDCWD,(uintptr_t)renamed,0,0));
    }
}
int main(int argc,char **argv) {
    assert(argc==3 || argc==4); alarm(120);
    const char *workload=argc==4 ? argv[3] : "stat";
    int files=!strcmp(workload,"opens") || !strcmp(workload,"mutations");
    assert(files || !strcmp(workload,"stat"));
    assert(!files || !strncmp(argv[2],"bench-",6));
    unsigned iterations=!strcmp(workload,"opens") ? 4096 : files ? 1024 : 32768;
    unsigned calls_per_iteration=!strcmp(workload,"opens") ? 2 : files ? 4 : 1;
    uint64_t benchmark_elapsed=0;
    assert(snprintf(path,sizeof(path),"%s/live-file",argv[1])<(int)sizeof(path));
    int fd=open(path,O_CREAT|O_RDWR|O_TRUNC,0600);
    assert(fd>=0 && write(fd,"test",4)==4 && !close(fd));
    md_svc_live_body_init(&live_body);
    int fork_mirror=!strncmp(argv[2],"mirror-fork",11);
    int filter_mirror=!strcmp(argv[2],"mirror-filter");
    int denied_mirror=!strcmp(argv[2],"mirror-denied");
    int live_mirror=!strcmp(argv[2],"mirror-live");
    int signal_gate=!strcmp(argv[2],"bench-signals");
    int bench_mirror=!strcmp(argv[2],"bench-mirror") || signal_gate;
    int mirror=fork_mirror || filter_mirror || denied_mirror || !strcmp(argv[2],"mirror");
    int lifetime=!strncmp(argv[2],"lifetime",8),mapping=mirror || !strncmp(argv[2],"mapping",7);
    int entry=!strncmp(argv[2],"entry",5);
    int owned=!strcmp(argv[2],"bench-owned");
    int trap_cold=!strncmp(argv[2],"cold-trap",9);
    int restart_cold=!strncmp(argv[2],"cold-restart",12);
    int cold=!strcmp(argv[2],"cold-syscall") || !strncmp(argv[2],"cold-filter",11) || trap_cold || restart_cold;
    void *benchmark_body=NULL;
    prepare(lifetime || mapping || entry || owned,mapping,entry,files,cold,signal_gate);
    if (lifetime || mapping || entry || live_mirror || !strcmp(argv[2],"live") || !strcmp(argv[2],"overflow")) {
        /* Keep channel exhaustion and frame collisions separate from lifetime
         * proofs. The assembly wrappers place SVC at nine distinct SP hashes.
         * check/collision still cover arbitrary SP, guard SP and busy frames. */
        fixture_stacks=mmap((void *)0x3600000,9*65536,PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
        assert(fixture_stacks==(void *)0x3600000);
        fixture_stack_select(0);
    }
    if (live_mirror || cold || (bench_mirror && !files)) {
        size_t page=(size_t)getpagesize();
        uintptr_t address=(uintptr_t)md_svc_lab_call&~(uintptr_t)(page-1);
        /* Snapshot this fixture-owned immutable ELF page before any patch;
         * the same context and benchmark code then exercises both writers. */
        assert(!md_svc_text_install(&main_text,memfd,address,address,page));
    }
    uint32_t before[3]; memcpy(before,md_svc_lab_call-4,sizeof(before));
    publish(1);
    assert(!memcmp(before,md_svc_lab_call-4,4) && !memcmp(before+2,md_svc_lab_call+4,4));
    context(SYS_newfstatat);
    assert(payload->api ? payload->completed : native_completed);
    uint64_t begin=now();
    if (restart_cold) {
        cold_restart(!strcmp(argv[2],"cold-restart-unsafe") ? 1
            : !strcmp(argv[2],"cold-restart-unprojected") ? 2 : 0);
    } else if (trap_cold) {
        cold_trap(!strcmp(argv[2],"cold-trap-unsafe"));
    } else if (cold) {
        cold_syscall(!strncmp(argv[2],"cold-filter",11),!strcmp(argv[2],"cold-filter-unsafe"));
    } else if (!strcmp(argv[2],"cold-blocked-unsafe")) {
        sigset_t mask;
        sigemptyset(&mask); sigaddset(&mask,SIGTRAP);
        assert(!pthread_sigmask(SIG_BLOCK,&mask,NULL));
        context(SYS_getpid);
        assert(0 && "blocked internal BRK must fail this negative control");
    } else if (denied_mirror) {
        mirror_denied();
    } else if (filter_mirror) {
        mirror_filter();
    } else if (fork_mirror) {
        mirror_fork(!strcmp(argv[2],"mirror-fork-shared"));
    } else if (entry) {
        entry_lifetime(!strcmp(argv[2],"entry-unsafe"));
    } else if (!strcmp(argv[2],"protection")) {
        protections();
    } else if (mapping) {
        mappings(!strcmp(argv[2],"mapping-unsafe"),mirror);
    } else if (lifetime) {
        reclaim(!strcmp(argv[2],"lifetime-unsafe"));
    } else if (!strcmp(argv[2],"check")) {
        size_t page=(size_t)getpagesize();
        void *guard=mmap(NULL,2*page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(guard!=MAP_FAILED && !mprotect((char *)guard+page,page,PROT_READ|PROT_WRITE));
        struct stat st;
        assert(!md_svc_lab_without_tls((char *)guard+page,path,&st) && st.st_size==4);
        assert(!munmap(guard,2*page));
        uint64_t prior=payload->api ? payload->completed : native_completed;
        for (unsigned i=0;i<4096;++i) context(SYS_newfstatat);
        assert((payload->api ? payload->completed : native_completed)==prior+4096);
        /* Same low syscall number but a different upper bit must not be
         * mistaken for the specialized full-register value. */
        context((UINT64_C(1)<<40)|SYS_newfstatat);
        assert(retired && misses==1);
        assert(!memcmp(md_svc_lab_call,before+1,4));
    } else if (!strcmp(argv[2],"collision")) {
        uint64_t prior=payload->api ? payload->completed : native_completed;
        for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i)
            __atomic_store_n((uint64_t *)(MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE),1,__ATOMIC_RELEASE);
        context(SYS_newfstatat);
        assert(retired && misses==1 && prior==(payload->api ? payload->completed : native_completed));
    } else if (!strcmp(argv[2],"filter") || !strcmp(argv[2],"filter-signals")) {
        __atomic_store_n(&payload->admitted,0,__ATOMIC_RELEASE);
        sigset_t mask;
        struct sigaction disposition;
        assert(!sigaction(SIGTRAP,NULL,&disposition) && disposition.sa_sigaction==miss);
        pthread_t sender;
        int signals=!strcmp(argv[2],"filter-signals");
        if (signals) {
            receiver=(pid_t)syscall(SYS_gettid); group=getpid();
            assert(!pthread_create(&sender,NULL,send_traps,NULL));
            /* EVENT_WAIT: sender startup; alarm bounds a missing announcement. */
            while (!__atomic_load_n(&sender_ready,__ATOMIC_ACQUIRE)) sched_yield();
        }
        filtering=1;
        for (unsigned i=0;i<(signals ? 64u : 1u);++i) filter();
        filtering=0;
        if (signals) {
            __atomic_store_n(&sender_stop,1,__ATOMIC_RELEASE);
            assert(!pthread_join(sender,NULL) && async_traps && traps_during_filter);
            printf("SVC_SIGNALS traps=%d duringFilter=%d\n",(int)async_traps,(int)traps_during_filter);
        }
        assert(!pthread_sigmask(SIG_SETMASK,NULL,&mask));
        assert(!sigaction(SIGTRAP,NULL,&disposition));
        fprintf(stderr,"FILTER_STATE trapBlocked=%d handler=%p expected=%p\n",
            sigismember(&mask,SIGTRAP),(void *)disposition.sa_sigaction,(void *)miss);
        assert(!sigismember(&mask,SIGTRAP) && disposition.sa_sigaction==miss);
        assert(call_stat()==-EACCES && misses==1 && retired);
        assert(call_stat()==-EACCES && misses==1);
    } else if (!strncmp(argv[2],"bench-",6)) {
        int base=!strcmp(argv[2],"bench-base");
        int callback=!strcmp(argv[2],"bench-callback");
        assert(base || callback || owned || bench_mirror || !strcmp(argv[2],"bench-direct"));
        if (owned) {
            body_context=(struct body_context){.callback=(uintptr_t)direct_dispatch,.state=payload};
            benchmark_body=body_mapping();
            assert(!md_svc_live_body_publish(&live_body,(uintptr_t)benchmark_body,&body_context));
        }
        if (base) store_instruction(UINT32_C(0xd4000001));
        if (files) {
            if (bench_mirror) {
                size_t page=(size_t)getpagesize();
                uintptr_t address=(uintptr_t)file_entries[0]&~(uintptr_t)(page-1);
                assert((uintptr_t)file_entries[3]+12<=address+page);
                assert(!md_svc_text_install(&file_text,memfd,address,address,page));
            }
            if (!base && !callback) file_publish(1);
            char temporary[4096],renamed[4096];
            assert(snprintf(temporary,sizeof(temporary),"%s/live-new",argv[1])<(int)sizeof(temporary));
            assert(snprintf(renamed,sizeof(renamed),"%s/live-renamed",argv[1])<(int)sizeof(renamed));
            int mutations=!strcmp(workload,"mutations");
            for (unsigned i=0;i<128;++i) file_step(mutations,callback,temporary,renamed);
            begin=now();
            for (unsigned i=0;i<iterations;++i) file_step(mutations,callback,temporary,renamed);
            benchmark_elapsed=now()-begin;
            if (!base && !callback) file_publish(0);
            struct stat st;
            assert(stat(temporary,&st)==-1 && errno==ENOENT);
            assert(stat(renamed,&st)==-1 && errno==ENOENT);
            assert(!stat(path,&st) && st.st_size==4);
            md_svc_text_release(&file_text);
        } else {
            struct stat st;
            uint64_t regs[31]={AT_FDCWD,(uintptr_t)path,(uintptr_t)&st};
            regs[8]=SYS_newfstatat;
            for (unsigned i=0;i<128;++i) assert(!call_stat());
            begin=now();
            for (unsigned i=0;i<iterations;++i) {
                if (callback) {
                    regs[0]=AT_FDCWD;
                    assert(direct_dispatch(regs,payload) && !regs[0]);
                } else assert(!call_stat());
            }
            benchmark_elapsed=now()-begin;
        }
    } else if (live_mirror || !strcmp(argv[2],"live") || !strcmp(argv[2],"overflow")) {
        unsigned count=live_mirror || !strcmp(argv[2],"live") ? 7 : 8;
        pthread_t peers[8];
        for (unsigned i=0;i<count;++i) assert(!pthread_create(&peers[i],NULL,worker,(void *)(uintptr_t)i));
        /* EVENT_WAIT: peers announce startup; alarm is the failure bound.
         * They are never asked to park or acknowledge a patch epoch. */
        while (__atomic_load_n(&ready,__ATOMIC_ACQUIRE)!=count) sched_yield();
        uint64_t baseline[8];
        for (unsigned i=0;i<count;++i) baseline[i]=__atomic_load_n(&progress[i],__ATOMIC_RELAXED);
        for (unsigned i=0;i<30000;++i) publish(i%3);
        __atomic_store_n(&stop,1,__ATOMIC_RELEASE);
        for (unsigned i=0;i<count;++i) {
            assert(!pthread_join(peers[i],NULL));
            assert(progress[i]>baseline[i]);
        }
        if (count==7) assert(!retired && !misses && publications==30001);
        else if (payload->api) assert(retired && miss_reasons[1]);
    } else assert(0 && "unknown mode");
    uint64_t elapsed=benchmark_elapsed ? benchmark_elapsed : now()-begin,total=0;
    if (benchmark_body) {
        assert(!md_svc_live_body_close(&live_body) && md_svc_live_body_drained(&live_body));
        assert(body_calls==(uint64_t)(iterations+128)*calls_per_iteration && body_fallbacks==1);
        assert(!munmap(benchmark_body,(size_t)getpagesize()));
    }
    for (unsigned i=0;i<8;++i) total+=progress[i];
    if (!filter_mirror) store_instruction(UINT32_C(0xd4000001));
    md_svc_text_release(&main_text);
    printf("SVC_LIVE {\"mode\":\"%s\",\"workload\":\"%s\",\"iterations\":%u,\"callsPerIteration\":%u,"
        "\"provider\":%s,\"completed\":%" PRIu64
        ",\"nativeCompleted\":%" PRIu64 ",\"misses\":%" PRIu64
        ",\"retired\":%u,\"publications\":%u,\"peerCalls\":%" PRIu64
        ",\"ns\":%" PRIu64 ",\"gateBytes\":%zu,\"peerStops\":0}\n",
        argv[2],workload,iterations,calls_per_iteration,payload->api ? "true" : "false",payload->completed,native_completed,
        misses,retired,publications,total,elapsed,signal_gate ? md_svc_direct_signal_size() : md_svc_direct_size());
    printf("SVC_MISSES {\"mismatch\":%" PRIu64 ",\"declined\":%" PRIu64 ",\"busy\":%" PRIu64 "}\n",
        miss_reasons[0],miss_reasons[1],miss_reasons[2]);
    assert(!close(memfd));
    return 0;
}
