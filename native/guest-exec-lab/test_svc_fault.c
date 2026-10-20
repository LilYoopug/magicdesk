#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
extern long faulting_call(const void *);
extern char faulting_load[];
__asm__(".text\n.global faulting_call\nfaulting_call:\nmov x9,x0\nmov x8,#172\n"
    ".global faulting_load\nfaulting_load:\nldr x5,[x9]\nsvc #0\nret\n");
static volatile sig_atomic_t faults;
static uint64_t good=42;
static void *bad;
static void fault(int signal,siginfo_t *info,void *context) {
    ucontext_t *u=context;
    if (signal!=SIGSEGV || info->si_addr!=bad || u->uc_mcontext.pc!=(uintptr_t)faulting_load) _exit(70);
    ++faults; u->uc_mcontext.regs[9]=(uintptr_t)&good;
}
int main(void) {
    struct sigaction action={.sa_sigaction=fault,.sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGSEGV,&action,NULL));
    bad=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(bad!=MAP_FAILED);
    for (unsigned i=0;i<512;++i) assert(faulting_call(&good)==getpid());
    assert(faulting_call(bad)==getpid() && faults==1);
    assert(!munmap(bad,4096));
    puts("PASS SVC fault: original instruction PC, fault address and handler-edited resume");
    printf("SVC_FAULT {\"pc\":\"%#" PRIxPTR "\",\"faults\":%d}\n",(uintptr_t)faulting_load+4,faults);
}
