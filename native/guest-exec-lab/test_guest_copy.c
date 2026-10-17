#define _GNU_SOURCE
#include "raw.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

extern char md_guest_copy_begin[],md_guest_copy_end[];
static volatile sig_atomic_t faults;
static void fault(int signal,siginfo_t *info,void *context) {
    ucontext_t *uc=context;
    assert((signal==SIGSEGV || signal==SIGBUS) && info->si_code>0);
    assert(uc->uc_mcontext.pc>=(uintptr_t)md_guest_copy_begin
        && uc->uc_mcontext.pc<(uintptr_t)md_guest_copy_end);
    ++faults;
    uc->uc_mcontext.regs[0]=(uint64_t)-EFAULT;
    uc->uc_mcontext.pc=uc->uc_mcontext.regs[30];
}
int main(void) {
    alarm(10);
    struct sigaction action={.sa_sigaction=fault,.sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGSEGV,&action,NULL) && !sigaction(SIGBUS,&action,NULL));
    size_t page=(size_t)getpagesize();
    unsigned char *source=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    unsigned char *output=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(source!=MAP_FAILED && output!=MAP_FAILED);
    assert(!mprotect(source+page,page,PROT_NONE) && !mprotect(output+page,page,PROT_NONE));
    for (size_t a=0;a<16;++a) for (size_t b=0;b<16;++b) for (size_t n=0;n<257;++n) {
        for (size_t i=0;i<n;++i) source[32+a+i]=(unsigned char)(i*13+a);
        memset(output,0xa5,512);
        assert(!md_read_memory(output+32+b,source+32+a,n));
        assert(!memcmp(output+32+b,source+32+a,n));
        assert(output[31+b]==0xa5 && output[32+b+n]==0xa5);
    }
    for (size_t n=0;n<257;++n) {
        memset(source+page-n-1,'x',n); source[page-1]=0;
        memset(output+page-n-2,0xa5,n+2);
        assert(!md_read_string((void *)(output+page-n-1),n+1,(void *)(source+page-n-1)));
        assert(output[page-n-2]==0xa5 && !memcmp(source+page-n-1,output+page-n-1,n+1));
        assert(md_read_string((void *)output,n,(void *)(source+page-n-1))==-ENAMETOOLONG);
        assert(!md_read_memory(output+page-n,source+page-n,n));
        assert(!memcmp(source+page-n,output+page-n,n));
    }
    assert(!faults && !md_read_memory(NULL,NULL,0));
    assert(md_read_string((void *)output,page,NULL)==-EFAULT);
    assert(md_read_memory(output,source+page,1)==-EFAULT);
    assert(md_write_memory(output+page,source,1)==-EFAULT);
    source[page-1]='x';
    assert(md_read_string((void *)output,page,(void *)(source+page-1))==-EFAULT);
    assert(faults==3);
    for (size_t n=1;n<=32;++n) {
        memset(source,0x37,page); memset(output,0xa5,page);
        assert(md_read_memory(output+page-n,source+page-n,n+8)==-EFAULT);
        for (size_t i=0;i<n;++i) assert(output[page-n+i]==0x37);
        assert(output[page-n-1]==0xa5);
    }
    assert(faults==35);
    assert(!munmap(source,2*page) && !munmap(output,2*page));
    puts("PASS guest copy: exact lengths, terminal NUL, no overread/overwrite and shared fault PCs");
    return 0;
}
