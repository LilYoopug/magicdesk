#define _GNU_SOURCE
#include "task_memory.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned calls;
static int denied;
ssize_t __real_process_vm_readv(pid_t,const struct iovec *,unsigned long,const struct iovec *,unsigned long,unsigned long);
ssize_t __wrap_process_vm_readv(pid_t pid,const struct iovec *local,unsigned long ln,
        const struct iovec *remote,unsigned long rn,unsigned long flags) {
    ++calls;
    if (denied) { errno=EPERM; return -1; }
    return __real_process_vm_readv(pid,local,ln,remote,rn,flags);
}
int main(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *memory=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED && !mprotect(memory+page,page,PROT_NONE));
    char out[2048]; pid_t pid=getpid();
    memset(memory,'a',page); memory[page-1]=0;
    const size_t sizes[]={0,1,255,256,257,1023};
    for (size_t i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        size_t length=sizes[i]; uintptr_t address=(uintptr_t)(memory+page-length-1);
        calls=0;
        assert(md_task_read_string(pid,address,out,sizeof(out),page)==(ssize_t)length);
        assert(calls==(length+256)/256 && !out[length]);
        assert(md_task_read_string(pid,address,out,length,page)==-ENAMETOOLONG);
    }
    memory[page-1]='a';
    assert(md_task_read_string(pid,(uintptr_t)(memory+page-32),out,sizeof(out),page)==-EFAULT);
    assert(md_task_read_string(pid,UINTPTR_MAX-3,out,sizeof(out),page)==-EFAULT);
    assert(md_task_read_string(pid,(uintptr_t)memory,out,sizeof(out),0)==-EINVAL);
    int retained=open("/proc/self/mem",O_RDONLY|O_CLOEXEC); assert(retained>=0);
    memory[page-1]=0; denied=1;
    uintptr_t address=(uintptr_t)(memory+page-258);
    assert(md_task_read_string(pid,address,out,sizeof(out),page)==-EPERM);
    assert(md_task_read_string_from(pid,address,out,sizeof(out),page,retained)==257 && !out[257]);
    assert(md_task_read_memory(pid,UINTPTR_MAX-3,out,8,retained)==-EFAULT);
    assert(!close(retained)); denied=0;
    assert(!munmap(memory,page*2));
    puts("PASS task strings: bounded reads, exact lengths, inaccessible next page, overflow and explicit retained authority");
    return 0;
}
