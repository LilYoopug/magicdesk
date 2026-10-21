#ifndef MD_TASK_MEMORY_H
#define MD_TASK_MEMORY_H
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/* The optional descriptor must belong to this exact address space. Its owner
 * authorizes retained access; this reader never acquires or widens authority. */
static inline ssize_t md_task_read_memory(pid_t pid,uintptr_t address,void *out,size_t size,int memory) {
    if (address>UINTPTR_MAX-size) return -EFAULT;
    struct iovec local={out,size},remote={(void *)address,size};
    ssize_t n=process_vm_readv(pid,&local,1,&remote,1,0);
    if (n==(ssize_t)size || (n>=0 && memory<0)) return n;
    int error=n<0 ? errno : EFAULT;
    if (memory<0 || address>INT64_MAX) return -error;
    n=pread(memory,out,size,(off_t)address);
    return n<0 ? -errno : n;
}

/* Return the length excluding NUL. Page-bounded reads must not reject a valid
 * string whose terminator immediately precedes an inaccessible mapping. */
static inline ssize_t md_task_read_string_from(pid_t pid,uintptr_t address,char *out,size_t capacity,size_t page,int memory) {
    if (!out || !page) return -EINVAL;
    size_t copied=0;
    while (copied<capacity) {
        if (address>UINTPTR_MAX-copied) return -EFAULT;
        size_t size=page-((address+copied)%page);
        if (size>256) size=256;
        if (size>capacity-copied) size=capacity-copied;
        ssize_t n=md_task_read_memory(pid,address+copied,out+copied,size,memory);
        if (n<=0) return n ? n : -EFAULT;
        const char *end=memchr(out+copied,0,(size_t)n);
        if (end) return end-out;
        copied+=(size_t)n;
    }
    return -ENAMETOOLONG;
}
static inline ssize_t md_task_read_string(pid_t pid,uintptr_t address,char *out,size_t capacity,size_t page) {
    return md_task_read_string_from(pid,address,out,capacity,page,-1);
}
#endif
