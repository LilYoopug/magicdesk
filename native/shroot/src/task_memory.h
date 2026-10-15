#ifndef MD_TASK_MEMORY_H
#define MD_TASK_MEMORY_H
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>

static inline int md_task_read_string(pid_t pid,uintptr_t address,char *out,size_t capacity,size_t page) {
    size_t copied=0;
    while (copied<capacity) {
        if (address>UINTPTR_MAX-copied) return -EFAULT;
        size_t size=page-((address+copied)%page);
        if (size>256) size=256;
        if (size>capacity-copied) size=capacity-copied;
        struct iovec local={out+copied,size},remote={(void *)(address+copied),size};
        ssize_t n=process_vm_readv(pid,&local,1,&remote,1,0);
        if (n<=0) return n<0 ? -errno : -EFAULT;
        if (memchr(out+copied,0,(size_t)n)) return 0;
        copied+=(size_t)n;
    }
    return -ENAMETOOLONG;
}
#endif
