#define _GNU_SOURCE
#include "arguments.h"
#include "raw.h"
#include <errno.h>
#include <sys/mman.h>

void md_arguments_init(struct md_arguments *a) {
    a->values=a->local; a->count=0;
    a->capacity=sizeof(a->local)/sizeof(*a->local);
    a->values[0]=NULL;
}
int md_arguments_reserve(struct md_arguments *a,size_t count) {
    if (count>MD_EXEC_POINTERS) return -E2BIG;
    if (count<=a->capacity) return 0;
    size_t capacity=a->capacity;
    while (capacity<count) {
        capacity*=2;
        if (capacity>MD_EXEC_POINTERS) capacity=MD_EXEC_POINTERS;
    }
    long memory=RAW6(mmap,0,capacity*sizeof(char *),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (memory<0) return (int)memory;
    memcpy((void *)memory,a->values,(a->count+1)*sizeof(char *));
    if (a->values!=a->local) RAW2(munmap,a->values,a->capacity*sizeof(char *));
    a->values=(char **)memory; a->capacity=capacity;
    return 0;
}
int md_arguments_read(struct md_arguments *a,char *const *input) {
    if (!input) return 0;
    uintptr_t address=(uintptr_t)input;
    for (;;) {
        char *chunk[64];
        size_t bytes=md_page_size-address%md_page_size;
        if (bytes>sizeof(chunk)) bytes=sizeof(chunk);
        /* An unaligned pointer may straddle pages; read that pointer alone. */
        size_t count=bytes/sizeof(char *);
        if (!count) count=1;
        bytes=count*sizeof(char *);
        if (address>UINTPTR_MAX-bytes) return -EFAULT;
        long r=md_read_memory(chunk,(const void *)address,bytes);
        if (r<0) return (int)r;
        size_t n=0;
        while (n<count && chunk[n]) ++n;
        r=md_arguments_reserve(a,a->count+n+1);
        if (r<0) return (int)r;
        memcpy(a->values+a->count,chunk,n*sizeof(char *));
        a->count+=n; a->values[a->count]=NULL;
        if (n<count) return 0;
        address+=bytes;
    }
}
void md_arguments_close(struct md_arguments *a) {
    if (a->values!=a->local) RAW2(munmap,a->values,a->capacity*sizeof(char *));
    md_arguments_init(a);
}
