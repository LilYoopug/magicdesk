#ifndef MD_MEMORY_ADMISSION_H
#define MD_MEMORY_ADMISSION_H
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static inline int md_memory_native_arguments(long number,uint64_t protection,uint64_t flags) {
    if (number==SYS_munmap) return 1;
    /* For remap, argument 2 is the new length. Without FIXED/DONTUNMAP,
     * the kernel cannot overwrite an unrelated mapping or create an alias. */
    if (number==SYS_mremap) return protection && !(flags&~(uint64_t)MREMAP_MAYMOVE);
    if (number!=SYS_mprotect && number!=SYS_mmap) return 0;
    if (protection&~(uint64_t)(PROT_READ|PROT_WRITE|PROT_EXEC)) return 0;
    return number!=SYS_mmap || flags==(MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED);
}

enum { MD_MEMORY_ADMISSION_RANGES=64 };
/* Published only while the sole address-space owner is stopped. Sharing
 * revokes admission before another task can execute. Overflow declines. */
struct md_memory_admission {
    atomic_uint enabled;
    unsigned count;
    struct { uintptr_t first,end; } ranges[MD_MEMORY_ADMISSION_RANGES];
};
static inline int md_memory_admission_allows(const struct md_memory_admission *p,
        uintptr_t address,size_t size,size_t page) {
    if (!atomic_load_explicit(&p->enabled,memory_order_acquire)
            || !page || (page&(page-1)) || address&(page-1)
            || !size || size>SIZE_MAX-(page-1) || p->count>MD_MEMORY_ADMISSION_RANGES) return 0;
    size=(size+page-1)&~(page-1);
    if (address>UINTPTR_MAX-size) return 0;
    for (unsigned i=0;i<p->count && p->ranges[i].first<address+size;++i)
        if (p->ranges[i].end>address) return 0;
    return 1;
}
#endif
