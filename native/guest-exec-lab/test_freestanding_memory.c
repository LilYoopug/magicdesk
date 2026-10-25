#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned char *guarded(size_t size) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    unsigned char *p=mmap(NULL,size+2*page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED && !mprotect(p+page,size,PROT_READ|PROT_WRITE));
    return p+page;
}
int main(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    unsigned char *a=guarded(page),*b=guarded(page),expected[512];
    for (size_t n=0;n<=257;++n) for (size_t src=0;src<16;++src) for (size_t dst=0;dst<16;++dst) {
        for (size_t i=0;i<page;++i) { a[i]=(unsigned char)(i*7+11); b[i]=0xa5; }
        assert(memcpy(b+dst,a+src,n)==b+dst);
        for (size_t i=0;i<page;++i)
            assert(b[i]==(i>=dst && i<dst+n ? a[src+i-dst] : 0xa5));
        assert(memset(b+dst,0x123,n)==b+dst);
        for (size_t i=0;i<page;++i) assert(b[i]==(i>=dst && i<dst+n ? 0x23 : 0xa5));
    }
    for (size_t n=0;n<=page;++n) {
        assert(memcpy(b+page-n,a+page-n,n)==b+page-n);
        assert(!memcmp(b+page-n,a+page-n,n));
        assert(memset(b+page-n,0,n)==b+page-n);
        for (size_t i=page-n;i<page;++i) assert(!b[i]);
    }
    for (size_t n=0;n<=256;++n) for (size_t shift=0;shift<64;++shift) {
        for (unsigned reverse=0;reverse<2;++reverse) {
            for (size_t i=0;i<sizeof(expected);++i) expected[i]=a[i]=(unsigned char)(i*13+3);
            size_t src=reverse ? shift : 0,dst=reverse ? 0 : shift;
            for (size_t i=0;i<n;++i) expected[dst+i]=a[src+i];
            assert(memmove(a+dst,a+src,n)==a+dst);
            assert(!memcmp(a,expected,sizeof(expected)));
        }
        /* Overlap directly against the inaccessible upper boundary. */
        for (size_t i=0;i<page;++i) a[i]=(unsigned char)i;
        assert(memmove(a+page-n,a+page-n-shift,n)==a+page-n);
        for (size_t i=0;i<n;++i) assert(a[page-n+i]==(unsigned char)(page-n-shift+i));
    }
    assert(!munmap(a-page,3*page) && !munmap(b-page,3*page));
    puts("PASS freestanding memory: alignment, overlap, canaries and guard pages");
}
