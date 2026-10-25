#include <stddef.h>
#include <stdint.h>

/* AArch64 ordinary memory permits unaligned words. These internal-buffer
 * routines never touch beyond n or use SIMD; guarded guest copies are separate. */
typedef uint64_t word __attribute__((__may_alias__,__aligned__(1)));
void *memcpy(void *out,const void *in,size_t n) {
    unsigned char *d=out; const unsigned char *s=in;
    while (n>=sizeof(word)) {
        *(word *)d=*(const word *)s;
        d+=sizeof(word); s+=sizeof(word); n-=sizeof(word);
    }
    while (n--) *d++=*s++;
    return out;
}
void *memset(void *out,int value,size_t n) {
    unsigned char *d=out;
    word fill=UINT64_C(0x0101010101010101)*(unsigned char)value;
    while (n>=sizeof(word)) {
        *(word *)d=fill; d+=sizeof(word); n-=sizeof(word);
    }
    while (n--) *d++=(unsigned char)value;
    return out;
}
void *memmove(void *out,const void *in,size_t n) {
    unsigned char *d=out; const unsigned char *s=in;
    if ((uintptr_t)d<=(uintptr_t)s) return memcpy(out,in,n);
    while (n>=sizeof(word)) {
        n-=sizeof(word); *(word *)(d+n)=*(const word *)(s+n);
    }
    while (n) { --n; d[n]=s[n]; }
    return out;
}
