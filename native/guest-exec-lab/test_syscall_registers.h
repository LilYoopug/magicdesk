#ifndef MD_TEST_SYSCALL_REGISTERS_H
#define MD_TEST_SYSCALL_REGISTERS_H
#include <assert.h>
#include <errno.h>
#include <sys/syscall.h>

/* Use nonzero unused arguments and retain the syscall register. A syscall
 * adapter must preserve the machine context, not merely libc's return value. */
static long test_syscall_registers(long nr,unsigned long a0,unsigned long a1,unsigned long a2,unsigned long a3) {
    register unsigned long x0 __asm__("x0")=a0;
    register unsigned long x1 __asm__("x1")=a1;
    register unsigned long x2 __asm__("x2")=a2;
    register unsigned long x3 __asm__("x3")=a3;
    register unsigned long x4 __asm__("x4")=0x123456789abcdefUL;
    register unsigned long x5 __asm__("x5")=0xfedcba987654321UL;
    register unsigned long x6 __asm__("x6")=0x56789abcdef0123UL;
    register unsigned long x7 __asm__("x7")=0x987654321fedcbaUL;
    register unsigned long x8 __asm__("x8")=nr;
    unsigned long before,after;
    __asm__ volatile("cmp xzr, xzr\n\tmrs %9, nzcv\n\tsvc #0\n\tmrs %10, nzcv"
        : "+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3),"+r"(x4),"+r"(x5),"+r"(x6),"+r"(x7),"+r"(x8),
          "=&r"(before),"=&r"(after) : : "memory","cc");
    assert(x1==a1 && x2==a2 && x3==a3
        && x4==0x123456789abcdefUL && x5==0xfedcba987654321UL && x6==0x56789abcdef0123UL
        && x7==0x987654321fedcbaUL && x8==(unsigned long)nr && before==after);
    if (x0>=(unsigned long)-4095L) { errno=-(long)x0; return -1; }
    return (long)x0;
}
static inline int test_open_registers(int base,const char *path,int flags,unsigned mode) {
    return (int)test_syscall_registers(SYS_openat,(unsigned long)(long)base,(unsigned long)path,(unsigned)flags,mode);
}
#endif
