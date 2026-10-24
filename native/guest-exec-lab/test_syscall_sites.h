#pragma once
#include <assert.h>

/* Distinct executed SVCs, not compiler-merged copies of one syscall wrapper. */
enum { MD_TEST_SYSCALL_SITES=32, MD_TEST_SYSCALL_STRIDE=16 };
extern const char md_test_syscall_sites[];
__asm__(".pushsection .text\n.balign 16\n.global md_test_syscall_sites\n"
    "md_test_syscall_sites:\n.rept 32\nmov x8,x6\nsvc #0\nret\nnop\n.endr\n.popsection\n");
typedef long (*md_test_syscall_fn)(unsigned long,unsigned long,unsigned long,
    unsigned long,unsigned long,unsigned long,long);
static md_test_syscall_fn md_test_syscall_site(unsigned site) {
    assert(site<MD_TEST_SYSCALL_SITES);
    return (md_test_syscall_fn)(md_test_syscall_sites+site*MD_TEST_SYSCALL_STRIDE);
}
