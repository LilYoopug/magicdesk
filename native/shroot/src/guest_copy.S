#include <asm-generic/errno.h>
.text
.balign 4
.global md_read_memory
.global md_write_memory
.type md_read_memory, %function
.type md_write_memory, %function
md_read_memory:
md_write_memory:
    cbz x2, 3f
.global md_guest_copy_begin
md_guest_copy_begin:
    /* Aligned words cannot cross a protection or tagging granule. Different
     * source/destination alignment retains exact byte-at-a-time faults. */
    eor x10, x0, x1
    tst x10, #7
    b.ne 2f
1:
    tst x0, #7
    b.eq 4f
    ldrb w9, [x1], #1
    strb w9, [x0], #1
    subs x2, x2, #1
    b.eq 3f
    b 1b
4:
    cmp x2, #8
    b.lo 5f
    ldr x9, [x1], #8
    str x9, [x0], #8
    sub x2, x2, #8
    b 4b
5:
    cbz x2, 3f
2:
    ldrb w9, [x1], #1
    strb w9, [x0], #1
    subs x2, x2, #1
    b.ne 2b
3:
    mov x0, #0
    ret
.size md_read_memory, .-md_read_memory
.size md_write_memory, .-md_write_memory
.balign 4
.global md_read_string
.type md_read_string, %function
md_read_string:
    /* Do not read beyond the terminator, even inside the same memory page. */
    cbz x2, 5f
    cbz x1, 4f
2:
    ldrb w9, [x2], #1
    strb w9, [x0], #1
    cbz w9, 3f
    subs x1, x1, #1
    b.ne 2b
4:
    mov x0, #-ENAMETOOLONG
    ret
5:
    mov x0, #-EFAULT
    ret
3:
    mov x0, #0
    ret
.size md_read_string, .-md_read_string
.global md_guest_copy_end
md_guest_copy_end:
.section .note.GNU-stack,"",%progbits
