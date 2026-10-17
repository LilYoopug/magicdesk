#include <sysdep.h>

/* Entered with Linux registers after the caller checked the runtime offer.
 * The frame exists only for offered calls, never for clone/rt_sigreturn. */
ENTRY (__shroot_syscall_asm)
    stp x29, x30, [sp, #-64]!
    cfi_adjust_cfa_offset (64)
    cfi_rel_offset (x29, 0)
    cfi_rel_offset (x30, 8)
    mov x29, sp
    stp x0, x1, [sp, #16]
    stp x2, x3, [sp, #32]
    stp x4, x5, [sp, #48]
    mov x0, x8
    add x1, sp, #16
    bl __shroot_syscall
    ldp x29, x30, [sp], #64
    cfi_restore (x29)
    cfi_restore (x30)
    cfi_adjust_cfa_offset (-64)
    ret
END (__shroot_syscall_asm)
