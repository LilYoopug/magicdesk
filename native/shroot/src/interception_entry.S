#include <asm/unistd.h>
.text
.global md_guest_entry_kernel
.type md_guest_entry_kernel, %function
md_guest_entry_kernel:
    /* This is an application syscall site, never the raw adapter gate.
     * Kernel seccomp sees the real number and all six original arguments. */
    mov x8, x0
    mov x9, x1
    ldp x0, x1, [x9]
    ldp x2, x3, [x9, #16]
    ldp x4, x5, [x9, #32]
    svc #0
    ret
.size md_guest_entry_kernel, .-md_guest_entry_kernel
.global md_guest_dispatch_entry
.type md_guest_dispatch_entry, %function
md_guest_dispatch_entry:
    /* The kernel restores x7 after ARM64 syscall stops. Supervisor policy
     * arrives in x9; only userspace turns it into the eighth C argument. */
    mov x7, x9
    b md_guest_dispatch
.size md_guest_dispatch_entry, .-md_guest_dispatch_entry
.global md_guest_task_control
.type md_guest_task_control, %function
md_guest_task_control:
    brk #0x5bd
    ret
.size md_guest_task_control, .-md_guest_task_control
.global md_guest_task_call
.global md_guest_task_collect
md_guest_task_collect:
    bl md_task_receive_collect
.global md_guest_task_collected
md_guest_task_collected:
    brk #0
md_guest_task_call:
    svc #0
.global md_guest_task_return
md_guest_task_return:
    brk #0x5be
.global md_guest_task_abort
md_guest_task_abort:
    mov x0, #0
    mov x8, #__NR_exit
    svc #0
.global md_guest_task_abort_return
md_guest_task_abort_return:
    brk #0x5bf
.global md_guest_export_control
.type md_guest_export_control, %function
md_guest_export_control:
    brk #0x5bc
    ret
.size md_guest_export_control, .-md_guest_export_control
.global md_guest_buffer_control
.type md_guest_buffer_control, %function
md_guest_buffer_control:
    brk #0x5bb
    ret
.size md_guest_buffer_control, .-md_guest_buffer_control
.global md_guest_buffer_admit
.type md_guest_buffer_admit, %function
md_guest_buffer_admit:
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x8, #__NR_gettid
    svc #0
.global md_guest_buffer_admitted
md_guest_buffer_admitted:
    ret
.size md_guest_buffer_admit, .-md_guest_buffer_admit
.global md_guest_open_anchor
.type md_guest_open_anchor, %function
md_guest_open_anchor:
    /* x4 selects cwd or a source FD for ordered provenance capture; the
     * kernel uses only openat's four arguments. */
    mov x8, #__NR_openat
    svc #0
.global md_guest_anchor_return
md_guest_anchor_return:
    ret
.size md_guest_open_anchor, .-md_guest_open_anchor
.global md_guest_fd_control
.type md_guest_fd_control, %function
md_guest_fd_control:
    brk #0x5ba
    ret
.size md_guest_fd_control, .-md_guest_fd_control
.global md_guest_ipc_wait
md_guest_ipc_wait:
    sub sp, sp, #16
    stp x1, x2, [sp]
    mov x2, sp
    cmp x3, #0
    csel x2, x2, xzr, ne
    mov x0, xzr
    mov x1, xzr
    mov x3, xzr
    mov x4, #8
    mov x8, #__NR_ppoll
    b md_raw_return - 4
.balign 4
.global md_guest_watch_gate
md_guest_watch_gate:
    svc #0
.global md_guest_watch_return
md_guest_watch_return:
    brk #0x5b7
.global md_guest_ready
.type md_guest_ready, %function
md_guest_ready:
    brk #0x5b0
    ret
.size md_guest_ready, .-md_guest_ready
.global md_guest_done
md_guest_done:
    brk #0x5b1
.global md_guest_exported
md_guest_exported:
    brk #0x5b3
.global md_guest_store
md_guest_store:
    stp x2, x3, [x0]
.global md_guest_stored
md_guest_stored:
    brk #0x5b4
.global md_guest_load_byte
md_guest_load_byte:
    ldrb w2, [x0]
.global md_guest_loaded_byte
md_guest_loaded_byte:
    brk #0x5b5
.global md_guest_store_ids
md_guest_store_ids:
    str w3, [x0]
    str w4, [x1]
    str w5, [x2]
.global md_guest_stored_ids
md_guest_stored_ids:
    brk #0x5b6
/* Bounded task-affine credential transfer, including nondumpable programs.
 * x0 points at 1..16 gids, x1 is their count, w3..w18 carry their values. */
.global md_guest_load_groups
md_guest_load_groups:
.irp reg,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
    ldr w\reg, [x0], #4
    subs x1, x1, #1
    b.eq md_guest_loaded_groups
.endr
.global md_guest_loaded_groups
md_guest_loaded_groups:
    brk #0x5b8
.global md_guest_store_groups
md_guest_store_groups:
.irp reg,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
    str w\reg, [x0], #4
    subs x1, x1, #1
    b.eq md_guest_stored_groups
.endr
.global md_guest_stored_groups
md_guest_stored_groups:
    brk #0x5b9
.global md_guest_allocate
.type md_guest_allocate, %function
md_guest_allocate:
    adrp x20, md_page_size
    ldr x20, [x20, :lo12:md_page_size]
    mov x0, #0
    mov x1, #0x80000
    add x1, x1, x20, lsl #1
    mov x2, #0
    mov x3, #0x22
    mov x4, #-1
    mov x5, #0
    mov x8, #__NR_mmap
    svc #0
    tbnz x0, #63, md_guest_allocated
    mov x19, x0
    add x0, x0, x20
    mov x1, #0x80000
    mov x2, #3
    mov x8, #__NR_mprotect
    svc #0
    tbnz x0, #63, 1f
    add x0, x19, #0x80000
    add x0, x0, x20
    b md_guest_allocated
1:
    mov x21, x0
    mov x0, x19
    mov x1, #0x80000
    add x1, x1, x20, lsl #1
    mov x8, #__NR_munmap
    svc #0
    mov x0, x21
.global md_guest_allocated
md_guest_allocated:
    brk #0x5b2
.size md_guest_allocate, .-md_guest_allocate
.section .note.GNU-stack,"",%progbits
