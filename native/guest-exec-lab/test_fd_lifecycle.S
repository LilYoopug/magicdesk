.text
.p2align 2
.global md_lifecycle_bridge
.type md_lifecycle_bridge, %function
md_lifecycle_bridge:
    mov x16, x0
    ldp x0, x1, [x16]
    ldp x2, x3, [x16, #16]
    ldp x4, x5, [x16, #32]
    ldp x6, x7, [x16, #48]
.global md_lifecycle_bridge_trap
md_lifecycle_bridge_trap:
    brk #0
    stp x0, x1, [x16]
    stp x2, x3, [x16, #16]
    stp x4, x5, [x16, #32]
    stp x6, x7, [x16, #48]
    ret
.size md_lifecycle_bridge, .-md_lifecycle_bridge

.p2align 2
.global md_lifecycle_open
.type md_lifecycle_open, %function
md_lifecycle_open:
    mov x4, x1
    mov x1, x0
    mov x0, #-100
    cbz x4, 1f
    mov w0, #-100
1:
    mov x2, #0x280000
    mov x3, xzr
    mov x8, #56
.global md_lifecycle_open_gate
md_lifecycle_open_gate:
    brk #1
.global md_lifecycle_open_call
md_lifecycle_open_call:
    svc #0
.global md_lifecycle_open_return
md_lifecycle_open_return:
    brk #2
    ret
.size md_lifecycle_open, .-md_lifecycle_open
.section .note.GNU-stack,"",%progbits
