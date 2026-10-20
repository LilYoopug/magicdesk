.text
.balign 16
.global md_svc_live_body_begin,md_svc_live_body_end
md_svc_live_body_begin:
    stp x29,x30,[sp,#-32]!
    stp x19,x20,[sp,#16]
    mov x19,x1
    mov x20,x0
1:  ldar w9,[x19]
    cbz w9,2f
    add x10,x19,#4
    mov w9,#1
    stlr w9,[x10]
    mov x0,x19
    mov x1,#128
    mov x2,#1
    mov x3,#0
    mov x8,#98
    svc #0
    b 1b
2:  ldr x16,[x19,#8]
    ldr x1,[x19,#16]
    mov x0,x20
    blr x16
    ldp x19,x20,[sp,#16]
    ldp x29,x30,[sp],#32
    ret
md_svc_live_body_end:
.global md_svc_live_stack_call
md_svc_live_stack_call:
    stp x19,x30,[sp,#-16]!
    mov x19,sp
    mov sp,x0
    mov x16,x1
    mov x1,x2
    mov x2,x3
    mov x0,#-100
    mov x3,#0
    mov x4,#0
    mov x5,#0
    mov x6,#79
    blr x16
    mov sp,x19
    ldp x19,x30,[sp],#16
    ret
.global md_svc_live_context_call
md_svc_live_context_call:
    stp x19,x30,[sp,#-16]!
    mov x19,sp
    add x9,x0,#832
    mov sp,x9
    mov x0,x1
    mov x1,x2
    bl md_svc_lab_context
    mov sp,x19
    ldp x19,x30,[sp],#16
    ret
.balign 16384
.macro file_call name,number
.global md_svc_live_\name
md_svc_live_\name:
    mov x8,#\number
    svc #0
    ret
.endm
file_call open,56
file_call close,57
file_call rename,38
file_call unlink,35
.section .note.GNU-stack,"",%progbits
