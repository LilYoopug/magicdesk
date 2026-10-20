#include "svc_borrowed.h"
#include "svc_frame.inc"
.arch_extension lse
.text
.balign 16
.global md_svc_edge_begin,md_svc_edge_end
.global md_svc_edge_prefix,md_svc_edge_return,md_svc_edge_dispatch
.global md_svc_edge_state
.global md_svc_edge_done_branch,md_svc_edge_kernel_branch,md_svc_edge_busy_branch
.macro edge_slot
    md_svc_slot x30
.endm
md_svc_edge_begin:
    edge_slot
    swpal x30,x30,[x30]
    cbnz x30,edge_busy
    ldr x30,md_svc_edge_return
md_svc_edge_prefix:
    .rept 16
    nop
    .endr
    edge_slot
    add x30,x30,#MD_SVC_FRAME_OFFSET
    md_svc_save_gprs x30
    ldr x0,md_svc_edge_return
    str x0,[x30,#240]
    sub x0,x0,#4
    str x0,[x30,#MD_SVC_OWNER_OFFSET-MD_SVC_FRAME_OFFSET]
    mrs x0,nzcv
    str x0,[x30,#248]
    mov x0,sp
    str x0,[x30,#MD_SVC_SAVED_SP-MD_SVC_FRAME_OFFSET]
    mov x0,x30
    sub x30,x30,#MD_SVC_FRAME_OFFSET
    add sp,x30,#16,lsl#12
    ldr x16,md_svc_edge_dispatch
    ldr x1,md_svc_edge_state
    blr x16
    sub x30,sp,#16,lsl#12
    add x30,x30,#MD_SVC_FRAME_OFFSET
    adr x1,edge_done
    cbnz w0,1f
    adr x1,edge_kernel
1:  str x1,[x30,#272]
    ldr x1,[x30,#MD_SVC_SAVED_SP-MD_SVC_FRAME_OFFSET]
    mov sp,x1
    ldr x1,[x30,#248]
    msr nzcv,x1
    md_svc_restore_gprs x30
    ldr x30,[x30,#272]
    br x30
edge_done:
    edge_slot
    stlr xzr,[x30]
    ldr x30,md_svc_edge_return
md_svc_edge_done_branch:
    b .
edge_kernel:
    edge_slot
    stlr xzr,[x30]
    ldr x30,md_svc_edge_return
md_svc_edge_kernel_branch:
    b .
edge_busy:
    ldr x30,md_svc_edge_return
md_svc_edge_busy_branch:
    b .
.balign 8
md_svc_edge_return:
    .quad 0
md_svc_edge_dispatch:
    .quad 0
md_svc_edge_state:
    .quad 0
md_svc_edge_end:
.section .note.GNU-stack,"",%progbits
