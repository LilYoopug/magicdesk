#include "svc_borrowed.h"
#include "svc_frame.inc"
.arch_extension lse
.text
.balign 16
.global md_svc_single_begin,md_svc_single_end,md_svc_single_prefix
.global md_svc_single_dispatch,md_svc_single_done_branch,md_svc_single_kernel_branch
.global md_svc_single_state
.global md_svc_single_owner
.global md_svc_single_busy_branch,md_svc_single_done_replay,md_svc_single_kernel_replay,md_svc_single_busy_replay
.macro single_mark name,n
.if \n == 1
.global md_svc_single_\name
md_svc_single_\name:
.endif
.endm
.macro single_entry n
.if \n == 1
md_svc_single_begin:
.endif
    md_svc_slot x\n
    single_mark claim,\n
    swpal x\n,x\n,[x\n]
    single_mark claimed,\n
    cbnz x\n,single_busy_\n
    single_mark owned,\n
    md_svc_slot x\n
    str x30,[x\n,#MD_SVC_FRAME_OFFSET+240]
.if \n == 1
md_svc_single_prefix:
.endif
    nop
    single_mark borrow_lr,\n
    md_svc_slot x30
    add x30,x30,#MD_SVC_FRAME_OFFSET
    md_svc_save_gprs x30
    single_mark saved_gprs,\n
    ldr x1,single_owner_\n
    str x1,[x30,#MD_SVC_OWNER_OFFSET-MD_SVC_FRAME_OFFSET]
    mrs x8,nzcv
    str x8,[x30,#248]
    mov x8,sp
    str x8,[x30,#MD_SVC_SAVED_SP-MD_SVC_FRAME_OFFSET]
    single_mark saved_sp,\n
    mov x0,x30
    sub x30,x30,#MD_SVC_FRAME_OFFSET
    add sp,x30,#16,lsl#12
    ldr x16,single_dispatch_\n
    ldr x1,single_state_\n
    single_mark invoke,\n
    blr x16
    single_mark returned,\n
    sub x\n,sp,#16,lsl#12
    add x\n,x\n,#MD_SVC_FRAME_OFFSET
    adr x30,single_done_\n
    cbnz w0,1f
    adr x30,single_kernel_\n
1:  str x30,[x\n,#272]
    single_mark outcome,\n
    ldr x30,[x\n,#MD_SVC_SAVED_SP-MD_SVC_FRAME_OFFSET]
    mov sp,x30
    ldr x30,[x\n,#248]
    msr nzcv,x30
    md_svc_restore_gprs x\n,\n
    ldr x30,[x\n,#272]
    br x30
single_done_\n:
    single_mark done,\n
    ldr x30,[x\n,#240]
    sub x\n,x\n,#MD_SVC_FRAME_OFFSET
    stlr xzr,[x\n]
.if \n == 1
md_svc_single_done_replay:
.endif
    nop
.if \n == 1
md_svc_single_done_branch:
.endif
    b .
single_kernel_\n:
    single_mark kernel,\n
    ldr x30,[x\n,#240]
    sub x\n,x\n,#MD_SVC_FRAME_OFFSET
    stlr xzr,[x\n]
.if \n == 1
md_svc_single_kernel_replay:
.endif
    nop
.if \n == 1
md_svc_single_kernel_branch:
.endif
    b .
single_busy_\n:
.if \n == 1
md_svc_single_busy_replay:
.endif
    nop
.if \n == 1
md_svc_single_busy_branch:
.endif
    b .
.balign 8
.if \n == 1
md_svc_single_dispatch:
.endif
single_dispatch_\n:
    .quad 0
.if \n == 1
md_svc_single_state:
.endif
single_state_\n:
    .quad 0
.if \n == 1
md_svc_single_owner:
.endif
single_owner_\n:
    .quad 0
.if \n == 1
md_svc_single_end:
.endif
.endm
.irp n,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
single_entry \n
.endr
.section .note.GNU-stack,"",%progbits
