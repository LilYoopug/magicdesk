#include "svc_borrowed.h"
#include "svc_frame.inc"
.arch_extension lse
.text
.macro slot reg
    md_svc_slot \reg
.endm

.macro borrowed name, pair
.global \name
\name:
    slot x8
.if \pair
    mov x7,xzr
    casal x7,x8,[x8]
    cbnz x7,\name\()_busy
.else
    swpal x8,x8,[x8]
    cbnz x8,\name\()_busy
    slot x8
.endif
    str x30,[x8,#MD_SVC_FRAME_OFFSET+240]
.if \pair
    mov x7,xzr
.endif
    mov x8,x6
    slot x30
    add x30,x30,#MD_SVC_FRAME_OFFSET
    md_svc_save_gprs x30
    mrs x8,nzcv
    str x8,[x30,#248]
    mov x8,sp
    str x8,[x30,#MD_SVC_SAVED_SP-MD_SVC_FRAME_OFFSET]
    mov x0,x30
    sub x30,x30,#MD_SVC_FRAME_OFFSET
    add sp,x30,#16,lsl#12
    bl md_svc_lab_dispatch
    sub x8,sp,#16,lsl#12
    add x8,x8,#MD_SVC_FRAME_OFFSET
    adr x30,\name\()_complete
    cbnz w0,1f
    adr x30,\name\()_fallback
1:
.if \pair
    ldr x9,[x8,#64]
    add x9,x9,#1
    cbnz x9,3f
    mov x9,#1
    adr x30,\name\()_complete_max
    cbnz w0,3f
    adr x30,\name\()_fallback_max
3:  stur x9,[x8,#-MD_SVC_FRAME_OFFSET]
.endif
    str x30,[x8,#272]
    ldr x30,[x8,#MD_SVC_SAVED_SP-MD_SVC_FRAME_OFFSET]
    mov sp,x30
    ldr x30,[x8,#248]
    msr nzcv,x30
    ldp x0,x1,[x8,#0]
    ldp x2,x3,[x8,#16]
    ldp x4,x5,[x8,#32]
    ldp x6,x7,[x8,#48]
    ldr x9,[x8,#72]
    ldp x10,x11,[x8,#80]
    ldp x12,x13,[x8,#96]
    ldp x14,x15,[x8,#112]
    ldp x16,x17,[x8,#128]
    ldp x18,x19,[x8,#144]
    ldp x20,x21,[x8,#160]
    ldp x22,x23,[x8,#176]
    ldp x24,x25,[x8,#192]
    ldp x26,x27,[x8,#208]
    ldp x28,x29,[x8,#224]
    ldr x30,[x8,#272]
    br x30
.macro release_\name target, max=0
    ldr x30,[x8,#240]
    sub x8,x8,#MD_SVC_FRAME_OFFSET
.if \pair
    /* Contenders use CAS(0), so cannot overwrite this encoded last register.
     * Clearing the lock and loading it is one indivisible operation. */
    swpal xzr,x8,[x8]
.if \max
    mov x8,#-1
.else
    sub x8,x8,#1
.endif
.else
    stlr xzr,[x8]
    /* No access to the borrowed frame is permitted after release. */
    mov x8,x6
.endif
    b \target
.endm
\name\()_complete:
    release_\name md_svc_lab_call+4
\name\()_fallback:
    release_\name md_svc_lab_call
.if \pair
\name\()_complete_max:
    release_\name md_svc_lab_call+4, 1
\name\()_fallback_max:
    release_\name md_svc_lab_call, 1
.endif
\name\()_busy:
.if \pair
    mov x7,xzr
.endif
    mov x8,x6
    b md_svc_lab_call
.endm

/* The one-register form requires a nonfaulting, replayable MOV. The two-dead-
 * register form can restore any final value, without rereading guest memory. */
borrowed md_svc_lab_borrowed_stub, 0
borrowed md_svc_lab_pair_stub, 1
.section .note.GNU-stack,"",%progbits
