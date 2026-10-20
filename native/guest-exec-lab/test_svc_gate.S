/* Laboratory gate: preserves the full base AArch64 register context.
 * Deliberately uses the caller's stack; this is NOT yet a runtime admission
 * rule for arbitrary stack-switching programs or extended SVE/SME state. */
.text
.balign 16384
.global md_svc_lab_raw
.type md_svc_lab_raw,%function
md_svc_lab_raw:
    mov x7,xzr
    mov x8,x6
.global md_svc_lab_call
md_svc_lab_call:
    svc #0
    ret
.macro svc_stub name, gate
.global \name
\name:
    mov x8,x6
    stp x16,x17,[sp,#-16]!
    adr x16,1f
    adr x17,2f
    b \gate
1:  ldp x16,x17,[sp],#16
    b md_svc_lab_call+4
2:  ldp x16,x17,[sp],#16
    b md_svc_lab_call
.endm
svc_stub md_svc_lab_stub, md_svc_lab_gate
svc_stub md_svc_lab_integer_stub, md_svc_lab_integer_gate
.size md_svc_lab_raw,.-md_svc_lab_raw
.balign 16384
.macro svc_gate name, vectors
\name:
.if \vectors
    sub sp,sp,#800
.else
    sub sp,sp,#288
.endif
    stp x0,x1,[sp,#0]
    stp x2,x3,[sp,#16]
    stp x4,x5,[sp,#32]
    stp x6,x7,[sp,#48]
    stp x8,x9,[sp,#64]
    stp x10,x11,[sp,#80]
    stp x12,x13,[sp,#96]
    stp x14,x15,[sp,#112]
    stp x16,x17,[sp,#128]
    stp x18,x19,[sp,#144]
    stp x20,x21,[sp,#160]
    stp x22,x23,[sp,#176]
    stp x24,x25,[sp,#192]
    stp x26,x27,[sp,#208]
    stp x28,x29,[sp,#224]
    str x30,[sp,#240]
    mrs x9,nzcv
    str x9,[sp,#248]
.if \vectors
    mrs x9,fpcr
    str x9,[sp,#256]
    mrs x9,fpsr
    str x9,[sp,#264]
    stp q0,q1,[sp,#288]
    stp q2,q3,[sp,#320]
    stp q4,q5,[sp,#352]
    stp q6,q7,[sp,#384]
    stp q8,q9,[sp,#416]
    stp q10,q11,[sp,#448]
    stp q12,q13,[sp,#480]
    stp q14,q15,[sp,#512]
    stp q16,q17,[sp,#544]
    stp q18,q19,[sp,#576]
    stp q20,q21,[sp,#608]
    stp q22,q23,[sp,#640]
    stp q24,q25,[sp,#672]
    stp q26,q27,[sp,#704]
    stp q28,q29,[sp,#736]
    stp q30,q31,[sp,#768]
.endif
    str x16,[sp,#272]
    str x17,[sp,#280]
    mov x0,sp
    bl md_svc_lab_dispatch
    cbz w0,3f
    ldr x16,[sp,#272]
    b 4f
3:  ldr x16,[sp,#280]
4:
.if \vectors
    ldp q0,q1,[sp,#288]
    ldp q2,q3,[sp,#320]
    ldp q4,q5,[sp,#352]
    ldp q6,q7,[sp,#384]
    ldp q8,q9,[sp,#416]
    ldp q10,q11,[sp,#448]
    ldp q12,q13,[sp,#480]
    ldp q14,q15,[sp,#512]
    ldp q16,q17,[sp,#544]
    ldp q18,q19,[sp,#576]
    ldp q20,q21,[sp,#608]
    ldp q22,q23,[sp,#640]
    ldp q24,q25,[sp,#672]
    ldp q26,q27,[sp,#704]
    ldp q28,q29,[sp,#736]
    ldp q30,q31,[sp,#768]
    ldr x9,[sp,#256]
    msr fpcr,x9
    ldr x9,[sp,#264]
    msr fpsr,x9
.endif
    ldr x9,[sp,#248]
    msr nzcv,x9
    ldp x0,x1,[sp,#0]
    ldp x2,x3,[sp,#16]
    ldp x4,x5,[sp,#32]
    ldp x6,x7,[sp,#48]
    ldp x8,x9,[sp,#64]
    ldp x10,x11,[sp,#80]
    ldp x12,x13,[sp,#96]
    ldp x14,x15,[sp,#112]
    ldp x18,x19,[sp,#144]
    ldp x20,x21,[sp,#160]
    ldp x22,x23,[sp,#176]
    ldp x24,x25,[sp,#192]
    ldp x26,x27,[sp,#208]
    ldp x28,x29,[sp,#224]
    ldr x30,[sp,#240]
.if \vectors
    add sp,sp,#800
.else
    add sp,sp,#288
.endif
    br x16
.endm
svc_gate md_svc_lab_gate, 1
svc_gate md_svc_lab_integer_gate, 0

.global md_svc_lab_context
.type md_svc_lab_context,%function
md_svc_lab_context:
    sub sp,sp,#832
    stp x0,x1,[sp,#0]
    stp x2,x3,[sp,#16]
    stp x4,x5,[sp,#32]
    stp x6,x7,[sp,#48]
    stp x8,x9,[sp,#64]
    stp x10,x11,[sp,#80]
    stp x12,x13,[sp,#96]
    stp x14,x15,[sp,#112]
    stp x16,x17,[sp,#128]
    stp x18,x19,[sp,#144]
    stp x20,x21,[sp,#160]
    stp x22,x23,[sp,#176]
    stp x24,x25,[sp,#192]
    stp x26,x27,[sp,#208]
    stp x28,x29,[sp,#224]
    str x30,[sp,#240]
    mrs x9,nzcv
    str x9,[sp,#248]
    mrs x9,fpcr
    str x9,[sp,#256]
    mrs x9,fpsr
    str x9,[sp,#264]
    stp q0,q1,[sp,#288]
    stp q2,q3,[sp,#320]
    stp q4,q5,[sp,#352]
    stp q6,q7,[sp,#384]
    stp q8,q9,[sp,#416]
    stp q10,q11,[sp,#448]
    stp q12,q13,[sp,#480]
    stp q14,q15,[sp,#512]
    stp q16,q17,[sp,#544]
    stp q18,q19,[sp,#576]
    stp q20,q21,[sp,#608]
    stp q22,q23,[sp,#640]
    stp q24,q25,[sp,#672]
    stp q26,q27,[sp,#704]
    stp q28,q29,[sp,#736]
    stp q30,q31,[sp,#768]
    str x1,[sp,#800]
    mov x16,x0
    ldp q0,q1,[x16,#288]
    ldp q2,q3,[x16,#320]
    ldp q4,q5,[x16,#352]
    ldp q6,q7,[x16,#384]
    ldp q8,q9,[x16,#416]
    ldp q10,q11,[x16,#448]
    ldp q12,q13,[x16,#480]
    ldp q14,q15,[x16,#512]
    ldp q16,q17,[x16,#544]
    ldp q18,q19,[x16,#576]
    ldp q20,q21,[x16,#608]
    ldp q22,q23,[x16,#640]
    ldp q24,q25,[x16,#672]
    ldp q26,q27,[x16,#704]
    ldp q28,q29,[x16,#736]
    ldp q30,q31,[x16,#768]
    ldr x9,[x16,#256]
    msr fpcr,x9
    ldr x9,[x16,#264]
    msr fpsr,x9
    ldr x9,[x16,#248]
    msr nzcv,x9
    ldp x0,x1,[x16,#0]
    ldp x2,x3,[x16,#16]
    ldp x4,x5,[x16,#32]
    ldp x6,x7,[x16,#48]
    ldp x8,x9,[x16,#64]
    ldp x10,x11,[x16,#80]
    ldp x12,x13,[x16,#96]
    ldp x14,x15,[x16,#112]
    ldp x18,x19,[x16,#144]
    ldp x20,x21,[x16,#160]
    ldp x22,x23,[x16,#176]
    ldp x24,x25,[x16,#192]
    ldp x26,x27,[x16,#208]
    ldp x28,x29,[x16,#224]
    ldr x17,[x16,#136]
    ldr x16,[x16,#128]
.global md_svc_lab_context_edge
md_svc_lab_context_edge:
    bl md_svc_lab_raw
.global md_svc_lab_context_return
md_svc_lab_context_return:
    str x16,[sp,#816]
    str x17,[sp,#824]
    ldr x16,[sp,#800]
    stp x0,x1,[x16,#0]
    stp x2,x3,[x16,#16]
    stp x4,x5,[x16,#32]
    stp x6,x7,[x16,#48]
    stp x8,x9,[x16,#64]
    stp x10,x11,[x16,#80]
    stp x12,x13,[x16,#96]
    stp x14,x15,[x16,#112]
    stp x16,x17,[x16,#128]
    stp x18,x19,[x16,#144]
    stp x20,x21,[x16,#160]
    stp x22,x23,[x16,#176]
    stp x24,x25,[x16,#192]
    stp x26,x27,[x16,#208]
    stp x28,x29,[x16,#224]
    str x30,[x16,#240]
    mrs x9,nzcv
    str x9,[x16,#248]
    mrs x9,fpcr
    str x9,[x16,#256]
    mrs x9,fpsr
    str x9,[x16,#264]
    stp q0,q1,[x16,#288]
    stp q2,q3,[x16,#320]
    stp q4,q5,[x16,#352]
    stp q6,q7,[x16,#384]
    stp q8,q9,[x16,#416]
    stp q10,q11,[x16,#448]
    stp q12,q13,[x16,#480]
    stp q14,q15,[x16,#512]
    stp q16,q17,[x16,#544]
    stp q18,q19,[x16,#576]
    stp q20,q21,[x16,#608]
    stp q22,q23,[x16,#640]
    stp q24,q25,[x16,#672]
    stp q26,q27,[x16,#704]
    stp q28,q29,[x16,#736]
    stp q30,q31,[x16,#768]
    ldr x9,[sp,#816]
    ldr x10,[sp,#824]
    stp x9,x10,[x16,#128]
    ldp q0,q1,[sp,#288]
    ldp q2,q3,[sp,#320]
    ldp q4,q5,[sp,#352]
    ldp q6,q7,[sp,#384]
    ldp q8,q9,[sp,#416]
    ldp q10,q11,[sp,#448]
    ldp q12,q13,[sp,#480]
    ldp q14,q15,[sp,#512]
    ldp q16,q17,[sp,#544]
    ldp q18,q19,[sp,#576]
    ldp q20,q21,[sp,#608]
    ldp q22,q23,[sp,#640]
    ldp q24,q25,[sp,#672]
    ldp q26,q27,[sp,#704]
    ldp q28,q29,[sp,#736]
    ldp q30,q31,[sp,#768]
    ldr x9,[sp,#256]
    msr fpcr,x9
    ldr x9,[sp,#264]
    msr fpsr,x9
    ldr x9,[sp,#248]
    msr nzcv,x9
    ldp x0,x1,[sp,#0]
    ldp x2,x3,[sp,#16]
    ldp x4,x5,[sp,#32]
    ldp x6,x7,[sp,#48]
    ldp x8,x9,[sp,#64]
    ldp x10,x11,[sp,#80]
    ldp x12,x13,[sp,#96]
    ldp x14,x15,[sp,#112]
    ldp x16,x17,[sp,#128]
    ldp x18,x19,[sp,#144]
    ldp x20,x21,[sp,#160]
    ldp x22,x23,[sp,#176]
    ldp x24,x25,[sp,#192]
    ldp x26,x27,[sp,#208]
    ldp x28,x29,[sp,#224]
    ldr x30,[sp,#240]
    add sp,sp,#832
    ret
.size md_svc_lab_context,.-md_svc_lab_context
.global md_svc_lab_small_stack
.type md_svc_lab_small_stack,%function
md_svc_lab_small_stack:
    stp x19,x30,[sp,#-16]!
    mov x19,sp
    mov sp,x0
    mov x0,#-100
    mov x3,#0
    mov x6,#79
.global md_svc_lab_small_edge
md_svc_lab_small_edge:
    bl md_svc_lab_raw
    mov sp,x19
    ldp x19,x30,[sp],#16
    ret
.size md_svc_lab_small_stack,.-md_svc_lab_small_stack
.global md_svc_lab_without_tls
.type md_svc_lab_without_tls,%function
md_svc_lab_without_tls:
    stp x19,x20,[sp,#-32]!
    str x30,[sp,#16]
    mov x19,sp
    mrs x20,tpidr_el0
    msr tpidr_el0,xzr
    mov sp,x0
    mov x0,#-100
    mov x3,#0
    mov x6,#79
.global md_svc_lab_tls_edge
md_svc_lab_tls_edge:
    bl md_svc_lab_raw
    msr tpidr_el0,x20
    mov sp,x19
    ldr x30,[sp,#16]
    ldp x19,x20,[sp],#32
    ret
.size md_svc_lab_without_tls,.-md_svc_lab_without_tls
.global md_svc_lab_edge_raw,md_svc_lab_work_edge,md_svc_lab_load_call
.type md_svc_lab_edge_raw,%function
md_svc_lab_edge_raw:
    sub sp,sp,#80
    str x30,[sp]
    str x6,[sp,#8]
    stp x0,x1,[sp,#16]
    stp x2,x3,[sp,#32]
    stp x4,x5,[sp,#48]
md_svc_lab_work_edge:
    bl md_svc_lab_load_args
    ldr x30,[sp]
    add sp,sp,#80
    ret
/* Ordinary load-only syscall wrapper, including the caller's saved LR. No
 * language-specific ABI is used by the edge planner to recognize it. */
md_svc_lab_load_args:
    ldr x8,[sp,#8]
    ldr x0,[sp,#16]
    ldr x1,[sp,#24]
    ldr x2,[sp,#32]
    ldr x3,[sp,#40]
    ldr x4,[sp,#48]
    ldr x5,[sp,#56]
md_svc_lab_load_call:
    svc #0
    ret
.size md_svc_lab_edge_raw,.-md_svc_lab_edge_raw
.global md_svc_lab_load_stack,md_svc_lab_fault_edge
md_svc_lab_load_stack:
    stp x19,x30,[sp,#-16]!
    mov x19,sp
    mov sp,x0
    mov x4,#0x4567
    mov x5,#0x5678
md_svc_lab_fault_edge:
    bl md_svc_lab_load_args
    mov sp,x19
    ldp x19,x30,[sp],#16
    ret
.section .note.GNU-stack,"",%progbits

