.text
.global _start
_start:
    mov x19,#2000
    mov x21,#172
    mrs x20,tpidr_el0
    cbnz x20,fail
    sub sp,sp,#16
    str x21,[sp]
loop:
    mov x8,#172
    svc #0
    cmp x0,#0
    b.le fail
    mov w8,#172
    svc #0
    mov x8,x21
    svc #0
    mov x8,#172
    mov x0,xzr
    svc #0
    /* Relocating this load requires the signal-PC map, not just an opcode match. */
    ldr x8,[sp]
    svc #0
    /* An incoming edge can bypass the replaced predecessor. Count actual
     * trampoline visits separately from calls at a site with a patched prefix. */
    mov x8,#172
    tbnz x19,#0,direct_svc
    mov x8,#172
direct_svc:
    svc #0
    /* Adjacent data deliberately encodes a valid MOV. Executing SVC does
     * not authorize rewriting this word: it is never entered as code. */
    mov x8,#172
    b after_literal
literal:
    .word 0xd2801588
after_literal:
    svc #0
    adr x9,literal
    ldr w10,[x9]
    mov w11,#0x1588
    movk w11,#0xd280,lsl #16
    cmp w10,w11
    b.ne fail
    subs x19,x19,#1
    b.ne loop
    add sp,sp,#16
    adr x9,embedded_data
    ldr w10,[x9]
    mov w11,#1
    movk w11,#0xd400,lsl #16
    cmp w10,w11
    b.ne fail
    mov x0,#1
    adr x1,message
    mov x2,#message_end-message
    mov x8,#64
    svc #0
    mov x0,#0
    b exit
fail:
    mov x0,#1
exit:
    mov x8,#94
    svc #0
.balign 4
embedded_data:
    .word 0xd4000001
message:
    .ascii "PASS raw assembly: zero TLS, opcode variants, incoming SVC edge and embedded data\n"
message_end:
.section .note.GNU-stack,"",%progbits
