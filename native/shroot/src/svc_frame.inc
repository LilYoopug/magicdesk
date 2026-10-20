.macro md_svc_slot reg
    mov \reg,sp
    eor \reg,\reg,\reg,lsr#16
    ubfx \reg,\reg,#8,#6
    movk \reg,#0,lsl#16
    movk \reg,#MD_SVC_POOL_HIGH,lsl#32
    movk \reg,#0,lsl#48
    bfi \reg,\reg,#16,#6
    and \reg,\reg,#0xffffffffffffffc0
.endm
.macro md_svc_save_gprs base
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
    str x\n,[\base,#8*\n]
    .endr
.endm
.macro md_svc_restore_gprs base, omit=-1
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
    .if \n != \omit
    ldr x\n,[\base,#8*\n]
    .endif
    .endr
.endm
