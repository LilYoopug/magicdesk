#include "cooperative_native.h"
.text
.global md_cooperative_native
.type md_cooperative_native, %function
md_cooperative_native:
    mov x9, x0
1:
    ldaxr w10, [x9]
    cmp w10, #MD_NATIVE_READY
    b.ne 2f
    mov w10, #MD_NATIVE_RUNNING
    stlxr w11, w10, [x9]
    cbnz w11, 1b
    ldr w8, [x9, #4]
    ldp x0, x1, [x9, #MD_NATIVE_ARGS]
    ldp x2, x3, [x9, #(MD_NATIVE_ARGS+16)]
    ldp x4, x5, [x9, #(MD_NATIVE_ARGS+32)]
.global md_cooperative_native_call
md_cooperative_native_call:
    svc #0
.global md_cooperative_native_return
md_cooperative_native_return:
    str x0, [x9, #MD_NATIVE_RESULT]
    mov w10, #MD_NATIVE_DONE
    stlr w10, [x9]
.global md_cooperative_native_end
md_cooperative_native_end:
    ret
2:
    clrex
    ret
.size md_cooperative_native, .-md_cooperative_native
