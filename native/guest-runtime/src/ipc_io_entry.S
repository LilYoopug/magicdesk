.text
.global md_ipc_io_syscall
.type md_ipc_io_syscall, %function
md_ipc_io_syscall:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
.global md_ipc_io_begin
md_ipc_io_begin:
    ldar w9, [x6]
    cbnz w9, md_ipc_io_cancelled
    svc #0
.global md_ipc_io_end
md_ipc_io_end:
    ret
.global md_ipc_io_cancelled
md_ipc_io_cancelled:
    mov x0, #-4
    ret
.size md_ipc_io_syscall, .-md_ipc_io_syscall
.section .note.GNU-stack,"",%progbits
