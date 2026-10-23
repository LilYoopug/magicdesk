.global _start
.text
_start:
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $message_end-message, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
message:
    .ascii "BINFMT_QEMU_X86_64_OK\n"
message_end:
