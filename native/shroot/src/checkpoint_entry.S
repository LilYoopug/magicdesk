#include <asm/unistd.h>
.text
.balign 4
/* x8 is caller-clobbered. ARM64 replaces x0 before ptrace for syscall(-1),
 * so C control entries must supply a number, even when the SVC is skipped. */
.macro CONTROL name
.global \name
.type \name, %function
\name:
    mov x8, #__NR_gettid
.global \name\()_checkpoint
\name\()_checkpoint:
    svc #0
    ret
.size \name, .-\name
.endm
CONTROL md_guest_ready
CONTROL md_guest_done
CONTROL md_guest_exported
CONTROL md_guest_export_control
CONTROL md_guest_fd_control
CONTROL md_guest_buffer_control
/* Same checkpoint, with the standard two-register C aggregate return ABI. */
.global md_guest_buffer_start
.set md_guest_buffer_start, md_guest_buffer_control
CONTROL md_guest_task_control
.section .note.GNU-stack,"",%progbits
