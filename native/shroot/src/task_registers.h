#ifndef MD_TASK_REGISTERS_H
#define MD_TASK_REGISTERS_H
#include <asm/ptrace.h>
#include <stdint.h>

/* A fresh continuation discards operands/NZCV, not the processor controls
 * selected by exec or the application (including SSBS). */
static inline struct user_pt_regs md_task_registers_entry(uint64_t pc,uint64_t sp,uint64_t pstate) {
    return (struct user_pt_regs){.pc=pc,.sp=sp,.pstate=pstate&~UINT64_C(0xf0000000)};
}
#endif
