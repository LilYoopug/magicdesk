#ifndef MD_SIGNAL_DELIVERY_H
#define MD_SIGNAL_DELIVERY_H
#include <signal.h>
#include <sys/types.h>
#include <stdint.h>
#include <asm/ptrace.h>

struct md_signal_delivery_node;
struct md_signal_delivery {
    struct md_signal_delivery_node *first,*last;
    uint64_t mask;
    struct user_pt_regs registers;
    uintptr_t gate;
    int active, preparing, syscall_boundary;
};
/* Event-loop-owned standard signals which interrupted a shielded internal
 * operation. Coalesce without losing the first siginfo. Realtime signals stay
 * blocked in the kernel; these helpers must not move them behind later peers. */
int md_signal_delivery_hold(struct md_signal_delivery *,const siginfo_t *);
/* Start only at a restored guest boundary. An unexecuted syscall is cancelled
 * and rewound at its exit, so delivery cannot consume it or corrupt its result.
 * Resume preparing with SYSCALL, active with SINGLESTEP through the owned NOP. */
int md_signal_delivery_publish(struct md_signal_delivery *,pid_t tid,uintptr_t step_gate);
/* 1 owns this delivery stop and supplies its resume signal, 0 leaves an
 * unrelated event unchanged, negative errno reports failure. */
int md_signal_delivery_event(struct md_signal_delivery *,pid_t tid,int signal,int *deliver);
void md_signal_delivery_clear(struct md_signal_delivery *);
#endif
