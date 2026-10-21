#ifndef MD_SVC_MACHINE_H
#define MD_SVC_MACHINE_H
#include "svc_registry.h"
#include <signal.h>
#include "signal_delivery.h"

struct md_svc_held_signal;
struct md_svc_machine_thread {
    struct md_svc_held_signal *signals;
    unsigned carriers[NSIG];
    int syscall_exit, draining;
    uintptr_t retry_svc;
    uint64_t retry_number;
    struct user_pt_regs restored;
};
struct md_svc_registry *md_svc_machine_admit(pid_t,uintptr_t descriptor);
int md_svc_machine_return(struct md_svc_registry *,struct md_svc_machine_thread *,pid_t,struct user_pt_regs *);
/* 1 consumes the original syscall entry; 0 leaves an unrelated stop to its
 * existing owner. Both retire the temporary retry observer. */
int md_svc_machine_retry(struct md_svc_registry *,struct md_svc_machine_thread *,pid_t);
void md_svc_machine_forget(struct md_svc_machine_thread *);
/* The supervisor retains resume ownership. A handled checkpoint requests one
 * syscall-exit stop; the common signal queue owns subsequent delivery. */
int md_svc_machine_syscall(struct md_svc_registry *,struct md_svc_machine_thread *,pid_t);
int md_svc_machine_exit(struct md_svc_machine_thread *,pid_t,pid_t group);
int md_svc_machine_signal(struct md_svc_registry *,struct md_svc_machine_thread *,pid_t,
    struct md_signal_delivery *,int *deliver);
/* Reconstruct the guest continuation before publishing queued signals.
 * Return 1 while a native operation must first reach its owned checkpoint. */
int md_svc_machine_flush(struct md_svc_registry *,struct md_svc_machine_thread *,pid_t);
/* Cold filter fence: all entries have been revoked and this task is stopped.
 * Adapter/syscall continuations must finish before reconstructing registers. */
int md_svc_machine_drain(struct md_svc_registry *,struct md_svc_machine_thread *,pid_t,
    const struct user_pt_regs *adapter,int syscall_stop);
#endif
