#ifndef MD_LAB_SVC_SIGNAL_H
#define MD_LAB_SVC_SIGNAL_H
#include <sys/types.h>
#include <stdint.h>
#include "signal_delivery.h"
struct md_svc_signal_window;
struct md_svc_registry;
void md_svc_signal_source(struct md_svc_registry *(*)(pid_t));
int md_svc_signal_window_at(pid_t,uintptr_t pc,uintptr_t sp,struct md_svc_signal_window *);
int md_svc_signal_window(pid_t,struct md_svc_signal_window *);
/* Stopped participant: arm an exit only when inside the private entry. */
int md_svc_signal_drain(pid_t,const struct md_svc_signal_window *,int);
uint64_t md_svc_signal_mask(pid_t,uint64_t);
uint64_t md_svc_signal_saved_mask(pid_t,uint64_t);
/* Opt-in proof owner, compiled only in a dedicated fixture runtime. It borrows
 * free hardware slots only while deferring one signal, never a second tracer.
 * Production needs admitted mapping generations instead of the lab descriptor. */
int md_svc_signal_event(pid_t pid,int status,int *deliver,struct md_signal_delivery *);
int md_svc_signal_syscall(pid_t);
void md_svc_signal_forget(pid_t pid);
int md_svc_signal_pending(pid_t pid);
void md_svc_signal_report(void);
int md_svc_signal_revoke(pid_t pid);
int md_svc_signal_retire(pid_t pid);
#endif
