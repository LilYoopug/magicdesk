#include "interception.h"
#include "raw.h"
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

/* Installed only when a launch first uses a PID namespace. The runtime gate
 * retains native IDs for its own proc access and transport credentials. */
long md_pid_filter_install(void) {
    uintptr_t gate=(uintptr_t)md_raw_return;
#define PROCESS(name) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##name,0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_PROCESS),
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)(gate>>32),0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)gate,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        PROCESS(getpid) PROCESS(gettid) PROCESS(getppid) PROCESS(set_tid_address)
        PROCESS(kill) PROCESS(tkill) PROCESS(tgkill) PROCESS(wait4) PROCESS(waitid)
        PROCESS(getpgid) PROCESS(getsid) PROCESS(setpgid) PROCESS(setsid)
        PROCESS(pidfd_open) PROCESS(pidfd_send_signal) PROCESS(rt_sigqueueinfo) PROCESS(rt_tgsigqueueinfo) PROCESS(rt_sigtimedwait)
        PROCESS(sched_getaffinity) PROCESS(sched_setaffinity) PROCESS(sched_getparam) PROCESS(sched_setparam)
        PROCESS(sched_getscheduler) PROCESS(sched_setscheduler) PROCESS(sched_getattr) PROCESS(sched_setattr)
        PROCESS(sched_rr_get_interval) PROCESS(get_robust_list) PROCESS(prlimit64)
        PROCESS(process_vm_readv) PROCESS(process_vm_writev) PROCESS(kcmp)
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_CHILD_SUBREAPER,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_GET_CHILD_SUBREAPER,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_PROCESS),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
#undef PROCESS
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    long result=RAW3(seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&program);
    if (result>0) return -ENOTSUP;
    return result ? result : RAW2(prctl,MD_GUEST_PID_FILTER,1);
}
