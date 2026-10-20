#define _GNU_SOURCE
#include "svc_discovery.h"
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

static int debug_set(pid_t pid,struct user_hwdebug_state *state) {
    unsigned count=state->dbg_info&255;
    if (count>16) return -ENOTSUP;
    struct iovec io={state,offsetof(struct user_hwdebug_state,dbg_regs)+count*sizeof(state->dbg_regs[0])};
    return ptrace(PTRACE_SETREGSET,pid,(void *)NT_ARM_HW_BREAK,&io)<0 ? -errno : 0;
}
int md_svc_discovery_cancel(struct md_svc_witness *w,pid_t pid) {
    if (!w->site) return 0;
    int error=debug_set(pid,&w->debug);
    if (!error || error==-ESRCH) w->site=NULL;
    return error;
}
int md_svc_discovery_observe(struct md_svc_registry *r,struct md_svc_witness *w,pid_t pid,
        uintptr_t svc,uintptr_t lr) {
    if (!r || r->disabled || w->site) return 0;
    struct md_svc_site *s=md_svc_registry_observe(r,svc);
    if (!s) return 0;
    int error=md_svc_registry_plan(r,s,pid,lr);
    if (error) return error;
    struct user_hwdebug_state debug;
    struct iovec io={&debug,sizeof(debug)};
    if (ptrace(PTRACE_GETREGSET,pid,(void *)NT_ARM_HW_BREAK,&io)<0) return -errno;
    unsigned count=debug.dbg_info&255,slot=16,free=0;
    if (count>16) return -ENOTSUP;
    for (unsigned i=0;i<count;++i) if (!(debug.dbg_regs[i].ctrl&1)) { if (slot==16) slot=i; ++free; }
    if (free<3) { s->state=MD_SVC_RETIRED; return -ENOSPC; }
    w->debug=debug;
    debug.dbg_regs[slot].addr=s->window.edge.call;
    debug.dbg_regs[slot].ctrl=(15u<<5)|(2u<<1)|1u;
    error=debug_set(pid,&debug);
    if (!error) w->site=s;
    else s->state=MD_SVC_RETIRED;
    return error;
}
int md_svc_discovery_event(struct md_svc_witness *w,pid_t pid,int status) {
    if (!w->site || !WIFSTOPPED(status) || (unsigned)status>>16 || WSTOPSIG(status)!=SIGTRAP) return 0;
    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO,pid,NULL,&info)<0) return -errno;
    if (info.si_code!=TRAP_HWBKPT) return 0;
    struct user_pt_regs regs; struct iovec io={&regs,sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return -errno;
    if (regs.pc!=w->site->window.edge.call) return 0;
    struct md_svc_site *site=w->site;
    int error=md_svc_discovery_cancel(w,pid);
    if (error) return error;
    site->state=MD_SVC_WITNESSED;
    return 1;
}
