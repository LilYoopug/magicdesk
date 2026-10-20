#define _GNU_SOURCE
#include "svc_signal.h"
#include "svc_payload.h"
#include "svc_registry.h"
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

struct pending_signal {
    struct pending_signal *next;
    pid_t pid;
    uint64_t mask;
    siginfo_t info;
    struct user_hwdebug_state debug;
    uintptr_t exits[3];
};
static struct pending_signal *pending;
static uint64_t deferred,delivered,faults,kernel_aliases,kernel_entries;
static struct md_svc_registry *(*registry_source)(pid_t);
void md_svc_signal_source(struct md_svc_registry *(*source)(pid_t)) { registry_source=source; }
static struct md_svc_registry *registry(pid_t pid) { return registry_source ? registry_source(pid) : NULL; }
int md_svc_signal_pending(pid_t pid) {
    for (struct pending_signal *s=pending;s;s=s->next) if (s->pid==pid) return 1;
    return 0;
}
static int proof_enabled(void) {
    static int enabled=-1;
    if (enabled<0) { const char *value=getenv("MD_SVC_SIGNAL_PROOF"); enabled=value && !strcmp(value,"1"); }
    return enabled;
}
static int read_remote(pid_t pid,uintptr_t at,void *data,size_t size) {
    struct iovec local={data,size},remote={(void *)at,size};
    if (process_vm_readv(pid,&local,1,&remote,1,0)==(ssize_t)size) return 0;
    for (size_t i=0;i<size;i+=8) {
        errno=0; uint64_t value=ptrace(PTRACE_PEEKTEXT,pid,(void *)(at+i),NULL);
        if (errno) return -errno;
        memcpy((char *)data+i,&value,size-i<8 ? size-i : 8);
    }
    return 0;
}
static int debug_set(pid_t pid,struct user_hwdebug_state *state) {
    struct iovec io={state,offsetof(struct user_hwdebug_state,dbg_regs)+(state->dbg_info&255)*sizeof(state->dbg_regs[0])};
    return ptrace(PTRACE_SETREGSET,pid,(void *)NT_ARM_HW_BREAK,&io)<0 ? -errno : 0;
}
int md_svc_signal_window_at(pid_t pid,uintptr_t pc,uintptr_t sp,struct md_svc_signal_window *w) {
    struct md_svc_registry *r=registry(pid);
    if (r) {
        const struct md_svc_signal_window *found=md_svc_registry_at(r,pc);
        if (!found && sp>=r->frames && sp<r->frames+MD_SVC_POOL_SIZE) {
            uintptr_t frame=sp&~(uintptr_t)(MD_SVC_SLOT_SIZE-1),owner;
            uint64_t busy;
            if (!read_remote(pid,frame,&busy,sizeof(busy)) && busy
                    && !read_remote(pid,frame+MD_SVC_OWNER_OFFSET,&owner,sizeof(owner)))
                for (unsigned i=0;i<r->count;++i) if (r->sites[i].state==MD_SVC_PUBLISHED
                        && r->sites[i].window.edge.call==owner) { found=&r->sites[i].window; break; }
        }
        if (found) *w=*found;
        return found!=NULL;
    }
    return proof_enabled() && !read_remote(pid,MD_SVC_PAYLOAD_STATE+
        offsetof(struct md_svc_payload_state,window),w,sizeof(*w))
        && w->magic==MD_SVC_SIGNAL_MAGIC && w->edge.call && w->begin<w->end
        && w->edge.prefix_count<=16;
}
int md_svc_signal_window(pid_t pid,struct md_svc_signal_window *w) {
    struct user_pt_regs regs; struct iovec io={&regs,sizeof(regs)};
    if (registry(pid) && ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return 0;
    if (!registry(pid)) regs=(struct user_pt_regs){0};
    return md_svc_signal_window_at(pid,regs.pc,regs.sp,w);
}
void md_svc_signal_forget(pid_t pid) {
    struct pending_signal **at=&pending;
    while (*at) {
        if ((*at)->pid==pid) { struct pending_signal *s=*at; *at=s->next; free(s); return; }
        at=&(*at)->next;
    }
}
int md_svc_signal_revoke(pid_t pid) {
    struct md_svc_registry *r=registry(pid);
    if (r) {
        r->disabled=1;
        uint64_t zero=0;
        return md_svc_registry_write(pid,r->frames+MD_SVC_POOL_SIZE+
            offsetof(struct md_svc_payload_state,admitted),&zero,sizeof(zero));
    }
    if (!proof_enabled()) return 0;
    uint64_t magic;
    if (read_remote(pid,MD_SVC_PAYLOAD_STATE+offsetof(struct md_svc_payload_state,window.magic),&magic,sizeof(magic))
            || magic!=MD_SVC_SIGNAL_MAGIC) return 0;
    /* Conservative address-space admission: no helper is executed by any peer
     * after a filter commits. Per-thread retention needs a separate proof. */
    if (ptrace(PTRACE_POKEDATA,pid,(void *)(MD_SVC_PAYLOAD_STATE+offsetof(struct md_svc_payload_state,admitted)),NULL)<0
            || ptrace(PTRACE_POKEDATA,pid,(void *)(MD_SVC_PAYLOAD_STATE+offsetof(struct md_svc_payload_state,revoked)),(void *)1)<0)
        return -errno;
    return 0;
}
int md_svc_signal_retire(pid_t pid) {
    struct md_svc_registry *r=registry(pid);
    if (!r && !proof_enabled()) return 0;
    uintptr_t base=r ? r->frames+MD_SVC_POOL_SIZE : MD_SVC_PAYLOAD_STATE;
    struct md_svc_payload_state state;
    if (read_remote(pid,base,&state,sizeof(state))
            || (!r && state.window.magic!=MD_SVC_SIGNAL_MAGIC)) return 0;
    return md_svc_registry_retire_client(pid,base);
}
static uint64_t shield_mask(uint64_t original) {
    uint64_t mask=~UINT64_C(0);
    int sync[]={SIGKILL,SIGSTOP,SIGSEGV,SIGBUS,SIGILL,SIGFPE,SIGTRAP,SIGSYS};
    for (unsigned i=0;i<sizeof(sync)/sizeof(*sync);++i) mask&=~(UINT64_C(1)<<(sync[i]-1));
    /* arm64 forces owned execution breakpoints; blocking TRAP resets its disposition. */
    return (mask|original)&~(UINT64_C(1)<<(SIGTRAP-1));
}
static int arm(pid_t pid,const struct md_svc_signal_window *w,const siginfo_t *info) {
    struct pending_signal *s=calloc(1,sizeof(*s)); if (!s) return -ENOMEM;
    s->pid=pid; if (info) s->info=*info;
    s->exits[0]=w->edge.svc; s->exits[1]=w->edge.svc+4; s->exits[2]=w->edge.callee;
    struct iovec debug_io={&s->debug,sizeof(s->debug)};
    int error=0;
    if (ptrace(PTRACE_GETREGSET,pid,(void *)NT_ARM_HW_BREAK,&debug_io)<0
            || ptrace(PTRACE_GETSIGMASK,pid,(void *)sizeof(s->mask),&s->mask)<0) error=-errno;
    struct user_hwdebug_state armed=s->debug;
    unsigned used=0,count=armed.dbg_info&255;
    if (!error && count<=16) for (unsigned i=0;i<count && used<3;++i) if (!(armed.dbg_regs[i].ctrl&1)) {
        armed.dbg_regs[i].addr=s->exits[used++];
        armed.dbg_regs[i].ctrl=(15u<<5)|(2u<<1)|1u;
    }
    if (!error && used!=3) error=-ENOSPC;
    if (!error) error=debug_set(pid,&armed);
    uint64_t mask=shield_mask(s->mask);
    if (!error && ptrace(PTRACE_SETSIGMASK,pid,(void *)sizeof(mask),&mask)<0) {
        error=-errno; assert(!debug_set(pid,&s->debug));
    }
    if (error) { free(s); return error; }
    s->next=pending; pending=s;
    return 1;
}
uint64_t md_svc_signal_mask(pid_t pid,uint64_t mask) {
    for (struct pending_signal *s=pending;s;s=s->next) if (s->pid==pid) {
        s->mask=mask;
        return shield_mask(mask);
    }
    return mask;
}
uint64_t md_svc_signal_saved_mask(pid_t pid,uint64_t effective) {
    for (struct pending_signal *s=pending;s;s=s->next) if (s->pid==pid) return s->mask;
    return effective;
}
int md_svc_signal_drain(pid_t pid,const struct md_svc_signal_window *w,int forced) {
    if (md_svc_signal_pending(pid)) return 1;
    struct user_pt_regs r; struct iovec io={&r,sizeof(r)};
    if (ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return errno==ESRCH ? 0 : -errno;
    if (!forced && !(r.pc>=w->begin && r.pc<w->end)
            && !(r.sp>=w->edge.frames && r.sp<w->edge.frames+MD_SVC_POOL_SIZE)) return 0;
    return arm(pid,w,NULL);
}
int md_svc_signal_syscall(pid_t pid) {
    if (!registry(pid) && !proof_enabled()) return 0;
    struct user_pt_regs r; struct iovec io={&r,sizeof(r)};
    if (ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return errno==ESRCH ? 0 : -errno;
    struct md_svc_signal_window w;
    if (!md_svc_signal_window_at(pid,r.pc,r.sp,&w) || !w.kernel_alias || r.pc!=w.kernel_alias+4) return 0;
    /* Canonicalize before executing a blocking syscall. do_signal compares
     * its saved restart PC after the ptrace signal stop; changing that PC
     * at signal delivery would override the kernel's SA_RESTART decision. */
    r.pc=w.edge.svc+4;
    if (ptrace(PTRACE_SETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return -errno;
    ++kernel_entries;
    return 1;
}
int md_svc_signal_event(pid_t pid,int status,int *deliver,struct md_signal_delivery *queue) {
    if (!WIFSTOPPED(status) || (unsigned)status>>16 || WSTOPSIG(status)==(SIGTRAP|0x80)) return 0;
    if (!registry(pid) && !proof_enabled()) return 0;
    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO,pid,NULL,&info)<0) return errno==ESRCH ? 0 : -errno;
    struct user_pt_regs r;
    struct iovec io={&r,sizeof(r)};
    if (ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return errno==ESRCH ? 0 : -errno;
    struct pending_signal *s=pending;
    while (s && s->pid!=pid) s=s->next;
    struct md_svc_signal_window w;
    if (md_svc_signal_window(pid,&w) && w.kernel_alias
            && (r.pc==w.kernel_alias || r.pc==w.kernel_alias+4)
            && info.si_signo==SIGSYS && info.si_code==SYS_SECCOMP) {
        /* TRAP precedes TRACE and never executes the syscall. Other signals
         * must retain the kernel restart decision made at the original PC. */
        r.pc=w.edge.svc+(r.pc-w.kernel_alias);
        if (ptrace(PTRACE_SETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return -errno;
        if (info.si_signo==SIGSYS && info.si_code==SYS_SECCOMP
                && (uintptr_t)info.si_call_addr==w.kernel_alias+4) {
            info.si_call_addr=(void *)(w.edge.svc+4);
            if (ptrace(PTRACE_SETSIGINFO,pid,NULL,&info)<0) return -errno;
        }
        if (s) {
            int error=debug_set(pid,&s->debug);
            if (error) return error;
            if (ptrace(PTRACE_SETSIGMASK,pid,(void *)sizeof(s->mask),&s->mask)<0) return -errno;
            if (s->info.si_signo) {
                error=md_signal_delivery_hold(queue,&s->info);
                if (error) return error;
                ++delivered;
            }
            md_svc_signal_forget(pid);
        }
        ++kernel_aliases; *deliver=info.si_signo; return 1;
    }
    if ((info.si_signo==SIGSEGV || info.si_signo==SIGBUS) && info.si_code>0
            && md_svc_signal_window(pid,&w)) {
        uintptr_t prefix=w.edge.stub+w.edge.prefix_offset;
        if (r.pc>=prefix && r.pc<prefix+w.edge.prefix_count*4) {
            uintptr_t slot=w.edge.frames+(((r.sp^(r.sp>>16))>>8)&63)*MD_SVC_SLOT_SIZE;
            if (ptrace(PTRACE_POKEDATA,pid,(void *)slot,NULL)<0) return -errno;
            r.pc=w.edge.callee+(r.pc-prefix);
            if (ptrace(PTRACE_SETREGSET,pid,(void *)NT_PRSTATUS,&io)<0) return -errno;
            if (s) {
                int error=debug_set(pid,&s->debug);
                if (error) return error;
                if (ptrace(PTRACE_SETSIGMASK,pid,(void *)sizeof(s->mask),&s->mask)<0) return -errno;
                if (s->info.si_signo) {
                    error=md_signal_delivery_hold(queue,&s->info);
                    if (error) return error;
                    ++delivered;
                }
                md_svc_signal_forget(pid);
            }
            *deliver=info.si_signo; ++faults; return 1;
        }
    }
    if (s) {
        if (info.si_code<=0 && info.si_signo!=SIGSTOP) {
            int error=md_signal_delivery_hold(queue,&info);
            if (error) return error;
            *deliver=0; return 1;
        }
        if (info.si_signo!=SIGTRAP || info.si_code!=TRAP_HWBKPT) return 0;
        if (r.pc!=s->exits[0] && r.pc!=s->exits[1] && r.pc!=s->exits[2]) return 0;
        int error=debug_set(pid,&s->debug);
        if (error) return error;
        if (ptrace(PTRACE_SETSIGMASK,pid,(void *)sizeof(s->mask),&s->mask)<0
                || (s->info.si_signo && ptrace(PTRACE_SETSIGINFO,pid,NULL,&s->info)<0)) return -errno;
        *deliver=s->info.si_signo; if (*deliver) ++delivered;
        md_svc_signal_forget(pid); return 1;
    }
    if (!md_svc_signal_window(pid,&w)) return 0;
    /* Only asynchronous delivery can wait for the original architectural
     * context. Synchronous bootstrap copy faults keep their existing owner. */
    if (info.si_code>0 && info.si_code!=SI_KERNEL) return 0;
    if (info.si_signo==SIGSTOP || info.si_signo==SIGKILL) return 0;
    if (!(r.pc>=w.begin && r.pc<w.end)
            && !(r.sp>=w.edge.frames && r.sp<w.edge.frames+MD_SVC_POOL_SIZE)) return 0;
    int error=arm(pid,&w,&info);
    if (error<0) return error;
    ++deferred; *deliver=0;
    return 1;
}
void md_svc_signal_report(void) {
    if (deferred || delivered || faults || kernel_aliases || kernel_entries)
        fprintf(stderr,"SVC_SIGNALS {\"deferred\":%" PRIu64 ",\"delivered\":%" PRIu64 ",\"prefixFaults\":%" PRIu64
            ",\"kernelAliases\":%" PRIu64 ",\"kernelEntries\":%" PRIu64 "}\n",
            deferred,delivered,faults,kernel_aliases,kernel_entries);
}
