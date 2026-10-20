#define _GNU_SOURCE
#include "svc_machine.h"
#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

struct md_svc_held_signal {
    struct md_svc_held_signal *next;
    siginfo_t info;
};
static int regs(pid_t pid,int operation,struct user_pt_regs *r) {
    struct iovec io={r,sizeof(*r)};
    return ptrace(operation,pid,(void *)NT_PRSTATUS,&io)<0 ? -errno : 0;
}
static int memory(void *opaque,uintptr_t at,void *data,size_t size,int write) {
    pid_t pid=(pid_t)(intptr_t)opaque;
    return write ? md_svc_registry_write(pid,at,data,size) : md_svc_registry_read(pid,at,data,size);
}
struct md_svc_registry *md_svc_machine_admit(pid_t pid,uintptr_t descriptor) {
    struct md_svc_runtime runtime;
    if (!descriptor || md_svc_registry_read(pid,descriptor,&runtime,sizeof(runtime))
            || !runtime.count || runtime.count>MD_SVC_CODE_POOLS || runtime.reserved) return NULL;
    struct md_svc_registry *r=md_svc_registry_new(runtime.frames,runtime.dispatch);
    if (!r) return NULL;
    for (unsigned i=0;i<runtime.count;++i)
        if (!md_svc_registry_executable(pid,runtime.pools[i],MD_SVC_CODE_BYTES)
                || md_svc_registry_pool(r,runtime.pools[i])) { free(r); return NULL; }
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/maps",pid);
    FILE *maps=fopen(path,"re");
    if (!maps) { free(r); return NULL; }
    char *line=NULL; size_t size=0;
    while (getline(&line,&size,maps)>0) {
        unsigned long start,end;
        if (sscanf(line,"%lx-%lx",&start,&end)==2 && start<=runtime.dispatch && runtime.dispatch<end) {
            r->native_begin=start; r->native_end=end; break;
        }
    }
    free(line); fclose(maps);
    if (!r->native_end) { free(r); return NULL; }
    return r;
}
void md_svc_machine_forget(struct md_svc_machine_thread *s) {
    while (s->signals) {
        struct md_svc_held_signal *next=s->signals->next;
        free(s->signals); s->signals=next;
    }
    *s=(struct md_svc_machine_thread){0};
}
static struct md_svc_held_signal **first(struct md_svc_machine_thread *s,int signal) {
    struct md_svc_held_signal **at=&s->signals;
    while (*at && (*at)->info.si_signo!=signal) at=&(*at)->next;
    return at;
}
static int hold(struct md_svc_machine_thread *s,const siginfo_t *info,int front) {
    struct md_svc_held_signal **at=first(s,info->si_signo);
    if (info->si_signo<SIGRTMIN && *at) return 0;
    struct md_svc_held_signal *node=malloc(sizeof(*node));
    if (!node) return -ENOMEM;
    if (!front) while (*at) at=&(*at)->next;
    *node=(struct md_svc_held_signal){.next=*at,.info=*info}; *at=node;
    return 0;
}
static int publish(struct md_svc_machine_thread *s,pid_t pid,pid_t group) {
    unsigned counts[NSIG]={0};
    for (struct md_svc_held_signal *node=s->signals;node;node=node->next) ++counts[node->info.si_signo];
    for (int n=1;n<NSIG;++n) while (s->carriers[n]<counts[n]) {
        siginfo_t info={.si_signo=n,.si_code=SI_QUEUE};
        info.si_pid=getpid(); info.si_uid=getuid(); info.si_value.sival_ptr=s;
        if (syscall(SYS_rt_tgsigqueueinfo,group,pid,n,&info)<0) return -errno;
        ++s->carriers[n];
    }
    return 0;
}
static int recover(struct md_svc_registry *r,struct md_svc_machine_thread *s,pid_t pid,
        struct user_pt_regs *registers) {
    struct md_svc_site *site=md_svc_registry_direct_at(r,pid,registers->pc,registers->sp);
    if (!site) return 0;
    if (registers->pc==site->window.kernel_alias) {
        registers->pc+=4;
        return md_svc_machine_return(r,s,pid,registers);
    } else if (registers->pc==site->window.kernel_alias+4) {
        registers->pc=site->direct.svc+4;
        s->draining=0;
        return 1;
    }
    int result=md_svc_direct_recover(&site->direct,registers,memory,(void *)(intptr_t)pid);
    if (result==1) s->draining=0;
    return result;
}
int md_svc_machine_drain(struct md_svc_registry *r,struct md_svc_machine_thread *s,pid_t pid,
        const struct user_pt_regs *adapter,int syscall_stop) {
    /* This stop already owns a reconstructed guest continuation. The exit
     * handler installs it before the filter fence permits publication. */
    if (s->syscall_exit) return 0;
    struct user_pt_regs registers;
    if (adapter) registers=*adapter;
    else {
        int error=regs(pid,PTRACE_GETREGSET,&registers);
        if (error) return error;
    }
    struct md_svc_site *site=md_svc_registry_direct_at(r,pid,registers.pc,registers.sp);
    if (!site) return 0;
    if (adapter || syscall_stop) {
        if (registers.sp>r->frames && registers.sp<=r->frames+MD_SVC_POOL_SIZE) {
            uintptr_t frame=(registers.sp-1)&~(uintptr_t)(MD_SVC_SLOT_SIZE-1);
            uint64_t one=1;
            int error=md_svc_registry_write(pid,frame+MD_SVC_DIRECT_PENDING,&one,8);
            if (error) return error;
            s->draining=1;
        } else if (!adapter) s->draining=1;
        return 0;
    }
    int result=recover(r,s,pid,&registers);
    if (result==2) s->draining=1;
    if (result==1) return regs(pid,PTRACE_SETREGSET,&registers);
    return result<0 ? result : 0;
}
int md_svc_machine_flush(struct md_svc_registry *r,struct md_svc_machine_thread *s,pid_t pid,pid_t group,
        struct md_signal_delivery *queue) {
    if (!r || queue->active || !queue->first) return 0;
    struct user_pt_regs registers;
    int error=regs(pid,PTRACE_GETREGSET,&registers);
    if (error) return error;
    int recovery=recover(r,s,pid,&registers);
    if (recovery<0) return recovery;
    if (recovery==1 && (error=regs(pid,PTRACE_SETREGSET,&registers))) return error;
    siginfo_t info;
    while (md_signal_delivery_take(queue,&info)) if ((error=hold(s,&info,0))) return error;
    if (recovery!=2) error=publish(s,pid,group);
    return error ? error : 1;
}
int md_svc_machine_signal(struct md_svc_registry *r,struct md_svc_machine_thread *s,pid_t pid,int *deliver) {
    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO,pid,NULL,&info)<0) return errno==EINVAL ? 0 : -errno;
    int signal=info.si_signo,queued=0;
    if (signal<=0 || signal>=NSIG) return 0;
    int carrier=info.si_code==SI_QUEUE && info.si_pid==getpid()
        && info.si_value.sival_ptr==s && s->carriers[signal];
    struct md_svc_held_signal **at=first(s,signal);
    if (carrier) --s->carriers[signal];
    if (*at) {
        /* A newer real arrival can precede replay notifications in the kernel
         * queue. Preserve the saved FIFO rather than appending it behind that
         * arrival. Standard signals retain their coalescing behavior. */
        if (!carrier) { int error=hold(s,&info,0); if (error) return error; }
        struct md_svc_held_signal *node=*at;
        info=node->info; *at=node->next; free(node); queued=1;
    } else if (carrier) { *deliver=0; return 1; }
    if (signal==SIGSTOP || signal==SIGKILL || (info.si_code>0 && info.si_code!=SI_KERNEL))
        return 0;
    struct user_pt_regs registers;
    int error=regs(pid,PTRACE_GETREGSET,&registers);
    if (error) return error;
    int recovery=recover(r,s,pid,&registers);
    if (recovery<0) return recovery;
    if (recovery==2) {
        error=hold(s,&info,1);
        if (!error) *deliver=0;
        return error ? error : 1;
    }
    if (recovery==1 && (error=regs(pid,PTRACE_SETREGSET,&registers))) return error;
    if (queued && ptrace(PTRACE_SETSIGINFO,pid,NULL,&info)<0) return -errno;
    if (recovery || queued) { *deliver=signal; return 1; }
    return 0;
}
int md_svc_machine_return(struct md_svc_registry *r,struct md_svc_machine_thread *s,
        pid_t pid,struct user_pt_regs *registers) {
    if (!r) return 0;
    int error=0;
    struct md_svc_site *site=md_svc_registry_direct_at(r,pid,registers->pc,registers->sp);
    if (!site) return 0;
    if (registers->pc==site->window.kernel_alias+4) {
        /* Intercepted cold misses retry at the original SVC. The ordinary
         * syscall owner, not the gate's synthetic PC, then owns execution. */
        error=md_svc_registry_suspend(r,pid,site->direct.svc);
        s->retry_svc=site->direct.svc;
        s->retry_number=registers->regs[8];
        registers->pc=site->direct.svc;
    } else if (registers->pc==md_svc_direct_checkpoint(&site->direct)+4) {
        int recovered=md_svc_direct_recover(&site->direct,registers,memory,(void *)(intptr_t)pid);
        if (recovered!=1) return recovered<0 ? recovered : -EPROTO;
    } else return 0;
    if (!error) s->draining=0;
    return error ? error : 1;
}
int md_svc_machine_syscall(struct md_svc_registry *r,struct md_svc_machine_thread *s,pid_t pid) {
    if (!r) return 0;
    struct user_pt_regs registers;
    int error=regs(pid,PTRACE_GETREGSET,&registers);
    if (error) return error;
    int owned=md_svc_machine_return(r,s,pid,&registers);
    if (owned<=0) return owned;
    int number=-1;
    struct iovec io={&number,sizeof(number)};
    if (ptrace(PTRACE_SETREGSET,pid,(void *)NT_ARM_SYSTEM_CALL,&io)<0) return -errno;
    s->restored=registers; s->syscall_exit=1;
    return 1;
}
int md_svc_machine_exit(struct md_svc_machine_thread *s,pid_t pid,pid_t group) {
    if (!s->syscall_exit) return 0;
    int error=regs(pid,PTRACE_SETREGSET,&s->restored);
    if (!error) error=publish(s,pid,group);
    if (error) return error;
    s->syscall_exit=0; s->draining=0; return 1;
}
int md_svc_machine_retry(struct md_svc_registry *r,struct md_svc_machine_thread *s,pid_t pid) {
    /* The original instruction has entered the kernel (or a signal handler
     * entered instead). Republish for future calls; only this caller needed
     * a syscall-entry stop, never its peers. */
    int error=md_svc_registry_resume(r,pid,s->retry_svc,s->retry_number);
    if (!error) s->retry_svc=0;
    return error;
}
