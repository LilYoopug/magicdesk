#define _GNU_SOURCE
#include "svc_patch.h"
#include "svc_edge.h"
#include "svc_payload.h"
#include "task_quiesce.h"
#include <assert.h>
#include <asm/hwcap.h>
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/ptrace.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/memfd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* Observe/forward/count never complete syscalls. Edge discovers one executed
 * call, publishes a cooperative payload, then detaches before the real work.
 * Neither census nor cold discovery is an entry-cost benchmark. */
enum { SITE_LIMIT=4096, POOL_SIZE=65536 };
struct site {
    uintptr_t pc,stub;
    uint32_t prefix;
    unsigned kind,patched,retired,witnessed,understood,number_distance;
    uint64_t calls,patched_calls,stub_visits,zero_tls,nonzero_tls;
    long number;
    struct md_svc_edge edge;
    uint32_t call_instruction,prefix_window[17];
    unsigned prefix_count,single;
};
struct space {
    struct space *next;
    uintptr_t pool;
    uintptr_t dispatch;
    unsigned used,count,id;
    struct site sites[SITE_LIMIT];
};
struct task {
    struct task *next;
    pid_t pid;
    int stopped,born,initial;
    uint64_t clone_flags;
    struct space *space;
    struct site *armed;
    unsigned arm_age;
    int detach_signal;
    struct user_hwdebug_state original_debug;
    int debug_owned;
};
struct pending { struct pending *next; pid_t pid; int status; };
static struct task *tasks;
static struct space *spaces;
static struct pending *first,*last;
static unsigned space_count,do_patch,count_visits;
static int edge_mode,edge_ready,edge_filtered,payload_fd=-1;
static long selected_number=SYS_newfstatat;
static struct md_svc_payload_state *payload;
static uint64_t total,overflow,unreadable,probe_failures;
static struct { uint64_t calls,visits; } numbers[512];

static long trace(int op,pid_t pid,void *address,void *data) {
    long result=ptrace(op,pid,address,data);
    if (result>=0 && (op==PTRACE_CONT || op==PTRACE_SYSCALL))
        for (struct task *t=tasks;t;t=t->next) if (t->pid==pid) t->stopped=0;
    return result;
}
static struct task *task(pid_t pid) {
    for (struct task *t=tasks;t;t=t->next) if (t->pid==pid) return t;
    struct task *t=calloc(1,sizeof(*t)); assert(t);
    *t=(struct task){.next=tasks,.pid=pid}; tasks=t; return t;
}
static struct space *space(struct space *copy) {
    struct space *s=calloc(1,sizeof(*s)); assert(s);
    if (copy) *s=*copy;
    if (copy) for (unsigned i=0;i<s->count;++i) {
        s->sites[i].calls=0; s->sites[i].patched_calls=0; s->sites[i].stub_visits=0;
        s->sites[i].zero_tls=0; s->sites[i].nonzero_tls=0;
    }
    s->next=spaces; s->id=++space_count; spaces=s; return s;
}
static pid_t wait_event(int *status) {
    if (first) {
        struct pending *p=first; first=p->next; if (!first) last=NULL;
        pid_t pid=p->pid; *status=p->status; free(p); return pid;
    }
    /* EVENT_WAIT: ptrace stop or terminal status; fixture alarm fails a hang. */
    pid_t pid; do { pid=waitpid(-1,status,__WALL); } while (pid<0 && errno==EINTR);
    assert(pid>0); return pid;
}
static void enqueue(pid_t pid,int status) {
    struct pending *p=calloc(1,sizeof(*p)); assert(p);
    p->pid=pid; p->status=status;
    if (last) last->next=p; else first=p;
    last=p;
}
static struct user_pt_regs registers(pid_t pid) {
    struct user_pt_regs r; struct iovec io={&r,sizeof(r)};
    assert(!trace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io)); return r;
}
static void set_registers(pid_t pid,struct user_pt_regs *r) {
    struct iovec io={r,sizeof(*r)}; assert(!trace(PTRACE_SETREGSET,pid,(void *)NT_PRSTATUS,&io));
}
static int read_word(pid_t pid,uintptr_t address,uint64_t *word) {
    errno=0; *word=(unsigned long)trace(PTRACE_PEEKTEXT,pid,(void *)address,NULL);
    return errno ? -errno : 0;
}
static int write_instruction(pid_t pid,uintptr_t address,uint32_t instruction) {
    uintptr_t aligned=address&~(uintptr_t)7; uint64_t word;
    int error=read_word(pid,aligned,&word); if (error) return error;
    unsigned shift=(unsigned)(address-aligned)*8;
    word=(word&~(UINT64_C(0xffffffff)<<shift))|((uint64_t)instruction<<shift);
    return trace(PTRACE_POKETEXT,pid,(void *)aligned,(void *)word)<0 ? -errno : 0;
}
static struct md_task_quiesce *quiesce(void) {
    struct md_task_quiesce *q=md_task_quiesce_new(trace); assert(q);
    for (struct task *t=tasks;t;t=t->next)
        assert(!md_task_quiesce_add(q,t->pid,t->stopped,PTRACE_SYSCALL));
    assert(!md_task_quiesce_stop(q));
    while (!md_task_quiesce_ready(q)) {
        int status; pid_t pid=wait_event(&status);
        task(pid)->stopped=1;
        assert(!md_task_quiesce_event(q,pid,status,NULL));
    }
    return q;
}
static void release(struct md_task_quiesce *q) {
    assert(!md_task_quiesce_release(q));
    int status; pid_t pid;
    while ((pid=md_task_quiesce_take(q,&status,NULL))) enqueue(pid,status);
    md_task_quiesce_destroy(q);
}
static int arm_prefix(struct task *t,struct site *p) {
    if (!p && !t->debug_owned) { t->armed=NULL; return 0; }
    struct user_hwdebug_state state=t->original_debug;
    if (p) {
        struct iovec observed={&state,sizeof(state)};
        if (trace(PTRACE_GETREGSET,t->pid,(void *)NT_ARM_HW_BREAK,&observed)<0) return -errno;
        unsigned count=state.dbg_info&255,slot=16,free=0;
        if (count>16) return -ENOTSUP;
        for (unsigned i=0;i<count;++i) if (!(state.dbg_regs[i].ctrl&1)) { if (slot==16) slot=i; ++free; }
        if (free<(edge_mode ? 3u : 1u)) { ++probe_failures; return -ENOSPC; }
        t->original_debug=state;
        state.dbg_regs[slot].addr=edge_mode ? p->edge.call : p->pc-4;
        /* Linux arm64 debug control: 4-byte execute, EL0, enabled. This
         * observes entry without corrupting a possible literal beforehand. */
        state.dbg_regs[slot].ctrl=(15u<<5)|(2u<<1)|1u;
    }
    struct iovec io={&state,offsetof(struct user_hwdebug_state,dbg_regs)+(state.dbg_info&255)*sizeof(state.dbg_regs[0])};
    if (trace(PTRACE_SETREGSET,t->pid,(void *)NT_ARM_HW_BREAK,&io)<0) {
        if (errno!=ESRCH) ++probe_failures;
        return -errno;
    }
    t->armed=p; t->arm_age=0; t->debug_owned=p!=NULL;
    return 0;
}
static int executable_private(pid_t pid,uintptr_t address,size_t size) {
    if (!size || size>UINTPTR_MAX-address) return 0;
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/maps",pid);
    FILE *file=fopen(path,"re"); if (!file) return 0;
    char *line=NULL; size_t capacity=0; uintptr_t cursor=address,end=address+size;
    while (cursor<end && getline(&line,&capacity,file)>0) {
        unsigned long begin,limit; char permission[5];
        if (sscanf(line,"%lx-%lx %4s",&begin,&limit,permission)!=3 || cursor<begin || cursor>=limit) continue;
        if (permission[1]=='w' || permission[2]!='x' || permission[3]!='p') break;
        cursor=limit<end ? limit : end;
    }
    free(line); fclose(file); return cursor==end;
}
static void publish(struct task *t,struct site *p) {
    struct space *s=t->space;
    if (edge_mode) {
        if (!p || !p->witnessed || !p->edge.call || p->patched || edge_filtered) return;
        size_t size=p->single ? md_svc_single_size() : md_svc_edge_size();
        assert(size<=2048 && s->used+size<=POOL_SIZE);
        unsigned char code[2048]; uint32_t replacement;
        struct md_svc_edge edge;
        int planned=p->single ? md_svc_single_plan(p->pc,p->prefix,s->pool+s->used,s->dispatch,MD_SVC_POOL_BASE,
            code,sizeof(code),&replacement,&edge)
            : md_svc_edge_plan(p->edge.call,p->call_instruction,p->edge.callee,
                p->prefix_window,p->prefix_count,s->pool+s->used,s->dispatch,MD_SVC_POOL_BASE,
                code,sizeof(code),&replacement,&edge);
        assert(!planned);
        struct md_task_quiesce *q=quiesce();
        uint64_t observed;
        int valid=executable_private(t->pid,p->edge.call,4)
            && executable_private(t->pid,p->edge.callee,p->pc+4-p->edge.callee)
            && !read_word(t->pid,p->edge.call,&observed) && (uint32_t)observed==p->call_instruction;
        if (p->single) valid=valid && (uint32_t)(observed>>32)==0xd4000001;
        for (unsigned i=0;valid && !p->single && i<p->prefix_count;++i)
            valid=!read_word(t->pid,p->edge.callee+i*4,&observed) && (uint32_t)observed==p->prefix_window[i];
        if (valid) {
            for (size_t i=0;i<size;i+=8) {
                uint64_t word=0; memcpy(&word,code+i,size-i<8 ? size-i : 8);
                assert(!trace(PTRACE_POKETEXT,t->pid,(void *)(edge.stub+i),(void *)word));
            }
            payload->window=(struct md_svc_signal_window){.begin=s->pool,.end=s->pool+POOL_SIZE,.edge=edge,
                .original=p->call_instruction,.replacement=replacement};
            __atomic_store_n(&payload->window.magic,MD_SVC_SIGNAL_MAGIC,__ATOMIC_RELEASE);
            assert(!write_instruction(t->pid,edge.call,replacement));
            p->edge=edge; p->patched=1; p->stub=edge.stub;
            s->used+=(unsigned)((size+15)&~(size_t)15); edge_ready=1;
        }
        release(q); return;
    }
    if (!p || p->retired || p->patched || !p->witnessed || s->used+16>POOL_SIZE) return;
    uint32_t original[2]={p->prefix,0xd4000001},replacement,code[2];
    uintptr_t destination=s->pool+s->used;
    if (md_svc_forward(p->pc,destination,original,&replacement,code)) return;
    uint32_t back=code[1];
    if (count_visits) {
        assert(!md_svc_branch(destination+8,p->pc,&back));
        code[1]=0xd42b6b00; /* BRK #0x5b58, owned by its exact trampoline PC. */
    }
    struct md_task_quiesce *q=quiesce();
    uint64_t observed;
    /* Revalidate after stopping writers. The witness applies to these exact
     * bytes only. Publish an immutable stub before the replacing branch. */
    if (!read_word(t->pid,p->pc-4,&observed) && observed==((uint64_t)original[1]<<32|original[0])) {
        assert(!trace(PTRACE_POKETEXT,t->pid,(void *)destination,
            (void *)((uint64_t)code[1]<<32|code[0])));
        if (count_visits) assert(!trace(PTRACE_POKETEXT,t->pid,(void *)(destination+8),(void *)(uintptr_t)back));
        assert(!write_instruction(t->pid,p->pc-4,replacement));
        p->patched=1; p->stub=destination; s->used+=16;
    }
    release(q);
}
static long inject(struct task *t,long number,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f) {
    struct user_pt_regs saved=registers(t->pid),r=saved;
    uintptr_t gate=saved.pc; uint64_t original;
    assert(!read_word(t->pid,gate,&original));
    assert(!trace(PTRACE_POKETEXT,t->pid,(void *)gate,(void *)UINT64_C(0xd4200000d4000001)));
    r.regs[8]=number;
    r.regs[0]=a; r.regs[1]=b; r.regs[2]=c; r.regs[3]=d; r.regs[4]=e; r.regs[5]=f;
    set_registers(t->pid,&r); assert(!trace(PTRACE_CONT,t->pid,NULL,NULL));
    int status; pid_t pid=wait_event(&status);
    assert(pid==t->pid && WIFSTOPPED(status) && WSTOPSIG(status)==SIGTRAP && !((unsigned)status>>16));
    t->stopped=1; r=registers(t->pid); assert(r.pc==gate+4);
    assert(!trace(PTRACE_POKETEXT,t->pid,(void *)gate,(void *)original));
    set_registers(t->pid,&saved);
    return (long)r.regs[0];
}
static uintptr_t read_auxv(struct task *t,unsigned long key) {
    uintptr_t at=registers(t->pid).sp; uint64_t count,value;
    assert(!read_word(t->pid,at,&count) && count<65536);
    at+=(count+2)*8;
    do { assert(!read_word(t->pid,at,&value)); at+=8; } while (value);
    for (unsigned i=0;i<128;++i) {
        assert(!read_word(t->pid,at,&count) && !read_word(t->pid,at+8,&value)); at+=16;
        if (count==key) return value;
        if (!count) return 0;
    }
    assert(0 && "invalid auxv"); return 0;
}
static void prepare_pool(struct task *t) {
    if (!do_patch) return;
    /* Exec's final x0 write must precede any injected operation. */
    assert(!trace(PTRACE_SYSCALL,t->pid,NULL,NULL));
    int status; pid_t pid=wait_event(&status);
    assert(pid==t->pid && WIFSTOPPED(status) && WSTOPSIG(status)==(SIGTRAP|0x80));
    t->stopped=1;
    uintptr_t gate=registers(t->pid).pc;
    long address=inject(t,SYS_mmap,(gate+0x4000000)&~(uintptr_t)0xffff,POOL_SIZE,
        PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(address>0); t->space->pool=(uintptr_t)address;
    if (edge_mode) {
        assert(read_auxv(t,AT_HWCAP)&HWCAP_ATOMICS);
        payload->api=(void *)read_auxv(t,MD_AT_COOPERATIVE);
        payload->admitted=1;
        assert(inject(t,SYS_mmap,MD_SVC_POOL_BASE,MD_SVC_SLOT_COUNT*MD_SVC_SLOT_SIZE,
            PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==MD_SVC_POOL_BASE);
        for (unsigned i=0;i<MD_SVC_SLOT_COUNT;++i)
            assert(!inject(t,SYS_mprotect,MD_SVC_POOL_BASE+i*MD_SVC_SLOT_SIZE+16384,16384,PROT_NONE,0,0,0));
        assert(inject(t,SYS_mmap,MD_SVC_PAYLOAD_STATE,MD_SVC_PAYLOAD_SIZE,PROT_READ|PROT_WRITE,
            MAP_SHARED|MAP_FIXED_NOREPLACE,payload_fd,0)==MD_SVC_PAYLOAD_STATE);
        assert(!inject(t,SYS_close,payload_fd,0,0,0,0,0));
        size_t length=(size_t)(__stop_md_svc_payload-__start_md_svc_payload);
        assert(length && length<16384);
        for (size_t i=0;i<length;i+=8) {
            uint64_t word=0; memcpy(&word,__start_md_svc_payload+i,length-i<8 ? length-i : 8);
            assert(!trace(PTRACE_POKETEXT,t->pid,(void *)(t->space->pool+i),(void *)word));
        }
        t->space->used=(unsigned)((length+15)&~(size_t)15);
        t->space->dispatch=t->space->pool+(uintptr_t)md_svc_payload_dispatch-(uintptr_t)__start_md_svc_payload;
    }
    fprintf(stderr,"SVC_POOL space=%u entry=%#" PRIxPTR " address=%#" PRIxPTR "\n",
        t->space->id,gate,t->space->pool);
}
static void discover_entry(struct task *t,struct site *p) {
    struct space *s=t->space;
    struct user_pt_regs r=registers(t->pid);
    unsigned char scratch[2048]; uint32_t replacement;
    uint64_t word;
    if (r.regs[30]>=4 && !read_word(t->pid,r.regs[30]-4,&word) && ((uint32_t)word&0xfc000000)==0x94000000) {
        uint32_t call=(uint32_t)word;
        uintptr_t call_pc=r.regs[30]-4;
        int64_t relative=(int64_t)((uint64_t)(call&0x03ffffff)<<38)>>36;
        uintptr_t callee=call_pc+relative;
        if (callee<=p->pc && p->pc-callee<=64 && !((p->pc-callee)&3)) {
            unsigned count=(unsigned)((p->pc-callee)/4)+1,i=0;
            for (;i<count;++i) {
                if (read_word(t->pid,callee+i*4,&word)) break;
                p->prefix_window[i]=(uint32_t)word;
            }
            if (i==count && !md_svc_edge_plan(call_pc,call,callee,p->prefix_window,count,s->pool+s->used,
                    s->dispatch,MD_SVC_POOL_BASE,scratch,sizeof(scratch),&replacement,&p->edge)) {
                p->call_instruction=call; p->prefix_count=count;
                arm_prefix(t,p); return;
            }
        }
    }
    if (!md_svc_single_plan(p->pc,p->prefix,s->pool+s->used,s->dispatch,MD_SVC_POOL_BASE,scratch,sizeof(scratch),&replacement,&p->edge)) {
        p->call_instruction=p->prefix; p->single=1;
        arm_prefix(t,p);
    }
}
static void observe(struct task *t,const struct ptrace_syscall_info *info) {
    ++total;
    if (info->entry.nr<512) ++numbers[info->entry.nr].calls;
    if (edge_mode && (info->entry.nr==SYS_seccomp || (info->entry.nr==SYS_prctl && info->entry.args[0]==PR_SET_SECCOMP)))
        edge_filtered=1;
    if (info->entry.nr==SYS_clone) t->clone_flags=info->entry.args[0];
    if (info->entry.nr==SYS_clone3) {
        t->clone_flags=0;
        if (read_word(t->pid,info->entry.args[0],&t->clone_flags)) t->clone_flags=0;
    }
    if (!t->space || info->instruction_pointer<8) return;
    struct space *s=t->space; uintptr_t pc=info->instruction_pointer-4;
    uint64_t word;
    if (read_word(t->pid,pc-4,&word) || (uint32_t)(word>>32)!=0xd4000001) { ++unreadable; return; }
    struct site *p=NULL;
    for (unsigned i=0;i<s->count;++i) {
        struct site *candidate=&s->sites[i];
        if (candidate->pc!=pc || candidate->retired) continue;
        uint32_t expected=candidate->prefix;
        if (candidate->patched) assert(!md_svc_branch(pc-4,candidate->stub,&expected));
        if ((uint32_t)word==expected) p=candidate;
        else candidate->retired=1;
        break;
    }
    if (!p) {
        if (s->count==SITE_LIMIT) { ++overflow; return; }
        p=&s->sites[s->count++];
        *p=(struct site){.pc=pc,.prefix=(uint32_t)word,.kind=md_svc_prefix((uint32_t)word),
            .number=(long)info->entry.nr};
        uint32_t window[10]; unsigned available=0;
        for (unsigned back=0;back<10 && pc>=back*4;++back) {
            uint64_t instruction;
            if (read_word(t->pid,pc-back*4,&instruction)) break;
            window[9-back]=(uint32_t)instruction; ++available;
        }
        struct md_svc_window context=md_svc_window(window+10-available,available);
        p->understood=context.understood; p->number_distance=context.number_distance;
    }
    ++p->calls; p->patched_calls+=p->patched;
    uintptr_t tls=0; struct iovec io={&tls,sizeof(tls)};
    if (trace(PTRACE_GETREGSET,t->pid,(void *)NT_ARM_TLS,&io)<0) { assert(errno==ESRCH); return; }
    if (tls) ++p->nonzero_tls; else ++p->zero_tls;
    if (edge_mode) {
        /* One selected hot syscall is a bounded discovery trigger, not an ABI
         * assumption. Publication still requires an executed entry witness. */
        if (edge_filtered || info->entry.nr!=(uint64_t)selected_number || p->calls<8 || t->armed || p->patched) return;
        discover_entry(t,p); return;
    }
    if (t->armed && ++t->arm_age>=64) arm_prefix(t,NULL);
    if (!do_patch || !p->kind || p->patched || t->armed || s->used+16>POOL_SIZE) return;
    uint32_t original[2]={p->prefix,0xd4000001},replacement,code[2];
    uintptr_t destination=s->pool+s->used;
    if (md_svc_forward(pc,destination,original,&replacement,code)) return;
    arm_prefix(t,p);
}
static const char *admission(struct space *s,struct site *p) {
    if (p->retired) return "code-replaced";
    if (p->patched) return edge_mode ? (p->single ? "witnessed-register-overwrite" : "witnessed-call-edge") : "witnessed-forwarding";
    if (!do_patch) return "observe-only";
    if (!p->kind) return "unsupported-prefix";
    if (s->used+16>POOL_SIZE) return "pool-limit";
    uint32_t original[2]={p->prefix,0xd4000001},replacement,code[2];
    if (md_svc_forward(p->pc,s->pool+s->used,original,&replacement,code)) return "branch-range";
    return p->witnessed ? "publication-revalidation" : "no-prefix-witness";
}
static void detach_pending(pid_t pid,int status) {
    if (!WIFSTOPPED(status) || (unsigned)status>>16 || WSTOPSIG(status)==(SIGTRAP|0x80)) return;
    struct task *t=task(pid);
    if (WSTOPSIG(status)==SIGTRAP && t->armed) {
        siginfo_t info;
        if (!trace(PTRACE_GETSIGINFO,pid,NULL,&info) && info.si_code==TRAP_HWBKPT
                && registers(pid).pc==t->armed->edge.call) return;
    }
    t->detach_signal=WSTOPSIG(status);
}
static int detach_tree(pid_t root) {
    struct md_task_quiesce *q=quiesce();
    int status,root_terminal=0; pid_t pid;
    while ((pid=md_task_quiesce_take(q,&status,NULL))) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid==root) root_terminal=1+(WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status));
            continue;
        }
        detach_pending(pid,status);
    }
    while (first) {
        struct pending *p=first; first=p->next;
        detach_pending(p->pid,p->status);
        free(p);
    }
    last=NULL;
    for (struct task *t=tasks;t;t=t->next) {
        arm_prefix(t,NULL);
        assert(!trace(PTRACE_DETACH,t->pid,NULL,(void *)(uintptr_t)t->detach_signal) || errno==ESRCH);
    }
    /* Detach transferred execution and pending signal ownership to the kernel;
     * do not resume synthetic stops again through the barrier. */
    md_task_quiesce_destroy(q);
    while (tasks) { struct task *t=tasks; tasks=t->next; free(t); }
    if (root_terminal) return root_terminal-1;
    do { pid=waitpid(root,&status,0); } while (pid<0 && errno==EINTR);
    assert(pid==root && (WIFEXITED(status) || WIFSIGNALED(status)));
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
}
int main(int argc,char **argv) {
    assert(argc>=3 && (!strcmp(argv[1],"observe") || !strcmp(argv[1],"forward") || !strcmp(argv[1],"count") || !strcmp(argv[1],"edge")));
    edge_mode=!strcmp(argv[1],"edge");
    const char *selected=getenv("MD_SVC_NUMBER");
    if (selected) { char *end; selected_number=strtol(selected,&end,10); assert(!*end && selected_number>=0 && selected_number<512); }
    do_patch=strcmp(argv[1],"observe")!=0; count_visits=!strcmp(argv[1],"count"); alarm(180);
    if (edge_mode) {
        assert(sizeof(*payload)<=MD_SVC_PAYLOAD_SIZE);
        payload_fd=(int)syscall(SYS_memfd_create,"svc-edge-proof",0);
        assert(payload_fd>=0 && !ftruncate(payload_fd,MD_SVC_PAYLOAD_SIZE));
        payload=mmap(NULL,MD_SVC_PAYLOAD_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,payload_fd,0);
        assert(payload!=MAP_FAILED);
        payload->selected_number=(uint64_t)selected_number;
    }
    int start[2]; assert(!pipe(start));
    pid_t root=fork(); assert(root>=0);
    if (!root) {
        close(start[1]); char byte; assert(read(start[0],&byte,1)==1); close(start[0]);
        execv(argv[2],argv+2); perror("execv"); _exit(127);
    }
    close(start[0]); task(root)->born=1;
    unsigned options=PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC|PTRACE_O_TRACECLONE
        |PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACEVFORKDONE|PTRACE_O_EXITKILL;
    assert(!trace(PTRACE_SEIZE,root,NULL,(void *)(uintptr_t)options));
    assert(!trace(PTRACE_INTERRUPT,root,NULL,NULL));
    int status; assert(wait_event(&status)==root && WIFSTOPPED(status));
    task(root)->stopped=1;
    assert(write(start[1],"s",1)==1); close(start[1]);
    assert(!trace(PTRACE_SYSCALL,root,NULL,NULL));
    int result=0;
    while (tasks) {
        pid_t pid=wait_event(&status); struct task *t=task(pid); t->stopped=1;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid==root || WIFSIGNALED(status)) result=WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
            struct task **at=&tasks; while (*at!=t) at=&(*at)->next; *at=t->next; free(t); continue;
        }
        assert(WIFSTOPPED(status));
        unsigned event=(unsigned)status>>16; int signal=WSTOPSIG(status);
        if (event==PTRACE_EVENT_EXEC) {
            t->space=space(NULL); t->armed=NULL; t->debug_owned=0;
            if (do_patch) arm_prefix(t,NULL);
            prepare_pool(t);
        }
        else if (event==PTRACE_EVENT_CLONE || event==PTRACE_EVENT_FORK || event==PTRACE_EVENT_VFORK) {
            unsigned long child; assert(!trace(PTRACE_GETEVENTMSG,pid,NULL,&child));
            struct task *newborn=task((pid_t)child);
            newborn->space=(event==PTRACE_EVENT_VFORK || (t->clone_flags&CLONE_VM))
                ? t->space : space(t->space);
            newborn->born=1;
            newborn->original_debug=t->original_debug; newborn->debug_owned=t->debug_owned;
            if (newborn->initial) {
                if (do_patch) arm_prefix(newborn,NULL);
                assert(!trace(PTRACE_SYSCALL,newborn->pid,NULL,NULL) || errno==ESRCH);
            }
        } else if (event==PTRACE_EVENT_STOP && !t->born) {
            /* Newborn stop may precede the parent's birth event. Do not run
             * patched code until its address-space owner has been attached. */
            t->initial=1; continue;
        } else if (event==PTRACE_EVENT_STOP && t->born && do_patch) {
            arm_prefix(t,NULL);
        } else if (!event && signal==SIGTRAP && t->space) {
            struct user_pt_regs r=registers(pid);
            siginfo_t information;
            assert(!trace(PTRACE_GETSIGINFO,pid,NULL,&information));
            if (t->armed && information.si_code==TRAP_HWBKPT
                    && r.pc==(edge_mode ? t->armed->edge.call : t->armed->pc-4)) {
                struct site *p=t->armed;
                assert(!arm_prefix(t,NULL));
                p->witnessed=1; publish(t,p); signal=0;
            }
            for (unsigned i=0;signal && count_visits && i<t->space->count;++i) {
                struct site *p=&t->space->sites[i];
                if (p->patched && r.pc==p->stub+4) {
                    ++p->stub_visits;
                    if (r.regs[8]<512) ++numbers[r.regs[8]].visits;
                    r.pc+=4; set_registers(pid,&r); signal=0; break;
                }
            }
        } else if (!event && signal==(SIGTRAP|0x80)) {
            struct ptrace_syscall_info info={0};
            long observed=trace(PTRACE_GET_SYSCALL_INFO,pid,(void *)sizeof(info),&info);
            if (observed<0 && errno==ESRCH) continue;
            assert(observed>0);
            if (info.op==PTRACE_SYSCALL_INFO_ENTRY) observe(t,&info);
        }
        int deliver=event || signal==(SIGTRAP|0x80) ? 0 : signal;
        if (edge_ready) {
            fprintf(stderr,"SVC_EDGE detached after witnessed call publication\n");
            result=detach_tree(root); break;
        }
        if (deliver && t->space) {
            struct user_pt_regs r=registers(pid);
            for (unsigned i=0;i<t->space->count;++i) {
                struct site *p=&t->space->sites[i];
                if (!p->patched) continue;
                uintptr_t original=md_svc_original_pc(p->pc,p->stub,r.pc,count_visits);
                if (original!=r.pc) { r.pc=original; set_registers(pid,&r); break; }
            }
        }
        assert(!trace(PTRACE_SYSCALL,pid,NULL,(void *)(uintptr_t)deliver) || errno==ESRCH);
    }
    for (struct space *s=spaces;s;s=s->next) for (unsigned i=0;i<s->count;++i) {
        struct site *p=&s->sites[i];
        printf("SVC_SITE {\"space\":%u,\"pc\":\"%#" PRIxPTR "\",\"prefix\":\"%08x\",\"kind\":%u,"
            "\"number\":%ld,\"calls\":%" PRIu64 ",\"patched\":%u,\"retired\":%u,\"witnessed\":%u,\"patchedSiteCalls\":%" PRIu64 ",\"stubVisits\":%" PRIu64 ","
            "\"zeroTls\":%" PRIu64 ",\"nonzeroTls\":%" PRIu64 ",\"understood\":%u,\"numberDistance\":%u,\"admission\":\"%s\"}\n",s->id,p->pc,p->prefix,p->kind,
            p->number,p->calls,p->patched,p->retired,p->witnessed,p->patched_calls,p->stub_visits,p->zero_tls,p->nonzero_tls,p->understood,p->number_distance,admission(s,p));
    }
    printf("SVC_TOTAL {\"calls\":%" PRIu64 ",\"overflow\":%" PRIu64 ",\"unreadable\":%" PRIu64 ",\"probeFailures\":%" PRIu64 ",\"exit\":%d}\n",total,overflow,unreadable,probe_failures,result);
    if (edge_mode) {
        printf("SVC_EDGE_STATS {\"detached\":%s,\"provider\":%s,\"completed\":%" PRIu64
            ",\"declined\":%" PRIu64 ",\"unknown\":%" PRIu64 ",\"revoked\":%" PRIu64
            ",\"selectedNumber\":%" PRIu64 ",\"selectedCompleted\":%" PRIu64 ",\"retiredClients\":%" PRIu64 "}\n",edge_ready ? "true" : "false",
            payload->api ? "true" : "false",payload->completed,payload->declined,payload->unknown,payload->revoked,
            payload->selected_number,payload->selected_completed,payload->retired_clients);
        assert(!munmap(payload,MD_SVC_PAYLOAD_SIZE) && !close(payload_fd));
    }
    for (unsigned i=0;i<512;++i) if (numbers[i].calls || numbers[i].visits)
        printf("SVC_NR {\"number\":%u,\"calls\":%" PRIu64 ",\"stubVisits\":%" PRIu64 "}\n",i,numbers[i].calls,numbers[i].visits);
    while (spaces) { struct space *s=spaces; spaces=s->next; free(s); }
    return result;
}
