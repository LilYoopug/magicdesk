#define _GNU_SOURCE
#include "task_helper.h"
#include "mapping_observation.h"
#include "fd_channel.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

enum operation { ALLOCATE, CLONE, CLEAR, CHANNEL, OPEN, EXPORT, BACKING, MAP, EXIT };
struct parcel {
    uint64_t token;
    struct iovec vector;
    struct msghdr message;
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    char path[PATH_MAX];
};
struct helper {
    struct helper *next;
    struct md_task_helpers *manager;
    pid_t owner, group, child;
    int parent_ready, reaped, started, cancelled, before, observed;
    enum operation parent_operation, operation;
    long result;
    struct md_interception_abi abi;
    struct md_interception_memory *memory;
    struct md_interception_buffer buffer;
    uintptr_t stack, parcel;
    struct md_task_mapping_request request;
    enum md_task_helper_kind kind;
    int flags;
    md_task_helper_complete complete;
    struct md_mapping_source source;
    struct md_fd_channel *channel;
    struct md_fd_channel_capture capture;
    int backing, maps;
    void *completion;
};
struct md_task_helpers {
    struct helper *first;
    struct md_task_helper_callbacks callbacks;
    unsigned count;
};
static long trace(struct helper *m, int request, pid_t pid, void *address, void *data) {
    long r=m->manager->callbacks.trace(request,pid,address,data);
    return r<0 ? -errno : r;
}
static int resume(struct helper *m, pid_t pid) {
    long r=trace(m,PTRACE_CONT,pid,NULL,NULL);
    /* EVENT_WAIT: ESRCH can precede an already queued exec/exit. Retain every
     * resource until that exact event; the launch deadline bounds lost events. */
    return r==-ESRCH ? 0 : (int)r;
}
static int registers(struct helper *m, pid_t pid, struct user_pt_regs *r, int write) {
    struct iovec io={r,sizeof(*r)};
    return (int)trace(m,write ? PTRACE_SETREGSET : PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io);
}
static int call(struct helper *m, pid_t pid, long nr, const unsigned long args[6]) {
    struct user_pt_regs r={.pc=m->abi.task_call,.sp=m->stack};
    memcpy(r.regs,args,6*sizeof(*args)); r.regs[8]=nr;
    int error=registers(m,pid,&r,1);
    return error==-ESRCH ? 0 : error ? error : resume(m,pid);
}
static void dispose(struct helper *m) {
    struct md_task_helpers *manager=m->manager;
    struct helper **p=&manager->first;
    while (*p && *p!=m) p=&(*p)->next;
    if (*p) { *p=m->next; --manager->count; }
    md_fd_channel_capture_cancel(&m->capture);
    md_fd_channel_release(m->channel);
    if (m->maps>=0) close(m->maps);
    if (m->backing>=0) close(m->backing);
    md_buffer_release(&m->buffer);
    if (m->memory) md_memory_stack_return(m->memory,m->stack);
    md_memory_release(m->memory);
    free(m);
}
static void complete(struct helper *m) {
    void *context=m->completion;
    struct md_task_helper_result result={.value=m->result,.descriptor=-1};
    if (m->kind==MD_TASK_HELPER_CAPTURE && !m->result && !m->cancelled) {
        result.descriptor=m->maps; m->maps=-1;
    } else if (m->kind==MD_TASK_HELPER_CAPTURE && m->cancelled) result.value=-ECANCELED;
    md_task_helper_complete callback=m->complete;
    dispose(m);
    callback(context,result);
}
static int abort_child(struct helper *m) {
    m->operation=EXIT;
    struct user_pt_regs r={.pc=m->abi.task_abort,.sp=m->stack};
    int error=registers(m,m->child,&r,1);
    return error==-ESRCH ? 0 : error ? error : resume(m,m->child);
}
static int clone_begin(struct helper *m) {
    m->parent_operation=CLONE;
    unsigned long args[6]={CLONE_VM|CLONE_THREAD|CLONE_SIGHAND,m->stack};
    return call(m,m->owner,SYS_clone,args);
}
static int child_begin(struct helper *m) {
    unsigned long options=PTRACE_O_TRACESECCOMP|PTRACE_O_TRACEEXIT|PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD;
    int error=(int)trace(m,PTRACE_SETOPTIONS,m->child,NULL,(void *)options);
    uint64_t mask=UINT64_MAX;
    if (!error) error=(int)trace(m,PTRACE_SETSIGMASK,m->child,(void *)sizeof(mask),&mask);
    if (error) return error==-ESRCH ? 0 : error;
    if (m->cancelled) return abort_child(m);
    m->operation=CLEAR;
    unsigned long args[6]={0,~0U,0};
    return call(m,m->child,SYS_close_range,args);
}
static int observe(struct helper *m, const struct user_pt_regs *r) {
    if (m->observed || !m->started) return 0;
    long address=(long)r->regs[0];
    if (r->pc!=m->abi.task_return || r->regs[8]!=SYS_mmap) return -EPROTO;
    if (address<=0) {
        m->result=address<0 && address>=-4095 ? address : -ECANCELED;
        m->observed=1; return 0;
    }
    int found=md_mapping_observe(m->maps,&m->source,(uintptr_t)address,
        m->request.size,m->request.offset);
    if (found<0) return found;
    m->result=found && !m->before ? address : -ECANCELED;
    m->observed=1; return 0;
}
static int advance(struct helper *m, long value) {
    if (value<0) {
        m->result=value>=-4095 ? value : -EPROTO;
        m->observed=1;
        return abort_child(m);
    }
    unsigned long args[6]={0}; long nr=SYS_prctl;
    switch (m->operation) {
        case CLEAR:
            if (value) return -EPROTO;
            m->operation=CHANNEL; args[0]=MD_GUEST_TASK_HELPER;
            break;
        case CHANNEL:
            if (value) return -EPROTO;
            m->operation=OPEN; nr=SYS_openat;
            args[0]=AT_FDCWD; args[1]=m->parcel+offsetof(struct parcel,path); args[2]=m->flags;
            break;
        case OPEN: {
            if (value>INT32_MAX) return -EPROTO;
            int error=md_fd_channel_capture_begin(m->channel,m->group,1,&m->capture);
            if (error) { m->result=error; return abort_child(m); }
            struct md_buffer_span span;
            if ((error=md_buffer_span(&m->buffer,&span))) return error;
            struct parcel *p=span.data;
            p->token=m->capture.request;
            p->vector=(struct iovec){(void *)m->parcel,sizeof(p->token)};
            p->message=(struct msghdr){.msg_iov=(void *)(m->parcel+offsetof(struct parcel,vector)),.msg_iovlen=1,
                .msg_control=(void *)(m->parcel+offsetof(struct parcel,control)),.msg_controllen=sizeof(p->control)};
            p->control.align=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS,.cmsg_len=CMSG_LEN(sizeof(int))};
            int fd=(int)value; memcpy(CMSG_DATA(&p->control.align),&fd,sizeof(fd));
            m->operation=EXPORT; nr=SYS_sendmsg;
            args[1]=m->parcel+offsetof(struct parcel,message); args[2]=MSG_NOSIGNAL|MSG_DONTWAIT;
            break;
        }
        case EXPORT: {
            if (value!=sizeof(uint64_t)) return -EPROTO;
            struct md_fd_channel_input input;
            int error=md_fd_channel_capture_finish(&m->capture,&input);
            if (error) { m->result=error; return abort_child(m); }
            m->maps=input.fd[0];
            if (m->kind==MD_TASK_HELPER_CAPTURE) {
                m->result=0;
                return abort_child(m);
            }
            if (m->request.address) {
                m->before=md_mapping_observe(m->maps,&m->source,m->request.address,
                    m->request.size,m->request.offset);
                if (m->before<0) { m->result=m->before; return abort_child(m); }
            }
            m->operation=BACKING; args[0]=MD_GUEST_TASK_HELPER; args[1]=1;
            break;
        }
        case BACKING:
            if (value) return -EPROTO;
            m->operation=MAP; nr=SYS_mmap;
            args[0]=m->request.address; args[1]=m->request.size;
            args[2]=m->request.protection; args[3]=m->request.flags;
            args[5]=m->request.offset;
            break;
        case MAP:
            m->observed=1; m->result=value;
            return abort_child(m);
        default: return -EPROTO;
    }
    return call(m,m->child,nr,args);
}
struct md_task_helpers *md_task_helpers_new(const struct md_task_helper_callbacks *callbacks) {
    if (!callbacks || !callbacks->trace || !callbacks->newborn) return NULL;
    struct md_task_helpers *manager=calloc(1,sizeof(*manager));
    if (manager) manager->callbacks=*callbacks;
    return manager;
}
void md_task_helpers_destroy(struct md_task_helpers *manager) {
    if (!manager) return;
    while (manager->first) {
        manager->first->result=-ECANCELED;
        complete(manager->first);
    }
    free(manager);
}
unsigned md_task_helpers_count(const struct md_task_helpers *manager) { return manager ? manager->count : 0; }
int md_task_helper_begin(struct md_task_helpers *manager, pid_t owner, pid_t group,
        const struct user_pt_regs *regs, const struct md_interception_abi *abi,
        struct md_interception_memory *memory, const struct md_interception_buffer *buffer,
        const struct md_task_helper_request *request, md_task_helper_complete callback, void *context) {
    if (!manager || owner<=0 || group<=0 || !regs || !abi || !memory || !request || !callback) return -EINVAL;
    if (request->kind!=MD_TASK_HELPER_MAP && request->kind!=MD_TASK_HELPER_CAPTURE) return -EINVAL;
    const char *path=request->kind==MD_TASK_HELPER_MAP ? "/proc/thread-self/maps" : request->path;
    if (!path || !*path || strnlen(path,PATH_MAX)==PATH_MAX) return -EINVAL;
    if (request->kind==MD_TASK_HELPER_MAP && !request->mapping.size) return -EINVAL;
    if (request->kind==MD_TASK_HELPER_CAPTURE && (!(request->flags&O_PATH)
            || request->flags&~(O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW))) return -EINVAL;
    for (struct helper *m=manager->first;m;m=m->next) if (m->owner==owner) return -EBUSY;
    struct helper *m=calloc(1,sizeof(*m));
    if (!m) return -ENOMEM;
    *m=(struct helper){.manager=manager,.owner=owner,.group=group,.abi=*abi,.request=request->mapping,
        .kind=request->kind,.complete=callback,.flags=request->kind==MD_TASK_HELPER_MAP
            ? O_RDONLY|O_CLOEXEC : request->flags|O_CLOEXEC,
        .completion=context,.backing=-1,.maps=-1,.result=-ECANCELED};
    m->memory=md_memory_fork(memory,1);
    int error=m->memory ? md_buffer_pin(buffer,&m->buffer) : -ENOMEM;
    struct md_buffer_span span;
    if (!error) error=md_buffer_span(&m->buffer,&span);
    if (!error && span.size<sizeof(struct parcel)) error=-EINVAL;
    if (!error) {
        m->parcel=md_memory_buffer_address(memory,&m->buffer);
        if (!m->parcel) error=-EINVAL;
        else { memset(span.data,0,sizeof(struct parcel)); strcpy(((struct parcel *)span.data)->path,path); }
    }
    if (!error && request->kind==MD_TASK_HELPER_MAP) {
        m->backing=fcntl(request->mapping.source,F_DUPFD_CLOEXEC,0);
        error=m->backing<0 ? -errno : md_mapping_source(m->backing,&m->source);
    }
    if (!error) error=md_fd_channel_new(&m->channel);
    if (error) { dispose(m); return error; }
    m->next=manager->first; manager->first=m; ++manager->count;
    m->stack=md_memory_stack_take(memory);
    if (m->stack) error=clone_begin(m);
    else {
        m->parent_operation=ALLOCATE;
        struct user_pt_regs r=*regs; r.pc=abi->allocate;
        error=registers(m,owner,&r,1);
        if (!error) error=resume(m,owner);
    }
    if (error && error!=-ESRCH) { dispose(m); return error; }
    return 0;
}
int md_task_helper_detach(struct md_task_helpers *manager, pid_t owner) {
    if (!manager) return 0;
    for (struct helper *m=manager->first;m;m=m->next) if (m->owner==owner) {
        m->owner=0; m->cancelled=1;
        if (!m->child || m->reaped) { complete(m); return 0; }
        int error=(int)trace(m,PTRACE_INTERRUPT,m->child,NULL,NULL);
        return error==-ESRCH ? 0 : error;
    }
    return 0;
}
int md_task_helper_notification(struct md_task_helpers *manager, int listener, const struct seccomp_notif *q) {
    for (struct helper *m=manager ? manager->first : NULL;m;m=m->next) if (m->child==(pid_t)q->pid) {
        if (q->data.nr!=SYS_prctl || q->data.instruction_pointer!=m->abi.task_return
                || q->data.args[0]!=MD_GUEST_TASK_HELPER || q->data.args[1]!=(unsigned)(m->operation==BACKING)
                || q->data.args[2] || q->data.args[3] || q->data.args[4] || q->data.args[5]
                || (m->operation!=CHANNEL && m->operation!=BACKING)) return -EPROTO;
        struct seccomp_notif_addfd add={.id=q->id,.flags=SECCOMP_ADDFD_FLAG_SEND|SECCOMP_ADDFD_FLAG_SETFD,
            .srcfd=m->operation==CHANNEL ? md_fd_channel_endpoint(m->channel) : m->backing,
            .newfd=0,.newfd_flags=O_CLOEXEC};
        if (ioctl(listener,SECCOMP_IOCTL_NOTIF_ADDFD,&add)<0 && errno!=ENOENT) {
            struct seccomp_notif_resp reply={.id=q->id,.error=-errno};
            if (ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) && errno!=ENOENT) return -errno;
        }
        return 1;
    }
    return 0;
}
int md_task_helper_event(struct md_task_helpers *manager, pid_t pid, int status) {
    struct helper *m=manager ? manager->first : NULL;
    while (m && m->owner!=pid && m->child!=pid) m=m->next;
    if (!m) return 0;
    int child=pid==m->child;
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        if (!child) return 0;
        m->reaped=1;
        if (!m->owner || m->parent_ready) complete(m);
        return 1;
    }
    if (!WIFSTOPPED(status)) return -EPROTO;
    unsigned event=(unsigned)status>>16;
    int sig=WSTOPSIG(status), error=0;
    if (!child && (event==PTRACE_EVENT_EXIT || event==PTRACE_EVENT_EXEC)) return 0;
    if (!child && event==PTRACE_EVENT_CLONE) {
        unsigned long born;
        error=(int)trace(m,PTRACE_GETEVENTMSG,pid,NULL,&born);
        if (!error) {
            if (m->child || m->parent_operation!=CLONE) return -EPROTO;
            m->child=(pid_t)born;
            int ready=manager->callbacks.newborn(m->child);
            error=ready<0 ? ready : ready ? child_begin(m) : 0;
            if (!error) error=resume(m,pid);
        }
    } else if (child && event==PTRACE_EVENT_EXIT) {
        if (m->operation==MAP) {
            struct user_pt_regs r;
            error=registers(m,pid,&r,0);
            if (!error) error=observe(m,&r);
        }
        if (!error) error=resume(m,pid);
    } else if (child && event==PTRACE_EVENT_STOP) {
        if (!m->operation) error=child_begin(m);
        else if (m->cancelled) {
            struct user_pt_regs r;
            error=registers(m,pid,&r,0);
            if (!error && m->operation==MAP) error=observe(m,&r);
            if (!error) error=abort_child(m);
        } else error=resume(m,pid);
    } else if (event==PTRACE_EVENT_SECCOMP) {
        struct user_pt_regs r;
        error=registers(m,pid,&r,0);
        if (!error && r.pc!=m->abi.task_return) return -EPROTO;
        if (!error) {
            if (child && m->operation==MAP) m->started=1;
            error=resume(m,pid);
        }
    } else if (!event && sig==SIGTRAP) {
        struct user_pt_regs r;
        error=registers(m,pid,&r,0);
        if (!error && !child && m->parent_operation==ALLOCATE && r.pc==m->abi.allocated) {
            long top=r.regs[0];
            if (top<0) { m->result=top; complete(m); return 1; }
            if (!top || top%(size_t)getpagesize()) return -EPROTO;
            m->stack=top;
            error=md_memory_stack_add(m->memory,m->stack);
            if (!error) error=clone_begin(m);
        } else if (!error && r.pc==m->abi.task_return) {
            if (child) error=advance(m,(long)r.regs[0]);
            else {
                if ((long)r.regs[0]<0) {
                    if (m->child) return -EPROTO;
                    m->result=(long)r.regs[0]; complete(m); return 1;
                }
                if (!m->child || r.regs[0]!=(unsigned)m->child) return -EPROTO;
                /* EVENT_WAIT: exact helper reaping. Completion owns the caller
                 * continuation; no userspace wait or settling delay is used. */
                m->parent_ready=1;
                if (m->reaped) { complete(m); return 1; }
            }
        } else if (!error) return -EPROTO;
    } else if (child) {
        m->result=-EINTR;
        if (m->operation==MAP) {
            struct user_pt_regs r;
            error=registers(m,pid,&r,0);
            if (!error) error=observe(m,&r);
        }
        if (!error) error=abort_child(m);
    } else return 0;
    return error && error!=-ESRCH ? error : 1;
}
