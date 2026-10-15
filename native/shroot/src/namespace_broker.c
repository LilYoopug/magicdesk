#define _GNU_SOURCE
#include "task_memory.h"
#include "namespace_broker.h"
#include "fs_engine.h"
#include "watch_broker.h"
#include "task_descriptor.h"
#include "ofd_order.h"
#include "fd_install.h"
#include "notification_result.h"
#include "fs_buffer.h"
#include "fs_path_call.h"
#include <errno.h>
#include <fcntl.h>
#include "linux_abi.h"
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

struct operation {
    struct md_fs_work work;
    struct md_namespace_broker *owner;
    struct operation *all, *free;
    struct operation *waiting;
    struct task *task;
    struct seccomp_notif notification;
    struct md_fs_context context;
    struct md_fd_order order;
    struct md_fs_order fs_order;
    struct md_ofd_order cursor;
    struct md_fd_origin_update update;
    struct md_fs_anchor *input_origin, *output_origin;
    struct md_fs_request request;
    struct md_fs_result result;
    struct md_notification_result completion;
    struct md_fd_object *output_object;
    int control_descriptor;
    int64_t position;
    int listener, directory, undelivered, owned_open, executed, recovering;
    char path[PATH_MAX];
};
enum { TASK_BUCKETS = 257 };
struct md_namespace_broker {
    struct md_fs_worker *worker;
    void (*delegate)(const struct seccomp_notif *);
    void (*recover)(pid_t,struct md_broker_completion *);
    md_control_factory control;
    struct md_resource_wakeup *wakeup;
    struct operation *all, *free;
    struct operation *waiting;
    struct task *tasks;
    struct task *task_index[TASK_BUCKETS];
    struct task *result_waiting;
    struct task *event_ready;
    pthread_mutex_t lock;
    int listener;
    struct counters { uint64_t received, handled, delegated; } *counts;
    int synchronous_wake;
    uint64_t result_deliveries, result_waits, result_cancelled;
    struct md_watch_broker *watches;
    /* One synchronous worker owns this buffer; delegated operations retain no
     * bytes in it. Allocation is per broker, never per syscall or directory. */
    char output[64 * 1024];
};
struct task {
    struct task *next;
    struct task *indexed;
    int pid, eligible, process, borrowed;
    uintptr_t gate, watch_gate;
    struct operation *operation;
    struct md_namespace_broker *owner;
    struct md_fs_work event_work;
    struct task *event_next;
    int stopped, held, status, recovering;
    struct rusage usage;
    struct {
        struct md_notification_result completion;
        int queued;
        struct task *next;
    } result;
};
/* Caller holds the broker lock. A retired identity can still be borrowed by
 * a worker operation or by an exact kernel event awaiting main-loop delivery. */
static void task_release(struct task *t) {
    if (--t->borrowed<0) abort();
    if (!t->pid && !t->borrowed && t->process>=0) { close(t->process); t->process=-1; }
}
static int event_complete(struct md_fs_work *work) {
    struct task *t=(void *)((char *)work - offsetof(struct task,event_work));
    struct md_namespace_broker *b=t->owner;
    pthread_mutex_lock(&b->lock);
    if (t->pid) { t->event_next=b->event_ready; b->event_ready=t; }
    else { t->held=0; task_release(t); }
    pthread_mutex_unlock(&b->lock); return 0;
}
static void operation_retired(struct md_namespace_broker *b,struct operation *op) {
    /* Caller holds the broker lock. Publish only after resource turns and pins
     * have retired; the exact kernel event then resumes normal dispatch. */
    struct task *t=op->task;
    if (!t || t->operation!=op) return;
    t->operation=NULL;
    if (t->held==1) {
        t->held=2; md_fs_worker_publish(b->worker,&t->event_work);
    }
}
int md_broker_hold_event(struct md_namespace_broker *b,pid_t pid,int status,const struct rusage *usage) {
    if (!b) return 0;
    pthread_mutex_lock(&b->lock);
    struct task *t=NULL;
    for (t=b->task_index[(unsigned)pid%TASK_BUCKETS];t && t->pid!=pid;t=t->indexed) { }
    int held=0;
    if (t) {
        t->stopped=1;
        if (t->operation) {
            if (t->held) { pthread_mutex_unlock(&b->lock); return -EBUSY; }
            t->held=1; ++t->borrowed;
            t->status=status; t->usage=usage ? *usage : (struct rusage){0}; held=1;
        }
    }
    pthread_mutex_unlock(&b->lock);
    if (held) md_fs_worker_wake(b->worker);
    return held;
}
pid_t md_broker_take_event(struct md_namespace_broker *b,int *status,struct rusage *usage) {
    if (!b) return 0;
    pthread_mutex_lock(&b->lock);
    pid_t pid=0;
    while (b->event_ready && !pid) {
        struct task *t=b->event_ready;
        b->event_ready=t->event_next; t->event_next=NULL; t->held=0;
        task_release(t);
        pid=t->pid; *status=t->status; if (usage) *usage=t->usage;
    }
    pthread_mutex_unlock(&b->lock); return pid;
}
void md_broker_completion_handler(struct md_namespace_broker *b,void (*recover)(pid_t,struct md_broker_completion *)) {
    b->recover=recover;
}
void md_broker_control_factory(struct md_namespace_broker *b,md_control_factory factory) { b->control=factory; }
/* Broker lock protects admission against supervisor cancellation. No guest
 * memory, filesystem mutation or supervisor round trip occurs here. */
static int result_progress(struct md_namespace_broker *b, struct task *t) {
    int result=md_notification_result_progress(&t->result.completion);
    if (result==MD_NOTIFICATION_STATUS) result=md_notification_result_reply(&t->result.completion);
    if (result==MD_NOTIFICATION_WAIT) { ++b->result_waits; return 1; }
    if (result==MD_NOTIFICATION_CANCELLED) ++b->result_cancelled;
    if (result==MD_NOTIFICATION_DELIVERED) ++b->result_deliveries;
    return result<0 ? result : 0;
}
static void result_unqueue(struct md_namespace_broker *b, struct task *t) {
    if (!t->result.queued) return;
    struct task **p=&b->result_waiting;
    while (*p && *p!=t) p=&(*p)->result.next;
    if (*p) *p=t->result.next;
    t->result.queued=0; t->result.next=NULL;
}
static int result_clear(struct md_namespace_broker *b, struct task *t) {
    int error=md_notification_result_clear(&t->result.completion);
    if (error) return error;
    result_unqueue(b,t);
    memset(&t->result,0,sizeof(t->result));
    return 0;
}
static int result_receive(struct md_namespace_broker *b, struct task *t, const struct seccomp_notif *q) {
    if (!t || !t->result.completion.active || q->data.nr!=t->result.completion.call.nr
            || q->data.instruction_pointer!=t->result.completion.call.instruction_pointer) return 0;
    if (t->result.completion.delivered || !md_notification_result_matches(&t->result.completion,&q->data)) {
        struct seccomp_notif_resp reply={.id=q->id,.error=-EPERM};
        return ioctl(b->listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) && errno!=ENOENT ? -errno : 1;
    }
    int result=md_notification_result_offer(&t->result.completion,b->listener,q->id,b->wakeup);
    if (result==MD_NOTIFICATION_STATUS) result=md_notification_result_reply(&t->result.completion);
    if (result<0) return result;
    if (result==MD_NOTIFICATION_DELIVERED) ++b->result_deliveries;
    if (result==MD_NOTIFICATION_CANCELLED) ++b->result_cancelled;
    if (result==MD_NOTIFICATION_WAIT && !t->result.queued) {
        ++b->result_waits;
        t->result.next=b->result_waiting; b->result_waiting=t; t->result.queued=1;
    } else if (result!=MD_NOTIFICATION_WAIT) result_unqueue(b,t);
    return 1;
}
static int valid(struct operation *op) {
    return !ioctl(op->listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &op->notification.id);
}
static int duplicate(struct task *task, pid_t pid, int number) {
    /* Worker borrows this identity until preparation ends. Retirement cannot
     * close or reuse it meanwhile; file numbers themselves are never cached. */
    return md_task_descriptor_copy(pid,number,&task->process);
}
static int pathname(pid_t pid, uintptr_t address, char *out, size_t capacity) {
    return md_task_read_string(pid,address,out,capacity,(size_t)sysconf(_SC_PAGESIZE));
}
static int deliver_bytes(struct operation *op, uintptr_t pointer, const void *data, size_t size) {
    if (!valid(op)) return -ECANCELED;
    if (!size) return 0;
    struct iovec local = {(void *)data, size}, remote = {(void *)pointer, size};
    ssize_t n = process_vm_writev(op->notification.pid, &local, 1, &remote, 1, 0);
    /* Only a denied, untouched output may fall back to the task-affine path.
     * Partial copies and notification cancellation are terminal for this call. */
    if (n < 0 && (errno == EPERM || errno == EACCES)) op->undelivered = 1;
    return n == (ssize_t)size ? 0 : -EFAULT;
}
static int control_open(void *context,const struct md_control_file_ops *ops,void *data,
        const struct md_identity *identity,int flags) {
    struct operation *op=context;
    if (!op->owner->control) return -EOPNOTSUPP;
    if (op->output_object) return -EBUSY;
    op->output_object=op->owner->control(ops,data,identity,flags,&op->control_descriptor);
    return op->output_object ? 0 : -errno;
}
static void execute(struct operation *op,
        void *data, size_t capacity) {
    op->result = (struct md_fs_result){.fd = -1, .error = -ECANCELED};
    struct md_fs_output output = {.data = data, .capacity = capacity,
        .directory_position=op->request.operation==MD_FS_GETDENTS ? &op->position : NULL,
        .origin=op->request.operation==MD_FS_OPEN ? &op->output_origin : NULL,
        .control=op->owned_open && op->owner->control ? control_open : NULL,.control_context=op};
    if (valid(op)) {
        op->executed=1;
        md_fs_context_execute(&op->context, &op->request, &op->result, &output);
        if (!op->result.error && op->result.fd>=0 && op->control_descriptor>=0) {
            close(op->result.fd); op->result.fd=op->control_descriptor; op->control_descriptor=-1;
        }
    }
}
struct md_namespace_broker *md_broker_create(struct md_fs_worker *worker, int statistics,
        void (*delegate)(const struct seccomp_notif *)) {
    struct md_namespace_broker *b = calloc(1, sizeof(*b));
    if (b) {
        b->worker = worker; b->listener = -1; b->delegate=delegate;
        if (pthread_mutex_init(&b->lock, NULL)) { free(b); return NULL; }
        b->wakeup=md_resource_wakeup_retain(md_fs_worker_wakeup(worker));
        if (!b->wakeup) {
            pthread_mutex_destroy(&b->lock); free(b); return NULL;
        }
        if (statistics && !(b->counts = calloc(512, sizeof(*b->counts)))) {
            md_resource_wakeup_release(b->wakeup);
            pthread_mutex_destroy(&b->lock); free(b); return NULL;
        }
    }
    return b;
}
static int recycle(struct md_namespace_broker *b, struct operation *op) {
    int cleared=md_notification_result_clear(&op->completion);
    if (cleared) return cleared;
    if (op->directory >= 0) close(op->directory);
    if (op->result.fd >= 0) close(op->result.fd);
    if (op->control_descriptor>=0) close(op->control_descriptor);
    op->control_descriptor=-1;
    md_fd_object_release(op->output_object); op->output_object=NULL;
    if (op->result.open_completion.kind == MD_OPEN_PIPE) close(op->result.open_completion.control);
    op->directory = op->result.fd = -1;
    op->result.open_completion = (struct md_open_completion){0};
    md_fd_origins_finish(&op->update,-1);
    md_fs_anchor_release(op->input_origin); op->input_origin=NULL;
    md_fs_anchor_release(op->output_origin); op->output_origin=NULL;
    int error=0;
    if (op->cursor.owner) {
        error=md_ofd_order_cancel(&op->cursor);
        if (error==1) error=md_ofd_order_complete(&op->cursor);
    }
    if (op->fs_order.fs) {
        error=md_fs_order_cancel(&op->fs_order);
        if (error==1) error=md_fs_order_complete(&op->fs_order);
    }
    if (op->order.table) {
        int retired=md_fd_order_cancel(&op->order);
        if (retired==1) retired=md_fd_order_complete(&op->order);
        if (!error) error=retired;
    }
    md_fs_context_end(&op->context);
    pthread_mutex_lock(&b->lock);
    operation_retired(b,op);
    if (op->task) {
        task_release(op->task);
        op->task=NULL;
    }
    op->free = b->free; b->free = op;
    pthread_mutex_unlock(&b->lock);
    return error;
}
static int prepare(struct md_filesystem *fs, struct operation *op, size_t capacity) {
    const struct seccomp_notif *q = &op->notification;
    if (!md_broker_filesystem_call(q->data.nr)) return 0;
    /* ADDFD uses fget(), which rejects O_PATH; SCM_RIGHTS preserves it. */
    if (q->data.nr==SYS_openat) {
        if (q->data.args[2]&(__O_TMPFILE|O_PATH)) return 0;
        op->owned_open=op->owner->recover && (op->task->eligible&MD_BROKER_OPEN);
        if (!op->owned_open && (q->data.args[2]&(O_CREAT|O_TRUNC))) return 0;
    }
    if (q->data.nr == SYS_newfstatat && (q->data.args[3] & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT))) return 0;
    if (q->data.nr==SYS_readlinkat && !q->data.args[3]) return -EINVAL;
    op->request = (struct md_fs_request){.actor = (int)q->pid, .operation = MD_FS_FSTAT, .directory = {-1, -1}};
    op->path[0] = 0;
    if (q->data.nr==SYS_fsopen) {
        if (!op->owner->recover || !(op->task->eligible&MD_BROKER_OPEN)) return 0;
        int error=md_fs_fsopen_parameters(&op->request,(unsigned)q->data.args[1]);
        if (error) return error;
        if (pathname(q->pid,q->data.args[0],op->path,sizeof(op->path))) return 0;
        op->request.path[0]=op->path; op->owned_open=1;
        error=md_fs_context_begin(fs,(int)q->pid,0,&op->context);
        return error ? error : 1;
    }
    unsigned long args[6];
    for (unsigned i=0;i<6;++i) args[i]=q->data.args[i];
    md_fs_path_call(&op->request,q->data.nr,args);
    if (q->data.nr == SYS_getdents64) {
        op->request.operation = MD_FS_GETDENTS;
        op->request.capacity = q->data.args[2] > capacity ? (uint32_t)capacity : (uint32_t)q->data.args[2];
    } else if (q->data.nr != SYS_fstat) {
        if (pathname(q->pid, q->data.args[1], op->path, sizeof(op->path))) goto delegate;
        if (!*op->path && q->data.nr!=SYS_readlinkat
                && (q->data.nr != SYS_newfstatat || !(q->data.args[3] & AT_EMPTY_PATH))) goto delegate;
        op->request.path[0] = op->path;
        if (q->data.nr==SYS_readlinkat) {
            op->request.operation=MD_FS_READLINK;
            op->request.capacity=q->data.args[3]>capacity ? (uint32_t)capacity : (uint32_t)q->data.args[3];
        } else {
            if (*op->path) op->request.operation = q->data.nr == SYS_openat ? MD_FS_OPEN : MD_FS_STAT;
            op->request.flags = q->data.nr == SYS_openat ? (uint32_t)q->data.args[2]
                : *op->path ? (uint32_t)(q->data.args[3] & AT_SYMLINK_NOFOLLOW) : 0;
        }
    }
    int error=md_fs_context_begin(fs,(int)q->pid,0,&op->context);
    if (error) return error;
    return 1;
delegate:
    return 0;
}
static int capture(struct operation *op) {
    const struct seccomp_notif *q=&op->notification;
    if (op->request.operation==MD_FS_FSOPEN) return 1;
    if (*op->path != '/') {
        if ((int)q->data.args[0] == AT_FDCWD && op->request.path[0]) {
            struct md_fs_location root;
            md_domain_paths(op->fs_order.fs,&root,&op->input_origin);
            if (op->input_origin)
                op->directory=fcntl(md_fs_anchor_fd(op->input_origin),F_DUPFD_CLOEXEC,0);
            else {
                char cwd[64]; snprintf(cwd, sizeof(cwd), "/proc/%u/cwd", q->pid);
                op->directory = open(cwd, O_PATH | O_DIRECTORY | O_CLOEXEC);
            }
        } else {
            op->directory = duplicate(op->task, q->pid, (int)q->data.args[0]);
            if (op->directory>=0) {
                struct md_fd_object *object=md_fd_origins_object(op->context.task.files,(int)q->data.args[0],NULL);
                op->input_origin=md_fs_anchor_retain(md_fs_anchor_from_object(object));
                int unsupported=object && !op->input_origin;
                md_fd_object_release(object);
                if (unsupported) return 0;
            }
        }
        if (op->directory < 0) return 0;
        op->request.directory[0] = op->directory;
        op->request.origin[0]=op->input_origin;
    }
    return 1;
}
static void recover(struct operation *op) {
    op->recovering=1;
    pthread_mutex_lock(&op->owner->lock);
    if (op->task && op->task->pid==(int)op->notification.pid) op->task->recovering=1;
    pthread_mutex_unlock(&op->owner->lock);
}
/* Zero requests task-affine handling, one means delivered/cancelled. */
static int reply(struct operation *op, const void *data) {
    if (op->result.error == -EXDEV || op->result.error == -EREMOTE || op->result.host_path || op->result.requires_control
            || op->undelivered) return 0;
    struct seccomp_notif_resp response = {.id = op->notification.id, .error = op->result.error};
    if (op->owned_open && op->executed) {
        if (op->result.error || op->result.fd<0) {
            recover(op); return 0;
        }
        if (!op->result.error && op->result.fd>=0 && (op->result.open_completion.kind!=MD_OPEN_READY
                || md_fd_object_selectors(op->output_object))) {
            recover(op); return 0;
        }
        int error=md_notification_result_fd(&op->completion,&op->notification.data,op->context.task.files,
                op->result.fd,op->output_object ? op->output_object : md_fs_anchor_object(op->output_origin),
                op->request.flags&O_CLOEXEC);
        if (error) return error;
        int result=md_notification_result_offer(&op->completion,op->listener,op->notification.id,op->owner->wakeup);
        if (result==MD_NOTIFICATION_CANCELLED || result==MD_NOTIFICATION_STATUS) { recover(op); return 0; }
        if (result==MD_NOTIFICATION_WAIT) return 2;
        if (result==MD_NOTIFICATION_DELIVERED) op->result.error=op->completion.value<0 ? (int)op->completion.value : 0;
        return result<0 ? result : 1;
    }
    if (op->result.open_completion.kind!=MD_OPEN_READY) return 0;
    if (!response.error && op->notification.data.nr == SYS_openat) {
        int error=md_fd_origins_prepare(op->context.task.files,op->output_origin,
            op->notification.data.args[2]&O_CLOEXEC ? FD_CLOEXEC : 0,&op->update);
        if (error) {
            response.error=error;
            return !ioctl(op->listener,SECCOMP_IOCTL_NOTIF_SEND,&response) || errno==ENOENT ? 1 : -errno;
        }
        /* Atomic kernel publication remains inside the same table turn as its
         * origin publication. A resumed CLONE_FILES peer must acquire that turn. */
        struct seccomp_notif_addfd add = {.id = response.id, .srcfd = op->result.fd,
            .flags = SECCOMP_ADDFD_FLAG_SEND,
            .newfd_flags = (uint32_t)op->notification.data.args[2] & O_CLOEXEC};
        int fd=ioctl(op->listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
        if (fd>=0) { md_fd_origins_finish(&op->update,fd); return 1; }
        response.error = -errno;
    } else if (!response.error && (op->notification.data.nr == SYS_getdents64
            || op->notification.data.nr==SYS_readlinkat)) {
        size_t size=op->result.size;
        int link=op->notification.data.nr==SYS_readlinkat;
        if (link && size>op->request.capacity) size=op->request.capacity;
        response.error=link && !op->request.capacity ? -EINVAL
            : deliver_bytes(op,op->notification.data.args[link ? 2 : 1],data,size);
        if (op->undelivered) return 0;
        if (!response.error) response.val=size;
    } else if (!response.error) {
        if (!valid(op)) return 1;
        struct stat st;
        if (op->result.size == sizeof(st)) memcpy(&st, data, sizeof(st));
        else md_fs_info_stat(&op->result.info, &st);
        uintptr_t pointer = op->notification.data.args[op->notification.data.nr == SYS_newfstatat ? 2 : 1];
        struct iovec local = {&st, sizeof(st)}, remote = {(void *)pointer, sizeof(st)};
        ssize_t n = process_vm_writev(op->notification.pid, &local, 1, &remote, 1, 0);
        if (n < 0 && (errno == EPERM || errno == EACCES)) return 0;
        if (n != sizeof(st)) response.error = -EFAULT;
    }
    if (ioctl(op->listener, SECCOMP_IOCTL_NOTIF_SEND, &response))
        return errno==ENOENT ? 1 : -errno;
    /* A signal may cancel the notification after copying bytes. Commit only
     * after kernel acceptance, retaining the table/OFD turn through this seek. */
    if (!response.error && op->notification.data.nr==SYS_getdents64) {
        off_t position=lseek(op->directory,op->position,SEEK_SET);
        if (position!=op->position) return position<0 ? -errno : -EIO;
    }
    return 1;
}
/* Caller holds the broker lock; borrowed retired records stay outside the index. */
static struct task *find_task(struct md_namespace_broker *b, int pid) {
    if (pid <= 0) return NULL;
    for (struct task *t = b->task_index[(unsigned)pid % TASK_BUCKETS]; t; t = t->indexed)
        if (t->pid == pid) return t;
    return NULL;
}
void md_broker_completion_taken(struct md_namespace_broker *b,pid_t pid) {
    if (!b) return;
    pthread_mutex_lock(&b->lock);
    struct task *t=find_task(b,pid);
    if (t) t->recovering=0;
    pthread_mutex_unlock(&b->lock);
}
int md_broker_result_begin(struct md_namespace_broker *b, int pid, const struct seccomp_data *call,
        struct md_fd_origins *files, int source, struct md_fd_object *origin, unsigned flags) {
    if (!b || !call || !call->instruction_pointer || (call->nr!=SYS_fstat && call->nr!=SYS_gettid)
            || !files || source<0 || flags&~O_CLOEXEC) return -EINVAL;
    pthread_mutex_lock(&b->lock);
    struct task *t=find_task(b,pid);
    int error=!t ? -ESRCH : t->result.completion.active ? -EBUSY
        : md_notification_result_fd(&t->result.completion,call,files,source,origin,flags);
    pthread_mutex_unlock(&b->lock); return error;
}
int md_broker_result_finish(struct md_namespace_broker *b, int pid, long *value) {
    if (!b) return 0;
    pthread_mutex_lock(&b->lock);
    struct task *t=find_task(b,pid);
    int delivered=t && t->result.completion.delivered;
    if (delivered && value) *value=t->result.completion.value;
    int error=t ? result_clear(b,t) : 0;
    pthread_mutex_unlock(&b->lock); return error ? error : delivered;
}
int md_broker_task(struct md_namespace_broker *b, int pid, int eligible, uintptr_t raw_gate, uintptr_t watch_gate) {
    if (pid <= 0) return -EINVAL;
    pthread_mutex_lock(&b->lock);
    struct task *t = find_task(b, pid);
    if (!t) {
        for (t = b->tasks; t && (t->pid || t->borrowed); t = t->next) { }
        if (!t) { t = calloc(1, sizeof(*t)); if (t) { t->process = -1; t->next = b->tasks; b->tasks = t; } }
        if (t) {
            unsigned bucket = (unsigned)pid % TASK_BUCKETS;
            t->indexed = b->task_index[bucket]; b->task_index[bucket] = t;
        }
    }
    if (t) {
        t->pid = pid; t->eligible = eligible; t->gate = raw_gate; t->watch_gate = watch_gate;
        t->stopped=0; t->owner=b; t->event_work.complete=event_complete;
    }
    pthread_mutex_unlock(&b->lock);
    return t ? 0 : -ENOMEM;
}
void md_broker_forget(struct md_namespace_broker *b, int pid) {
    if (!b || pid <= 0) return;
    pthread_mutex_lock(&b->lock);
    struct task **slot = &b->task_index[(unsigned)pid % TASK_BUCKETS];
    while (*slot && (*slot)->pid != pid) slot = &(*slot)->indexed;
    struct task *t = *slot;
    if (t) {
        if (result_clear(b,t)) abort();
        *slot = t->indexed; t->indexed = NULL;
        t->pid = 0;
        t->recovering=0;
        if (!t->borrowed && t->process >= 0) { close(t->process); t->process = -1; }
    }
    pthread_mutex_unlock(&b->lock);
    md_fs_worker_wake(b->worker);
}
static int perform(struct md_namespace_broker *b, struct operation *op, int prepared) {
    struct counters *count=b->counts && (unsigned)op->notification.data.nr<512
        ? &b->counts[op->notification.data.nr] : NULL;
    if (prepared>0 && !op->cursor.owner) {
        if (op->order.table && md_fd_order_state(&op->order)==MD_RESOURCE_ORDER_READY) {
            int error=md_fd_order_start(&op->order);
            if (error) return error;
        }
        int cwd=*op->path!='/' && (int)op->notification.data.args[0]==AT_FDCWD && op->request.path[0];
        if (cwd) {
            if (!op->fs_order.fs) {
                int ready=md_fs_order_begin(op->context.task.fs,&op->fs_order,b->wakeup);
                if (ready<0) return ready;
                if (!ready) {
                    /* EVENT_WAIT: the shared CLONE_FS owner completes its cwd
                     * mutation; notification cancellation retires this request. */
                    op->waiting=b->waiting; b->waiting=op; return 0;
                }
            }
            int error=md_fs_order_start(&op->fs_order);
            if (error) return error;
        }
        prepared=capture(op);
        if (op->fs_order.fs) {
            int error=md_fs_order_complete(&op->fs_order);
            if (error) return error;
        }
        if (prepared>0 && op->request.operation==MD_FS_GETDENTS) {
            int ready=md_ofd_order_begin(md_fs_worker_cursors(b->worker),op->directory,0,&op->cursor,b->wakeup);
            if (ready<0) prepared=ready;
            else if (!ready) {
                /* EVENT_WAIT: copied bytes are acknowledged by the current
                 * OFD owner; notification cancellation retires this reader. */
                op->waiting=b->waiting; b->waiting=op; return 0;
            }
        }
    }
    if (prepared>0 && op->cursor.owner) {
        int error=md_ofd_order_start(&op->cursor);
        if (error) return error;
    }
    if (op->owned_open && op->order.table) {
        int error=md_fd_order_complete(&op->order);
        if (error) return error;
    }
    if (prepared) {
        if (prepared>0) execute(op,b->output,sizeof(b->output));
        else op->result.error=prepared;
        int result=reply(op,b->output);
        if (result==2) { op->waiting=b->waiting; b->waiting=op; return 0; }
        if (result) {
            if (count) count->handled++;
            int error=recycle(b,op); return result<0 ? result : error;
        }
    }
    if (op->order.table) {
        int error=md_fd_order_complete(&op->order);
        if (error) return error;
    }
    if (op->cursor.owner) {
        int error=md_ofd_order_complete(&op->cursor);
        if (error) return error;
    }
    /* Delegation has not committed guest-visible IO; authenticate the later
     * task-affine request independently, without holding this table's turn. */
    md_fs_context_end(&op->context);
    md_fs_worker_publish(b->worker,&op->work);
    if (count) count->delegated++;
    return 0;
}
static int progress(struct md_namespace_broker *b) {
    pthread_mutex_lock(&b->lock);
    int result=0;
    struct task **pending=&b->result_waiting;
    while (*pending) {
        struct task *t=*pending;
        result=result_progress(b,t);
        if (result<0) break;
        if (result) { pending=&t->result.next; continue; }
        *pending=t->result.next; t->result.next=NULL; t->result.queued=0;
    }
    pthread_mutex_unlock(&b->lock);
    if (result<0) return result;
    struct operation **at=&b->waiting;
    while (*at) {
        struct operation *op=*at;
        if (op->completion.active) {
            int done=md_notification_result_progress(&op->completion);
            if (done<0) return done;
            if (done==MD_NOTIFICATION_WAIT) { at=&op->waiting; continue; }
            *at=op->waiting; op->waiting=NULL;
            if (done==MD_NOTIFICATION_CANCELLED || done==MD_NOTIFICATION_STATUS) {
                recover(op); md_fs_worker_publish(b->worker,&op->work);
            } else {
                int error=recycle(b,op); if (error) return error;
            }
            continue;
        }
        int alive=valid(op);
        if (alive && (op->cursor.owner
                ? md_ofd_order_state(&op->cursor)!=MD_RESOURCE_ORDER_READY
                : md_fd_order_state(&op->order)!=MD_RESOURCE_ORDER_READY
                    && md_fs_order_state(&op->fs_order)!=MD_RESOURCE_ORDER_READY)) { at=&op->waiting; continue; }
        *at=op->waiting; op->waiting=NULL;
        int error=alive ? perform(b,op,1) : recycle(b,op);
        if (error) return error;
    }
    return 0;
}
static int complete(struct md_fs_work *work) {
    struct operation *op=(struct operation *)work;
    struct md_namespace_broker *b=op->owner;
    if (op->recovering && op->task && op->task->pid==(int)op->notification.pid) {
        struct md_broker_completion result={.call=op->notification.data,.result=op->result,
            .notification_live=valid(op),
            .operation=op->request.operation,.flags=op->request.flags,
            .opened={.fd=op->result.fd,.origin=op->output_origin,.object=op->output_object,
                .completion=op->result.open_completion}};
        if (op->completion.active && op->completion.source<0) result.result.error=(int)op->completion.value;
        op->result.fd=-1; op->output_origin=NULL; op->output_object=NULL;
        op->result.open_completion=(struct md_open_completion){0};
        if (result.result.error) md_fs_buffer_open_release(&result.opened);
        b->recover((pid_t)op->notification.pid,&result);
    } else if (valid(op)) b->delegate(&op->notification);
    return recycle(b,op);
}
static int receive(void *context, struct md_filesystem *fs, short events) {
    struct md_inode_store *s = fs->store;
    struct md_namespace_broker *b = context;
    if (!events) {
        int error=progress(b);
        return error ? error : b->watches ? md_watch_broker_progress(b->watches,s) : 0;
    }
    if (events & (POLLERR | POLLNVAL)) return -EIO;
    if (!(events & POLLIN)) {
        if (events & POLLHUP) md_fs_worker_notifications(b->worker, -1, b, receive);
        return 0;
    }
    struct seccomp_notif q = {0};
    if (ioctl(b->listener, SECCOMP_IOCTL_NOTIF_RECV, &q)) {
        return errno == EINTR || errno == ENOENT ? 0 : -errno;
    }
    struct counters *count = b->counts && (unsigned)q.data.nr < 512 ? &b->counts[q.data.nr] : NULL;
    if (count) count->received++;
    pthread_mutex_lock(&b->lock);
    int eligible = 0, watch = 0;
    struct task *task = find_task(b, (int)q.pid);
    int delivered=result_receive(b,task,&q);
    if (delivered) {
        pthread_mutex_unlock(&b->lock);
        if (count && delivered>0) count->handled++;
        return delivered<0 ? delivered : 0;
    }
    if (task) {
        eligible = task->eligible && !task->stopped && !task->recovering && q.data.instruction_pointer != task->gate;
        watch = q.data.instruction_pointer == task->watch_gate;
        task->borrowed++;
    }
    if (watch) {
        pthread_mutex_unlock(&b->lock);
        int fd = duplicate(task, q.pid, (int)q.data.args[q.data.nr == SYS_sendfile ? 1 : 0]);
        pthread_mutex_lock(&b->lock);
        task_release(task);
        pthread_mutex_unlock(&b->lock);
        if (!b->watches) b->watches = md_watch_broker_create();
        if (!b->watches) { if (fd >= 0) close(fd); return -ENOMEM; }
        return md_watch_broker_submit(b->watches, s, b->listener, &q, fd);
    }
    struct operation *op = b->free;
    if (op) b->free = op->free;
    pthread_mutex_unlock(&b->lock);
    if (!op) {
        op = calloc(1, sizeof(*op));
        if (!op) {
            pthread_mutex_lock(&b->lock);
            if (task) task_release(task);
            pthread_mutex_unlock(&b->lock);
            return -ENOMEM;
        }
        op->all = b->all; b->all = op;
    }
    op->notification = q; op->listener = b->listener;
    op->directory = op->control_descriptor = -1; op->undelivered = 0;
    op->owned_open=op->executed=op->recovering=0;
    op->owner=b; op->work.complete=complete;
    op->task=task;
    pthread_mutex_lock(&b->lock);
    if (task && eligible) {
        eligible=!task->stopped && !task->recovering && !task->operation;
        if (eligible) task->operation=op;
    }
    pthread_mutex_unlock(&b->lock);
    op->result = (struct md_fs_result){.fd = -1};
    int prepared = eligible ? prepare(fs, op, sizeof(b->output)) : 0;
    /* Absolute metadata/link lookups neither borrow nor publish a caller FD.
     * Task-relative proc objects delegate before execution and acquire their
     * own table turn. Do not serialize ordinary pathname reads with close/dup. */
    if (prepared>0 && op->request.operation!=MD_FS_FSOPEN
            && (*op->path!='/' || op->request.operation==MD_FS_OPEN)) {
        int ready=md_fd_order_begin(op->context.task.files,&op->order,b->wakeup);
        if (ready<0) prepared=ready;
        else if (!ready) {
            op->waiting=b->waiting; b->waiting=op;
            return 0;
        }
    }
    return perform(b,op,prepared);
}
void md_broker_listen(struct md_namespace_broker *b, int listener) {
    b->listener = listener;
#ifdef SECCOMP_IOCTL_NOTIF_SET_FLAGS
    /* Optional scheduling hint, not a kernel prerequisite or an affinity policy. */
    b->synchronous_wake = !ioctl(listener, SECCOMP_IOCTL_NOTIF_SET_FLAGS, SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP);
#endif
    md_fs_worker_notifications(b->worker, listener, b, receive);
}
void md_broker_destroy(struct md_namespace_broker *b) {
    if (!b) return;
    md_watch_broker_destroy(b->watches);
    /* The worker must have joined before operation storage is released. */
    if (b->counts) {
        fprintf(stderr,"MD_BROKER resultDeliveries=%llu resultWaits=%llu resultCancelled=%llu\n",
            (unsigned long long)b->result_deliveries,(unsigned long long)b->result_waits,
            (unsigned long long)b->result_cancelled);
        fprintf(stderr, "MD_BROKER synchronousWake=%d\n", b->synchronous_wake);
        for (unsigned i = 0; i < 512; ++i) if (b->counts[i].received)
            fprintf(stderr, "MD_BROKER nr=%u notifications=%llu handled=%llu delegated=%llu\n", i,
                (unsigned long long)b->counts[i].received, (unsigned long long)b->counts[i].handled,
                (unsigned long long)b->counts[i].delegated);
        free(b->counts);
    }
    while (b->all) {
        struct operation *op = b->all; b->all = op->all;
        if (md_notification_result_clear(&op->completion)) abort();
        if (op->control_descriptor>=0) close(op->control_descriptor);
        md_fd_object_release(op->output_object);
        if (op->directory >= 0) close(op->directory);
        if (op->result.fd >= 0) close(op->result.fd);
        if (op->result.open_completion.kind == MD_OPEN_PIPE) close(op->result.open_completion.control);
        md_fd_origins_finish(&op->update,-1);
        md_fs_anchor_release(op->input_origin); md_fs_anchor_release(op->output_origin);
        if (op->cursor.owner) {
            if (md_ofd_order_cancel(&op->cursor)==1) md_ofd_order_complete(&op->cursor);
        }
        if (op->fs_order.fs) {
            if (md_fs_order_cancel(&op->fs_order)==1) md_fs_order_complete(&op->fs_order);
        }
        if (op->order.table) {
            if (md_fd_order_cancel(&op->order)==1) md_fd_order_complete(&op->order);
        }
        md_fs_context_end(&op->context);
        free(op);
    }
    while (b->tasks) {
        struct task *t = b->tasks; b->tasks = t->next;
        if (result_clear(b,t)) abort();
        if (t->process >= 0) close(t->process);
        free(t);
    }
    md_resource_wakeup_release(b->wakeup);
    pthread_mutex_destroy(&b->lock); free(b);
}
