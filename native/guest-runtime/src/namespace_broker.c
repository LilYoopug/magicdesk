#define _GNU_SOURCE
#include "namespace_broker.h"
#include "fs_engine.h"
#include "proc_paths.h"
#include "watch_broker.h"
#include "task_descriptor.h"
#include "ofd_order.h"
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
    int listener, directory, undelivered;
    char path[PATH_MAX];
};
struct md_namespace_broker {
    struct md_fs_worker *worker;
    void (*delegate)(const struct seccomp_notif *);
    struct md_resource_wakeup *wakeup;
    struct operation *all, *free;
    struct operation *waiting;
    struct task *tasks;
    pthread_mutex_t lock;
    int listener;
    struct counters { uint64_t received, handled, delegated; } *counts;
    int synchronous_wake;
    struct md_watch_broker *watches;
    /* One synchronous worker owns this buffer; delegated operations retain no
     * bytes in it. Allocation is per broker, never per syscall or directory. */
    char output[64 * 1024];
};
struct task {
    struct task *next;
    int pid, eligible, process, borrowed;
    uintptr_t gate, watch_gate;
};
static int valid(struct operation *op) {
    return !ioctl(op->listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &op->notification.id);
}
static int duplicate(struct task *task, pid_t pid, int number) {
    /* Worker borrows this identity until preparation ends. Retirement cannot
     * close or reuse it meanwhile; file numbers themselves are never cached. */
    return md_task_descriptor_copy(pid,number,&task->process);
}
static int pathname(pid_t pid, uintptr_t address, char *out, size_t capacity) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE), copied = 0;
    while (copied < capacity) {
        if (address > UINTPTR_MAX - copied) return -EFAULT;
        size_t size = page - ((address + copied) % page);
        if (size > capacity - copied) size = capacity - copied;
        struct iovec local = {out + copied, size}, remote = {(void *)(address + copied), size};
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n <= 0) return n < 0 ? -errno : -EFAULT;
        if (memchr(out + copied, 0, (size_t)n)) return 0;
        copied += (size_t)n;
    }
    return -ENAMETOOLONG;
}
static int deliver_directory(void *context, const void *data, size_t size) {
    struct operation *op = context;
    if (!valid(op)) return -ECANCELED;
    if (!size) return 0;
    struct iovec local = {(void *)data, size}, remote = {(void *)op->notification.data.args[1], size};
    ssize_t n = process_vm_writev(op->notification.pid, &local, 1, &remote, 1, 0);
    /* Only a denied, untouched output may fall back to the task-affine path.
     * Partial copies and notification cancellation are terminal for this call. */
    if (n < 0 && (errno == EPERM || errno == EACCES)) op->undelivered = 1;
    return n == (ssize_t)size ? 0 : -EFAULT;
}
static void execute(struct operation *op,
        void *data, size_t capacity) {
    op->result = (struct md_fs_result){.fd = -1, .error = -ECANCELED};
    struct md_fs_output output = {.data = data, .capacity = capacity,
        .deliver = deliver_directory, .context = op,
        .origin=op->request.operation==MD_FS_OPEN ? &op->output_origin : NULL};
    if (valid(op)) md_fs_context_execute(&op->context, &op->request, &op->result, &output);
    if (op->result.error == -EXDEV && op->request.operation == MD_FS_FSTAT) {
        /* Native descriptors outside the namespace retain kernel metadata. */
        struct stat st;
        if (fstat(op->directory, &st)) op->result.error = -errno;
        else {
            memcpy(data, &st, sizeof(st));
            op->result.size = sizeof(st); op->result.error = 0;
        }
    }
}
struct md_namespace_broker *md_broker_create(struct md_fs_worker *worker, int statistics,
        void (*delegate)(const struct seccomp_notif *)) {
    struct md_namespace_broker *b = calloc(1, sizeof(*b));
    if (b) {
        b->worker = worker; b->listener = -1; b->delegate=delegate;
        if (pthread_mutex_init(&b->lock, NULL)) { free(b); return NULL; }
        if (md_resource_wakeup_create(md_fs_worker_wake_fd(worker),&b->wakeup)) {
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
    if (op->directory >= 0) close(op->directory);
    if (op->result.fd >= 0) close(op->result.fd);
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
    if (op->task) {
        op->task->borrowed--;
        if (!op->task->pid && op->task->process>=0) { close(op->task->process); op->task->process=-1; }
        op->task=NULL;
    }
    op->free = b->free; b->free = op;
    pthread_mutex_unlock(&b->lock);
    return error;
}
static int prepare(struct md_filesystem *fs, struct operation *op, size_t capacity) {
    const struct seccomp_notif *q = &op->notification;
    if (q->data.nr != SYS_openat && q->data.nr != SYS_newfstatat
            && q->data.nr != SYS_fstat && q->data.nr != SYS_getdents64) return 0;
    /* Mutating opens retain the task-affine path, never speculative replay. */
    /* ADDFD uses fget(), which rejects O_PATH; SCM_RIGHTS preserves it. */
    if (q->data.nr == SYS_openat && (q->data.args[2] & (O_CREAT | O_TRUNC | __O_TMPFILE | O_PATH))) return 0;
    if (q->data.nr == SYS_newfstatat && (q->data.args[3] & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT))) return 0;
    op->request = (struct md_fs_request){.actor = (int)q->pid, .operation = MD_FS_FSTAT, .directory = {-1, -1}};
    op->path[0] = 0;
    if (q->data.nr == SYS_getdents64) {
        op->request.operation = MD_FS_GETDENTS;
        op->request.capacity = q->data.args[2] > capacity ? (uint32_t)capacity : (uint32_t)q->data.args[2];
    } else if (q->data.nr != SYS_fstat) {
        if (pathname(q->pid, q->data.args[1], op->path, sizeof(op->path)) || md_host_path(op->path)) goto delegate;
        if (!*op->path && (q->data.nr != SYS_newfstatat || !(q->data.args[3] & AT_EMPTY_PATH))) goto delegate;
        op->request.path[0] = op->path;
        if (*op->path) op->request.operation = q->data.nr == SYS_openat ? MD_FS_OPEN : MD_FS_STAT;
        op->request.flags = q->data.nr == SYS_openat ? (uint32_t)q->data.args[2]
            : *op->path ? (uint32_t)(q->data.args[3] & AT_SYMLINK_NOFOLLOW) : 0;
    }
    int error=md_fs_context_begin(fs,(int)q->pid,0,&op->context);
    if (error) return error;
    return 1;
delegate:
    return 0;
}
static int capture(struct operation *op) {
    const struct seccomp_notif *q=&op->notification;
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
            if (op->directory>=0)
                op->input_origin=md_fd_origins_get(op->context.task.files,(int)q->data.args[0],NULL);
        }
        if (op->directory < 0) return 0;
        op->request.directory[0] = op->directory;
        op->request.origin[0]=op->input_origin;
    }
    return 1;
}
static void metadata(const struct md_fs_info *i, struct stat *s) {
    *s = (struct stat){.st_dev = i->device, .st_ino = i->inode, .st_nlink = i->links,
        .st_rdev = i->rdev, .st_size = i->size, .st_blocks = i->blocks, .st_mode = i->mode,
        .st_uid = i->uid, .st_gid = i->gid, .st_blksize = i->block_size,
        .st_atim = {i->access_seconds, i->access_nanos}, .st_mtim = {i->modify_seconds, i->modify_nanos},
        .st_ctim = {i->change_seconds, i->change_nanos}};
}
/* Zero requests task-affine handling, one means delivered/cancelled. */
static int reply(struct operation *op, const void *data) {
    if (op->result.error == -EXDEV || op->result.error == -EREMOTE || op->result.host_path
            || op->result.open_completion.kind != MD_OPEN_READY || op->undelivered) return 0;
    struct seccomp_notif_resp response = {.id = op->notification.id, .error = op->result.error};
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
    } else if (!response.error && op->notification.data.nr == SYS_getdents64) {
        response.val = op->result.size;
    } else if (!response.error) {
        if (!valid(op)) return 1;
        struct stat st;
        if (op->result.size == sizeof(st)) memcpy(&st, data, sizeof(st));
        else metadata(&op->result.info, &st);
        uintptr_t pointer = op->notification.data.args[op->notification.data.nr == SYS_newfstatat ? 2 : 1];
        struct iovec local = {&st, sizeof(st)}, remote = {(void *)pointer, sizeof(st)};
        ssize_t n = process_vm_writev(op->notification.pid, &local, 1, &remote, 1, 0);
        if (n < 0 && (errno == EPERM || errno == EACCES)) return 0;
        if (n != sizeof(st)) response.error = -EFAULT;
    }
    return !ioctl(op->listener, SECCOMP_IOCTL_NOTIF_SEND, &response) || errno == ENOENT ? 1 : -errno;
}
int md_broker_task(struct md_namespace_broker *b, int pid, int eligible, uintptr_t raw_gate, uintptr_t watch_gate) {
    pthread_mutex_lock(&b->lock);
    struct task *t = b->tasks, *vacant = NULL;
    while (t && t->pid != pid) { if (!t->pid && !t->borrowed) vacant = t; t = t->next; }
    if (!t) {
        t = vacant;
        if (!t) { t = calloc(1, sizeof(*t)); if (t) { t->process = -1; t->next = b->tasks; b->tasks = t; } }
    }
    if (t) { t->pid = pid; t->eligible = eligible; t->gate = raw_gate; t->watch_gate = watch_gate; }
    pthread_mutex_unlock(&b->lock);
    return t ? 0 : -ENOMEM;
}
void md_broker_forget(struct md_namespace_broker *b, int pid) {
    if (!b) return;
    pthread_mutex_lock(&b->lock);
    for (struct task *t = b->tasks; t; t = t->next) if (t->pid == pid) {
        t->pid = 0;
        if (!t->borrowed && t->process >= 0) { close(t->process); t->process = -1; }
        break;
    }
    pthread_mutex_unlock(&b->lock);
    md_fs_worker_wake(b->worker);
}
static int perform(struct md_namespace_broker *b, struct operation *op, int prepared) {
    struct counters *count=b->counts && (unsigned)op->notification.data.nr<512
        ? &b->counts[op->notification.data.nr] : NULL;
    if (prepared>0 && !op->cursor.owner) {
        if (md_fd_order_state(&op->order)==MD_RESOURCE_ORDER_READY) {
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
    if (prepared) {
        if (prepared>0) execute(op,b->output,sizeof(b->output));
        else op->result.error=prepared;
        int result=reply(op,b->output);
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
    struct operation **at=&b->waiting;
    while (*at) {
        struct operation *op=*at;
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
    if (valid(op)) b->delegate(&op->notification);
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
    struct task *task = NULL;
    for (struct task *t = b->tasks; t; t = t->next) if (t->pid == (int)q.pid) {
        eligible = t->eligible && q.data.instruction_pointer != t->gate;
        watch = q.data.instruction_pointer == t->watch_gate;
        task = t; t->borrowed++; break;
    }
    if (watch) {
        pthread_mutex_unlock(&b->lock);
        int fd = duplicate(task, q.pid, (int)q.data.args[q.data.nr == SYS_sendfile ? 1 : 0]);
        pthread_mutex_lock(&b->lock);
        task->borrowed--;
        if (!task->pid && task->process >= 0) { close(task->process); task->process = -1; }
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
            if (task) task->borrowed--;
            pthread_mutex_unlock(&b->lock);
            return -ENOMEM;
        }
        op->all = b->all; b->all = op;
    }
    op->notification = q; op->listener = b->listener; op->directory = -1; op->undelivered = 0;
    op->owner=b; op->work.complete=complete;
    op->task=task;
    op->result = (struct md_fs_result){.fd = -1};
    int prepared = eligible ? prepare(fs, op, sizeof(b->output)) : 0;
    if (prepared>0) {
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
        fprintf(stderr, "MD_BROKER synchronousWake=%d\n", b->synchronous_wake);
        for (unsigned i = 0; i < 512; ++i) if (b->counts[i].received)
            fprintf(stderr, "MD_BROKER nr=%u notifications=%llu handled=%llu delegated=%llu\n", i,
                (unsigned long long)b->counts[i].received, (unsigned long long)b->counts[i].handled,
                (unsigned long long)b->counts[i].delegated);
        free(b->counts);
    }
    while (b->all) {
        struct operation *op = b->all; b->all = op->all;
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
        if (t->process >= 0) close(t->process);
        free(t);
    }
    md_resource_wakeup_release(b->wakeup);
    pthread_mutex_destroy(&b->lock); free(b);
}
