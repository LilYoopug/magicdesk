#define _GNU_SOURCE
#include "event_wait.h"
#include "fs_rpc.h"
#include "fs_worker.h"
#include "command_access.h"
#include "fs_mounts.h"
#include "namespace_broker.h"
#include "guest_domain.h"
#include "task_resources.h"
#include "fd_mutation.h"
#include "fd_exchange.h"
#include "fd_return.h"
#include "fd_install.h"
#include "fd_client.h"
#include "elf_admission.h"
#include "interception.h"
#include "interception_memory.h"
#include "task_helper.h"
#include "fs_buffer.h"
#include "adapter_frame.h"
#include "fs_buffer_service.h"
#include "watch_activation.h"
#include "launch_identity.h"
#include "sysv_shm.h"
#include "sysv_ipc.h"
#include <linux/memfd.h>
#include <sys/mman.h>
#include "task_registry.h"
#include "guest_user.h"
#include "guest_accounts.h"
#include "process_owner.h"
#include "raw.h"
#include "profile.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/close_range.h>
#include "linux_abi.h"
#include "task_descriptor.h"
#include <linux/seccomp.h>
#include <signal.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include "guest_debugger.h"
#include "process_image_view.h"
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include "launch_registry.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>

/* One supervisor owns one launched tree. It never attaches to Android tasks. */
static struct md_interception_abi abi;
#define READY abi.ready
#define DONE abi.done
#define ALLOCATE abi.allocate
#define ALLOCATED abi.allocated
#define DISPATCH abi.dispatch
#define EXPORT abi.export_fd
#define EXPORTED abi.exported
#define STORE abi.store
#define STORED abi.stored
#define LOAD_BYTE abi.load_byte
#define LOADED_BYTE abi.loaded_byte
#define STORE_IDS abi.store_ids
#define STORED_IDS abi.stored_ids
#define RAW_GATE abi.raw_gate
#define COPY_BEGIN abi.copy_begin
#define COPY_END abi.copy_end
static int diagnostics;
struct interception_statistics {
    uint64_t ptrace_requests, unknown, native_seeks, stops;
    struct md_cost rpc;
    struct { uint64_t trace, notification; } calls[512];
};
static struct interception_statistics *statistics;
#define TRACE(...) do { if (diagnostics) fprintf(stderr, __VA_ARGS__); } while (0)
enum phase { IDLE, ALLOCATING, DISPATCHING, EXECUTING, OBSERVING,
    EXPORT_CANCEL, EXPORTING, EXPORT_ENTRY, EXPORT_NOTIFY, EXPORT_RETURN, STORING,
    DELEGATE_CANCEL, LOADING_PATH, PROC_CANCEL, PROC_OPENING, STORING_IDS, DOMAIN_PATH,
    WATCH_CANCEL, WATCH_ENTRY, WATCH_READ, IPC_WAIT_ENTRY, IPC_WAITING,
    IDENTITY_COPY, DEBUG_WAIT_ENTRY, DEBUG_WAIT_EXIT, MEMORY_WAIT };
enum memory_action { MEMORY_NONE, MEMORY_KERNEL, MEMORY_DETACH, MEMORY_FORK };
struct metadata_operation {
    enum phase previous;
    struct seccomp_notif request;
    struct user_pt_regs saved, returned;
    uint64_t mask;
    int channel, error, descriptor;
    struct md_fd_channel *transport;
    struct md_fd_channel_capture capture;
    struct md_fd_order files;
    struct user_pt_regs control;
    int waiting, checking;
    int proc_attempted, proc_directory, proc_stat, task_open;
    size_t copied, output_size, path_size;
    uintptr_t output;
    char path[4096];
    struct stat value;
};
struct mapping_owner {
    pid_t caller, group;
    struct user_pt_regs continuation;
    struct md_shm_space *space;
    struct md_shm_mapping *pending;
    struct md_interception_memory *memory;
    struct md_resource_order order;
    struct md_task_mapping_request request;
    int started;
};
struct capture_owner {
    pid_t caller;
    struct md_fs_buffer_request *request;
};
struct probe_owner { pid_t caller; struct user_pt_regs continuation; };
struct send_owner { pid_t caller; struct md_fs_buffer_request *request; struct user_pt_regs continuation; };
struct receive_owner {
    pid_t caller;
    int started, ready;
    struct user_pt_regs continuation;
    struct md_task_receive request;
    struct md_fd_order files;
    struct md_received_fds received;
    int outgoing[253];
};
struct thread {
    struct thread *next;
    struct md_interception_memory *memory;
    struct md_interception_buffer buffer;
    struct md_fs_buffer_request *buffer_call;
    struct capture_owner *capture;
    struct probe_owner *probe;
    struct send_owner *send;
    struct receive_owner *receive;
    struct md_fs_buffer_open buffer_open;
    struct user_pt_regs buffer_registers;
    struct md_fd_install buffer_delivery, proc_delivery;
    int proc_image_fd;
    struct md_fd_return buffer_return;
    int buffer_return_waiting;
    int buffer_delivered;
    int buffer_waiting;
    struct md_watch_activation *watch_activation;
    pid_t pid, tgid, parent;
    int ready, born, initial_stop, resume_lost, listening, terminal_stop;
    enum phase phase;
    uint64_t stack, mask;
    struct user_pt_regs original;
    unsigned calls;
    char endpoint[108];
    int filter_length;
    struct metadata_operation metadata;
    struct md_task_resources resources;
    struct md_resource_change resource_change;
    struct md_fd_order fd_order;
    struct md_fs_order fs_order;
    struct md_fs_anchor *fd_origin;
    struct md_fd_mutation fd_mutation;
    struct user_pt_regs fd_registers;
    int fd_running, fd_cwd, fd_capture, fd_task;
    unsigned fd_job;
    struct md_fd_exchange *fd_exchange;
    unsigned long cloning;
    struct md_identity identity;
    struct md_exec_identity pending_identity;
    int exec_images[2];
    int exec_images_ready;
    int mapped_image, entered;
    int debug_step_call, debug_birth;
    pid_t debug_exec_old;
    int kernel_stopped, trace_options_dirty, debug_call_active, debug_adapter;
    int terminal_observation;
    unsigned long debug_options;
    uint64_t debug_wait_mask;
    struct rusage usage;
    uintptr_t process_image;
    int watch_wait;
    uint32_t *identity_buffer;
    unsigned identity_count, identity_copied;
    uintptr_t identity_address;
    int identity_loading, identity_stage, identity_result;
    struct md_shm_space *shm_space;
    struct mapping_owner *mapping;
    struct md_resource_order memory_order;
    enum memory_action memory_action;
    int shm_filter;
    struct md_ipc_pending *ipc_pending;
    struct md_ipc_transport ipc_transport;
    int ipc_cancel, ipc_waking;
    uint64_t ipc_event;
};
static struct thread *threads;
static struct md_debugger *debugger;
static pid_t leader;
static unsigned live, total, calls, images, signals, copy_faults, fstat_failures;
struct denial { unsigned nr, adapted, count; enum phase phase; };
static struct denial denials[64];
static int result, signal_fd, listener = -1;
static int fd_ready = -1;
static struct md_resource_wakeup *fd_wakeup;
static struct md_fd_exchanges *fd_exchanges;
static int cancelling;
static struct md_launch_registration registration = {.directory=-1, .record=-1};
static int64_t cancellation_deadline;
static unsigned external_stats, external_errors;
static unsigned protected_stats;
static unsigned retained_calls, retained_errors;
static unsigned root_changes, restricted_denials;
static unsigned group_stops, group_wakes, raced_wakes;
static const char *admitted_path;
static struct md_fs_worker *filesystem;
static struct md_fs_buffer_service *buffer_service;
static struct md_shm *shm;
static struct md_task_helpers *helpers;
static struct md_ipc *ipc;
static int ipc_events=-1;
static uint64_t ipc_sequence;
static const char *shm_store;
static struct md_namespace_broker *broker;
static struct md_task_registry *tasks;
static struct md_identity launch_identity;
static int virtual_identity;
static struct md_admission admission = {.source = -1};
static unsigned admitted_images, identity_changes;
static int registers(pid_t pid, struct user_pt_regs *out);
static int set_registers(pid_t pid, struct user_pt_regs *regs);
static void resume(pid_t pid, int sig);
static int shield(struct thread *t);
static int restore_mask(struct thread *t);
static void fd_discard(struct thread *t);
static void adapter_progress(void);
static void mapping_complete(void *, struct md_task_helper_result);
static void mapping_start(struct thread *);
static void memory_start(struct thread *);
static void dispatch(struct thread *t);
static void report_statistics(void);
static int debugger_allowed(pid_t, pid_t);
static void ipc_unwatch(struct thread *);
static const unsigned long trace_options = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACECLONE
    | PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD;
static void release_operation(struct thread *t);
static void exec_images_release(struct thread *t) {
    for (unsigned i=0;i<2;++i) {
        if (t->exec_images[i]>=0) close(t->exec_images[i]);
        t->exec_images[i]=-1;
    }
    t->exec_images_ready=0;
}
static void adapter_discard(struct thread *);
static int describe_filter(pid_t pid, const struct user_pt_regs *regs) {
    if (!diagnostics) return -1;
    if (!((regs->regs[8] == SYS_seccomp && regs->regs[0] == SECCOMP_SET_MODE_FILTER)
            || (regs->regs[8] == SYS_prctl && regs->regs[0] == PR_SET_SECCOMP))) return -1;
    struct sock_fprog program;
    struct iovec local = {&program, sizeof(program)}, remote = {(void *)regs->regs[2], sizeof(program)};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    TRACE("PROBE filter pid=%d instructions=%d readError=%d\n", pid,
        n == sizeof(program) ? program.len : -1, n < 0 ? errno : 0);
    return n == sizeof(program) ? program.len : -1;
}
static void describe_process(pid_t pid, uint64_t pc) {
    if (!diagnostics) return;
    const char *files[] = {"maps", "status"};
    for (unsigned i = 0; i < sizeof(files) / sizeof(*files); i++) {
        char path[64], line[1024];
        snprintf(path, sizeof(path), "/proc/%d/%s", pid, files[i]);
        FILE *file = fopen(path, "re");
        if (!file) { TRACE("PROBE %s error=%d\n", path, errno); continue; }
        unsigned count = 0;
        while (fgets(line, sizeof(line), file) && count++ < 4096) {
            unsigned long long begin = 0, end = 0;
            if (!i) sscanf(line, "%llx-%llx", &begin, &end);
            if (!i ? !pc || (pc >= begin && pc < end) :
                    !strncmp(line, "Seccomp", 7) || !strncmp(line, "NoNewPrivs", 10)
                    || !strncmp(line, "Uid:", 4) || !strncmp(line, "TracerPid:", 10))
                TRACE("PROBE %s %s", path, line);
        }
        fclose(file);
    }
}
static void cleanup(void) {
    report_statistics();
    for (struct thread *t = threads; t; t = t->next) if (t->pid) {
        kill(t->pid, SIGKILL); release_operation(t); adapter_discard(t);
    }
    /* EVENT_WAIT: reap owned tracees after cancellation; outer runner bounds
     * cleanup if the kernel cannot complete an exit. */
    for (;;) {
        int status;
        pid_t pid=waitpid(-1,&status,__WALL);
        if (pid<0) { if (errno==EINTR) continue; break; }
        if (md_fs_buffer_child(buffer_service,pid,status)) continue;
        /* SIGKILL may still publish TRACEEXIT. Reaping requires continuing
         * this owned terminal stop, not merely waiting for another event. */
        if (WIFSTOPPED(status)) {
            kill(pid,SIGKILL);
            ptrace(PTRACE_CONT,pid,NULL,NULL);
        }
    }
    md_task_helpers_destroy(helpers); helpers=NULL;
    while (threads) {
        struct thread *next = threads->next;
        exec_images_release(threads);
        fd_discard(threads);
        adapter_discard(threads);
        md_memory_release(threads->memory);
        md_watch_activation_release(threads->watch_activation);
        md_shm_space_release(shm,threads->shm_space);
        ipc_unwatch(threads);
        md_ipc_cancel(ipc,&threads->ipc_pending);
        md_ipc_transport_close(&threads->ipc_transport);
        md_resources_unshare_finish(ipc, &threads->resources, &threads->resource_change, -ECANCELED);
        md_resources_release(ipc, &threads->resources);
        md_identity_release(&threads->identity);
        free(threads->identity_buffer);
        free(threads); threads = next;
    }
    md_admission_close(&admission);
    md_debugger_destroy(debugger); debugger = NULL;
    md_shm_close(shm); shm = NULL;
    md_ipc_close(ipc); ipc = NULL;
    if (ipc_events>=0) close(ipc_events);
    ipc_events=-1;
    if (md_fs_worker_stop(filesystem)) _Exit(125);
    md_fs_buffer_service_destroy(buffer_service); buffer_service=NULL;
    filesystem = NULL;
    md_launch_unregister(&registration);
    md_broker_destroy(broker); broker = NULL;
    md_task_registry_destroy(tasks); tasks = NULL;
    md_fd_exchanges_destroy(fd_exchanges); fd_exchanges=NULL;
    md_identity_release(&launch_identity);
    if (listener >= 0) close(listener);
    if (fd_ready >= 0) close(fd_ready);
    md_resource_wakeup_release(fd_wakeup); fd_wakeup=NULL;
    free(statistics);
}
_Noreturn static void fail(const char *what, int line) {
    fprintf(stderr, "guest-runtime: supervisor failure line=%d %s errno=%d\n", line, what, errno);
    exit(125);
}
#define CHECK(x) do { if (!(x)) fail(#x, __LINE__); } while (0)
static void release_operation(struct thread *t) {
    struct metadata_operation *op=&t->metadata;
    md_fd_channel_capture_cancel(&op->capture);
    md_fd_channel_release(op->transport); op->transport=NULL;
    if (op->descriptor>=0) { close(op->descriptor); op->descriptor=-1; }
    if (op->files.table && md_fd_order_cancel(&op->files)==1)
        CHECK(!md_fd_order_complete(&op->files));
    op->waiting=op->checking=0;
}
static void adapter_discard(struct thread *t) {
    if (t->send) {
        t->send->caller=0; t->send->request=NULL; t->send=NULL;
        CHECK(!md_task_helper_detach(helpers,t->pid));
    }
    if (t->probe) {
        t->probe->caller=0; t->probe=NULL;
        CHECK(!md_task_helper_detach(helpers,t->pid));
    }
    if (t->mapping) {
        struct mapping_owner *owner=t->mapping;
        owner->caller=0; t->mapping=NULL;
        if (owner->started) CHECK(!md_task_helper_detach(helpers,t->pid));
        else mapping_complete(owner,(struct md_task_helper_result){.value=-ECANCELED,.descriptor=-1});
    }
    if (t->memory_order.queue && md_resource_order_cancel(&t->memory_order)==1)
        CHECK(!md_resource_order_complete(&t->memory_order));
    t->memory_action=0;
    CHECK(!md_fd_return_cancel(&t->buffer_return));
    if (t->receive) {
        struct receive_owner *owner=t->receive; t->receive=NULL; owner->caller=0;
        if (owner->started && !owner->ready) CHECK(!md_task_helper_detach(helpers,t->pid));
        else {
            if (owner->files.table && md_fd_order_cancel(&owner->files)==1)
                CHECK(!md_fd_order_complete(&owner->files));
            md_received_fds_close(&owner->received); free(owner);
        }
    }
    t->buffer_return_waiting=0;
    CHECK(!md_fd_install_cancel(&t->buffer_delivery));
    CHECK(!md_fd_install_cancel(&t->proc_delivery));
    if (t->proc_image_fd>=0) { close(t->proc_image_fd); t->proc_image_fd=-1; }
    md_fs_buffer_cancel(&t->buffer_call);
    if (t->capture) {
        t->capture->caller=0; t->capture=NULL;
        CHECK(!md_task_helper_detach(helpers,t->pid));
    }
    md_fs_buffer_open_release(&t->buffer_open);
    md_ipc_transport_close(&t->ipc_transport);
    CHECK(!md_buffer_release(&t->buffer));
    t->buffer_waiting=0;
    t->buffer_delivered=0;
}
static long native_trace(int request, pid_t pid, void *address, void *data) {
    if (statistics) statistics->ptrace_requests++;
    return ptrace(request, pid, address, data);
}
static int tracee_request(struct thread *t, int request, void *address, void *data, const char *operation) {
    if (t->resume_lost) return 0;
    if (!native_trace(request, t->pid, address, data)) return 1;
    CHECK(errno == ESRCH);
    /* EVENT_WAIT: concurrent group death/exec may invalidate a reported stop.
     * Keep ownership until its exact exit/exec event; the tree deadline bounds
     * missing events. Never substitute registers, mask or a successful resume. */
    TRACE("PROBE lost-stop pid=%d phase=%d operation=%s\n", t->pid, t->phase, operation);
    t->resume_lost = 1; return 0;
}
static struct thread *find_thread(pid_t pid) {
    for (struct thread *t = threads; t; t = t->next) if (t->pid == pid) return t;
    return NULL;
}
static struct thread *thread(pid_t pid) {
    struct thread *t = find_thread(pid);
    if (t) return t;
    for (t = threads; t && t->pid; t = t->next) { }
    if (!t) { t = calloc(1, sizeof(*t)); CHECK(t); t->next = threads; threads = t; }
    *t = (struct thread){.pid = pid, .tgid = pid, .next = t->next,
        .metadata = {.channel = -1, .descriptor = -1},
        .identity = md_identity_copy(&launch_identity), .memory = md_memory_new(),
        .shm_space = md_shm_space_new(),
        .buffer_open = {.fd=-1}, .proc_image_fd=-1,
        .exec_images = {-1,-1},
        .watch_activation = md_watch_activation_new()};
    CHECK(t->memory && t->watch_activation && t->shm_space);
    live++; total++; return t;
}
static void release_thread(struct thread *t) {
    int buffered=t->buffer.pool || t->buffer_call || t->buffer_waiting;
    fd_discard(t);
    adapter_discard(t);
    exec_images_release(t);
    md_task_registry_forget(tasks, t->pid);
    md_identity_release(&t->identity);
    CHECK(!md_shm_space_release(shm,t->shm_space)); t->shm_space = NULL;
    ipc_unwatch(t);
    CHECK(!md_ipc_cancel(ipc,&t->ipc_pending));
    md_ipc_transport_close(&t->ipc_transport);
    CHECK(!md_resources_unshare_finish(ipc, &t->resources, &t->resource_change, -ECANCELED));
    CHECK(!md_resources_release(ipc, &t->resources));
    free(t->identity_buffer); t->identity_buffer = NULL;
    md_broker_forget(broker, t->pid);
    release_operation(t);
    md_memory_stack_return(t->memory, t->stack);
    md_memory_release(t->memory); t->memory = NULL;
    md_watch_activation_release(t->watch_activation); t->watch_activation = NULL;
    t->pid = 0; live--;
    if (buffered) adapter_progress();
}
static int duplicate_fd(pid_t pid, int descriptor) {
    /* Never substitute a group's leader for another thread's descriptor table.
     * Older kernels can duplicate a leader's descriptors; other threads use
     * their task-affine SCM_RIGHTS continuation instead. */
    int process=-1;
    int fd=md_task_descriptor_copy(pid,descriptor,&process);
    if (process>=0) close(process);
    return fd;
}
static int read_string(pid_t pid, uintptr_t address, char *text, size_t capacity) {
    for (size_t i = 0; i < capacity; i++) {
        if (address > UINTPTR_MAX - i) return -EFAULT;
        struct iovec local = {text + i, 1}, remote = {(void *)(address + i), 1};
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n != 1) return n < 0 ? -errno : -EFAULT;
        if (!text[i]) return 0;
    }
    return -ENAMETOOLONG;
}
static int descriptor_stat(struct thread *t, int fd, struct stat *st, int native) {
    /* Internal loader validation inspects the actual descriptor. Only the guest
     * ABI receives catalogue ownership/mode; logical set-ID cannot authorize a
     * host ELF or bypass the production loader's set-ID rejection. */
    if (native || !t->endpoint[0]) return fstat(fd, st) ? -errno : 0;
    struct md_fs_request request = {.actor = t->pid, .operation = MD_FS_FSTAT, .directory = {fd, -1}};
    struct md_fs_response response;
    int64_t begin = md_cost_begin(statistics ? &statistics->rpc : NULL);
    int error = md_fs_call(t->endpoint, 5000, &request, &response);
    md_cost_end(statistics ? &statistics->rpc : NULL, begin);
    if (!error) error = response.result.error;
    if (!error || error == -EXDEV) {
        if (fstat(fd, st)) error = -errno;
        else if (!error) {
            st->st_dev = response.result.info.device; st->st_ino = response.result.info.inode;
            st->st_nlink = response.result.info.links; st->st_mode = response.result.info.mode;
            st->st_uid = response.result.info.uid; st->st_gid = response.result.info.gid;
            st->st_rdev = response.result.info.rdev; st->st_size = response.result.info.size;
            st->st_blocks = response.result.info.blocks; st->st_blksize = response.result.info.block_size;
            st->st_atim = (struct timespec){response.result.info.access_seconds, response.result.info.access_nanos};
            st->st_mtim = (struct timespec){response.result.info.modify_seconds, response.result.info.modify_nanos};
            st->st_ctim = (struct timespec){response.result.info.change_seconds, response.result.info.change_nanos};
        }
        else error = 0;
    }
    return error;
}
static void export_begin(struct thread *t, const struct seccomp_notif *q) {
    CHECK(t->phase == IDLE || t->phase == DISPATCHING);
    t->metadata = (struct metadata_operation){.previous = t->phase, .request = *q,
        .channel = -1, .descriptor = -1,
        .output_size = q->data.nr == SYS_openat ? 0 : sizeof(struct stat),
        .output = q->data.args[q->data.nr == SYS_newfstatat ? 2 : 1]};
    t->phase = EXPORT_CANCEL;
    tracee_request(t, PTRACE_INTERRUPT, NULL, NULL, "interrupt-notification");
}
static void export_start(struct thread *t) {
    struct metadata_operation *op = &t->metadata;
    errno = 0;
    CHECK(ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &op->request.id) == -1 && errno == ENOENT);
    if (!registers(t->pid, &op->saved)) return;
    op->saved.pc = op->request.data.instruction_pointer;
    op->saved.regs[8] = op->request.data.nr;
    for (unsigned i = 0; i < 6; i++) op->saved.regs[i] = op->request.data.args[i];
    if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(op->mask), &op->mask, "get-mask")
            || !shield(t)) return;
    struct user_pt_regs regs = op->saved;
    regs.pc = EXPORT; regs.regs[30] = EXPORTED;
    regs.regs[0] = op->request.data.args[0];
    if (!set_registers(t->pid, &regs)) return;
    t->phase = EXPORTING; resume(t->pid, 0);
}
static void replay(struct thread *t) {
    struct metadata_operation *op = &t->metadata;
    /* Reenter the original SVC: kernel admission, including any newer application
     * filter, precedes resource access, descriptor injection and output copying. */
    struct user_pt_regs regs = op->saved; regs.pc -= 4;
    if (!set_registers(t->pid, &regs)) return;
    t->phase = EXPORT_ENTRY; resume(t->pid, 0);
}
static void load_path(struct thread *t) {
    struct metadata_operation *op = &t->metadata;
    if (op->path_size == sizeof(op->path)) op->error = -ENAMETOOLONG;
    if (op->request.data.args[1] > UINTPTR_MAX - op->path_size) op->error = -EFAULT;
    if (op->error) { replay(t); return; }
    struct user_pt_regs regs = op->saved;
    regs.pc = LOAD_BYTE; regs.regs[0] = op->request.data.args[1] + op->path_size;
    if (!set_registers(t->pid, &regs)) return;
    t->phase = LOADING_PATH; resume(t->pid, 0);
}
static void export_reply(struct thread *t, long endpoint, uint64_t token) {
    struct user_pt_regs regs=t->metadata.control;
    regs.pc+=4; regs.regs[0]=endpoint; regs.regs[1]=token;
    t->metadata.waiting=0;
    if (set_registers(t->pid,&regs)) resume(t->pid,0);
}
static void export_progress(struct thread *t) {
    struct metadata_operation *op=&t->metadata;
    if (!op->waiting) return;
    if (md_fd_order_state(&op->files)==MD_RESOURCE_ORDER_READY)
        CHECK(!md_fd_order_start(&op->files));
    if (md_fd_order_state(&op->files)!=MD_RESOURCE_ORDER_RUNNING) return;
    int error=0;
    if (!op->transport) {
        error=md_fd_origins_channel(op->files.table,&op->channel,&op->transport);
        if (error==-ESTALE) {
            error=md_fd_origins_channel_candidate(op->files.table,&op->channel,&op->transport);
            if (!error) op->checking=1;
        }
        if (!error && !op->transport) error=md_fd_channel_new(&op->transport);
    }
    if (error) { export_reply(t,error,0); return; }
    if (op->checking) { export_reply(t,op->channel,0); return; }
    if (!op->capture.channel)
        error=md_fd_channel_capture_begin(op->transport,t->tgid,1,&op->capture);
    export_reply(t,error ? error : op->channel<0 ? MD_EXPORT_ADMIT : op->channel,
        error || op->channel<0 ? 0 : op->capture.request);
}
static void export_control(struct thread *t, const struct user_pt_regs *regs) {
    struct metadata_operation *op=&t->metadata;
    op->control=*regs;
    int error=-EINVAL;
    if ((t->phase==EXPORTING || t->phase==PROC_OPENING) && !op->waiting) {
        if ((regs->regs[0]==MD_EXPORT_BEGIN || regs->regs[0]==MD_EXPORT_READY)
                && !regs->regs[1] && !regs->regs[2] && !regs->regs[3] && !regs->regs[4]
                && !op->checking) {
            error=0;
            if (!op->files.table) error=md_fd_order_begin(t->resources.files,&op->files,fd_wakeup);
        } else if (regs->regs[0]==MD_EXPORT_OBSERVED && op->checking
                && md_fd_order_state(&op->files)==MD_RESOURCE_ORDER_RUNNING) {
            struct md_fd_channel_observation observation={.cookie=regs->regs[1],
                .flags=regs->regs[2],.length=regs->regs[3],.error=regs->regs[4]};
            error=md_fd_channel_resolve(op->transport,op->files.table,op->channel,&observation);
            if (!error) {
                md_fd_channel_release(op->transport); op->transport=NULL;
                op->channel=-1; op->checking=0;
            }
        }
    }
    if (error<0) { export_reply(t,error,0); return; }
    op->waiting=1;
    /* EVENT_WAIT: exact file-table turn. No mapped slot is held or needed;
     * terminal task cleanup cancels the lease and drains only its rights. */
    export_progress(t);
}
static void store_next(struct thread *t);
static void export_finish(struct thread *t) {
    struct metadata_operation *op = &t->metadata;
    struct user_pt_regs regs;
    if (!registers(t->pid, &regs)) return;
    long sent = (long)regs.regs[0];
    if (op->task_open) {
        /* Same-site admission preceded this fixed-path call. Its descriptor
         * is the application's result, never a temporary adapter handle. */
        op->returned=op->saved; op->returned.regs[0]=sent;
        if (sent>=0) CHECK(!md_fd_origins_close_range(op->files.table,sent,sent,0));
        else op->error=(int)sent;
        store_next(t); return;
    }
    op->error = sent < 0 ? (int)sent : sent == sizeof(uint64_t) ? 0 : -EIO;
    struct md_fd_channel_input input={0};
    int error=md_fd_channel_capture_finish(&op->capture,&input);
    if (!op->error) op->error=error;
    if (!op->error) {
        int fd=input.fd[0]; input.count=0;
        if (t->phase == PROC_OPENING) {
            op->error = descriptor_stat(t, fd, &op->value, 0); close(fd);
        } else op->descriptor = fd;
        if (!op->error && op->request.data.nr == SYS_fstat)
            op->error = descriptor_stat(t, op->descriptor, &op->value,
                op->request.data.instruction_pointer == RAW_GATE);
    }
    if (t->phase == PROC_OPENING && op->proc_stat && op->error == -EBADF) op->error = -ENOENT;
    md_fd_channel_input_close(&input);
    if (op->request.data.nr == SYS_fstat || t->phase == PROC_OPENING) replay(t); else load_path(t);
}
static void store_next(struct thread *t) {
    struct metadata_operation *op = &t->metadata;
    if (op->error || op->copied == op->output_size) {
        struct user_pt_regs regs = op->returned;
        if (op->error) regs.regs[0] = (uint64_t)(long)op->error;
        if (!set_registers(t->pid, &regs)
                || !tracee_request(t, PTRACE_SETSIGMASK, (void *)sizeof(op->mask), &op->mask, "restore-mask")) return;
        release_operation(t);
        t->phase = op->previous; protected_stats++; resume(t->pid, 0); return;
    }
    _Static_assert(sizeof(struct stat) % 16 == 0, "register output blocks");
    struct user_pt_regs regs = op->returned;
    regs.pc = STORE; regs.regs[0] = op->output + op->copied;
    memcpy(&regs.regs[2], (const char *)&op->value + op->copied, 16);
    if (!set_registers(t->pid, &regs)) return;
    t->phase = STORING; resume(t->pid, 0);
}
static void proc_query_begin(struct thread *t, const struct seccomp_notif *q, int target) {
    struct metadata_operation *op = &t->metadata;
    op->proc_stat=target>=0; op->task_open=target<0;
    op->proc_directory=target>=0 ? target : (int)q->data.args[0];
    op->request = *q; op->proc_attempted = 1; op->error = 0;
    t->phase = PROC_CANCEL; tracee_request(t, PTRACE_INTERRUPT, NULL, NULL, "interrupt-proc-query");
}
static void proc_query_start(struct thread *t) {
    struct metadata_operation *op = &t->metadata;
    CHECK(ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &op->request.id) == -1 && errno == ENOENT);
    struct user_pt_regs regs = op->saved;
    regs.pc = op->task_open ? abi.proc_open : EXPORT; regs.regs[30] = EXPORTED;
    regs.regs[0] = op->proc_directory;
    if (!set_registers(t->pid, &regs)) return;
    t->phase = PROC_OPENING; resume(t->pid, 0);
}
static void retained_result(struct thread *t, const struct seccomp_notif *q) {
    struct metadata_operation *op = &t->metadata;
    int fd = -1;
    if (!op->error && !(op->proc_attempted && op->proc_stat)) {
        int flags = q->data.nr == SYS_openat ? (int)q->data.args[2] : O_PATH;
        if (q->data.nr == SYS_newfstatat) {
            if (q->data.args[3] & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)) op->error = -ENOTSUP;
            if (q->data.args[3] & AT_SYMLINK_NOFOLLOW) flags |= O_NOFOLLOW;
        }
        if (!op->error) {
            fd = md_domain_open_retained(op->descriptor, t->pid, op->path, flags);
        }
        if (fd == -EACCES && !op->proc_attempted && q->data.nr == SYS_openat
                && md_domain_proc_fd_query(op->descriptor, op->path, flags)) {
            proc_query_begin(t,q,-1); return;
        }
        if ((fd == -EACCES || fd == -ELOOP) && !op->proc_attempted
                && q->data.nr == SYS_newfstatat && !q->data.args[3]) {
            int target = md_domain_proc_fd_number(op->descriptor, t->pid, op->path);
            if (target >= 0) { proc_query_begin(t, q, target); return; }
        }
        if (fd < 0 && !op->error) op->error = fd;
        if (!op->error && q->data.nr == SYS_newfstatat && fstat(fd, &op->value)) op->error = -errno;
    }
    retained_calls++;
    if (op->error) retained_errors++;
    TRACE("PROBE retained pid=%d nr=%d fd=%llu path=%s result=%d\n",
        t->pid, q->data.nr, q->data.args[0], op->path, op->error);
    if (!op->error && q->data.nr == SYS_openat) {
        struct seccomp_notif_addfd add = {.id = q->id, .srcfd = fd,
            .newfd_flags = (unsigned)q->data.args[2] & O_CLOEXEC,
            .flags = SECCOMP_ADDFD_FLAG_SEND};
        int result = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
        if (result < 0) op->error = -errno;
        else { close(fd); t->phase = EXPORT_RETURN; return; }
    }
    if (fd >= 0) close(fd);
    struct seccomp_notif_resp reply = {.id = q->id, .error = op->error};
    CHECK(!ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply) || errno == ENOENT);
    t->phase = EXPORT_RETURN;
}
static void image_request(struct thread *t, const struct seccomp_notif *q) {
    struct seccomp_notif_resp reply = {.id = q->id};
    if (q->data.instruction_pointer != RAW_GATE || t->phase != IDLE) reply.error = -EPERM;
    else if (q->data.args[0] == MD_GUEST_MAP_IMAGE) {
        if (q->data.args[2]==MD_IMAGE_TAKE_PROGRAM || q->data.args[2]==MD_IMAGE_TAKE_LOADER) {
            unsigned index=q->data.args[2]-MD_IMAGE_TAKE_PROGRAM;
            if (t->entered || !t->exec_images_ready || q->data.args[1]
                    || q->data.args[3] || q->data.args[4] || q->data.args[5]
                    || t->exec_images[index]<0) reply.error=-EPERM;
            else {
                struct seccomp_notif_addfd add={.id=q->id,.flags=SECCOMP_ADDFD_FLAG_SEND,
                    .srcfd=t->exec_images[index],.newfd_flags=O_CLOEXEC};
                int fd=ioctl(listener,SECCOMP_IOCTL_NOTIF_ADDFD,&add);
                if (fd>=0) { close(t->exec_images[index]); t->exec_images[index]=-1; return; }
                reply.error=-errno;
            }
        } else if (t->entered || q->data.args[2] > 1) reply.error = -EPERM;
        else if (!q->data.args[2]) {
            int fd = admitted_path ? duplicate_fd(t->pid, (int)q->data.args[1]) : -1;
            int matched = !admitted_path ? 0 : fd >= 0 ? md_admission_match(&admission, t->endpoint, fd) : fd;
            if (fd >= 0) close(fd);
            if (matched < 0) reply.error = matched;
            else {
                struct md_exec_identity next = {.value = t->identity};
                next.value.uid.saved = next.value.uid.fs = next.value.uid.effective;
                next.value.gid.saved = next.value.gid.fs = next.value.gid.effective;
                next.secure = next.value.uid.real != next.value.uid.effective
                    || next.value.gid.real != next.value.gid.effective;
                if (matched) reply.error = md_identity_prepare_exec(&t->identity, admission.image,
                    md_debugger_traced(debugger,t->pid), &next);
                else md_identity_exec(&t->identity, &next.value);
                if (!reply.error && matched) {
                    fd = md_exec_image_dup(admission.image);
                    if (fd < 0) reply.error = fd;
                    else {
                        struct seccomp_notif_addfd add = {.id = q->id, .srcfd = fd,
                            .newfd = q->data.args[1], .newfd_flags = O_CLOEXEC,
                            .flags = SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND};
                        int sent = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
                        int error = errno; close(fd);
                        if (sent >= 0) {
                            t->pending_identity = next; t->mapped_image = 1; admitted_images++;
                            TRACE("PROBE admitted-image pid=%d fd=%d euid=%u secure=%d\n",
                                t->pid, sent, next.value.uid.effective, next.secure);
                            return;
                        }
                        if (error == ENOENT) return;
                        reply.error = -error;
                    }
                }
                if (!reply.error) { t->pending_identity = next; t->mapped_image = 1; }
            }
        }
    } else if (q->data.args[0] == MD_GUEST_ENTER_IMAGE) {
        if (!t->ready || t->entered || q->data.args[2] > 128) reply.error = -EPERM;
        else if (t->mapped_image) {
            size_t count = q->data.args[2];
            Elf64_auxv_t aux[128];
            struct iovec local = {aux, count * sizeof(*aux)}, remote = {(void *)q->data.args[1], local.iov_len};
            if (process_vm_readv(t->pid, &local, 1, &remote, 1, 0) != (ssize_t)local.iov_len) reply.error = -EFAULT;
            unsigned found = 0;
            const struct md_exec_identity *next = &t->pending_identity;
            for (size_t i = 0; !reply.error && i < count; i++) {
                switch (aux[i].a_type) {
                case AT_UID: aux[i].a_un.a_val = next->value.uid.real; found |= 1; break;
                case AT_EUID: aux[i].a_un.a_val = next->value.uid.effective; found |= 2; break;
                case AT_GID: aux[i].a_un.a_val = next->value.gid.real; found |= 4; break;
                case AT_EGID: aux[i].a_un.a_val = next->value.gid.effective; found |= 8; break;
                case AT_SECURE: aux[i].a_un.a_val = next->secure; found |= 16; break;
                }
            }
            if (!reply.error && found != 31) reply.error = -EPROTO;
            if (!reply.error && process_vm_writev(t->pid, &local, 1, &remote, 1, 0) != (ssize_t)local.iov_len)
                reply.error = -EFAULT;
            if (!reply.error) {
                reply.val = next->secure;
                CHECK(!md_task_registry_publish(tasks, t->pid, t->tgid, &next->value, &t->resources));
                if (!ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply)) {
                    t->identity = next->value; t->mapped_image = 0; t->entered = 1;
                    TRACE("PROBE entered-image pid=%d uid=%u euid=%u secure=%d\n", t->pid,
                        t->identity.uid.real, t->identity.uid.effective, next->secure);
                    if (diagnostics) {
                        struct md_fs_location root;
                        struct md_fs_anchor *cwd=NULL;
                        md_domain_paths(t->resources.fs,&root,&cwd);
                        TRACE("PROBE image-cwd pid=%d known=%d\n",t->pid,cwd!=NULL);
                        md_fs_anchor_release(cwd);
                    }
                } else {
                    CHECK(errno == ENOENT);
                    CHECK(!md_task_registry_publish(tasks, t->pid, t->tgid, &t->identity, &t->resources));
                }
                return;
            }
        }
    } else reply.error = -EPROTO;
    CHECK(!ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply) || errno == ENOENT);
}
static void shm_request(struct thread *t, const struct seccomp_notif *q) {
    struct seccomp_notif_resp reply = {.id=q->id};
    int r = !shm_store ? -ENOTSUP : !shm ? md_shm_open(shm_store,&shm) : 0;
    if (!r && (t->phase != DISPATCHING || q->data.instruction_pointer != RAW_GATE)) r = -EPERM;
    unsigned op = q->data.args[1];
    if (op==MD_SHM_STAT || op==MD_SHM_OPEN || op==MD_SHM_ATTACHED || op==MD_SHM_ABORT) r=-EINVAL;
    unsigned long a[4] = {q->data.args[2],q->data.args[3],q->data.args[4],q->data.args[5]};
    struct shmid64_ds info;
    long value = r ? r : md_shm_call(shm,t->shm_space,NULL,&t->identity,t->tgid,op,a,&info);
    if (value < 0) reply.error = (int)value;
    else reply.val = value;
    CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno == ENOENT);
}
static void ipc_request(struct thread *t, const struct seccomp_notif *q) {
    struct seccomp_notif_resp reply={.id=q->id};
    struct md_ipc_request call={.nr=t->original.regs[8]};
    for (unsigned i=0;i<6;i++) call.args[i]=t->original.regs[i];
    int r=t->phase!=DISPATCHING || q->data.instruction_pointer!=RAW_GATE ? -EPERM : 0;
    if (!r && (call.nr!=SYS_semget && call.nr!=SYS_semctl
            && call.nr!=SYS_semop && call.nr!=SYS_semtimedop && call.nr!=SYS_msgget
            && call.nr!=SYS_msgctl && call.nr!=SYS_msgsnd && call.nr!=SYS_msgrcv)) r=-EINVAL;
    if (!r) r=!shm_store ? -ENOTSUP : !ipc ? md_ipc_open(shm_store,&ipc) : 0;
    long value=r;
    struct md_ipc_transport *channel=&t->ipc_transport;
    if (!r && q->data.args[1]==MD_IPC_CLOSE) {
        md_ipc_transport_close(channel);
        if (q->data.args[2]) {
            value=md_ipc_cancel(ipc,&t->ipc_pending); t->ipc_cancel=0;
        }
    } else if (!r && q->data.args[1]==MD_IPC_EXECUTE && channel->packet) {
        if (t->ipc_cancel) {
            value=t->ipc_cancel; t->ipc_cancel=0;
            int error=md_ipc_cancel(ipc,&t->ipc_pending); if (error) value=error;
        } else value=md_ipc_call(ipc,&t->ipc_pending,t->resources.sem_undo,&t->identity,t->pid,t->tgid,channel);
    } else if (!r) value=-EINVAL;
    if (value==MD_IPC_WAIT) reply.val=value;
    else if (value<0) reply.error=value;
    else reply.val=value;
    CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
}
static void ipc_unwatch(struct thread *t) {
    if (t->ipc_event) {
        CHECK(!epoll_ctl(ipc_events,EPOLL_CTL_DEL,md_ipc_wait_fd(t->ipc_pending),NULL)
            || errno==ENOENT);
        t->ipc_event=0;
    }
}
static int ipc_watch(struct thread *t) {
    if (t->ipc_event || !t->ipc_pending) return -EINVAL;
    if (ipc_sequence==UINT64_MAX) return -EOVERFLOW;
    if (ipc_events<0) {
        ipc_events=epoll_create1(EPOLL_CLOEXEC);
        if (ipc_events<0) return -errno;
    }
    struct epoll_event event={.events=EPOLLIN|EPOLLONESHOT,.data.u64=++ipc_sequence};
    if (epoll_ctl(ipc_events,EPOLL_CTL_ADD,md_ipc_wait_fd(t->ipc_pending),&event)) return -errno;
    t->ipc_event=event.data.u64; return 0;
}
static void ipc_events_ready(void) {
    struct epoll_event events[16];
    int count;
    do count=epoll_wait(ipc_events,events,16,0); while (count<0 && errno==EINTR);
    CHECK(count>=0);
    for (int i=0;i<count;++i) {
        struct thread *t=threads;
        while (t && (!t->pid || t->ipc_event!=events[i].data.u64)) t=t->next;
        if (!t) continue;
        CHECK(t->phase==IPC_WAITING);
        ipc_unwatch(t); t->ipc_waking=1;
        /* EVENT_WAIT: the task's interruptible empty poll is cancelled by an
         * exact watcher event. No guest FD or synthetic application signal. */
        if (!t->listening) tracee_request(t,PTRACE_INTERRUPT,NULL,NULL,"ipc-ready");
    }
}
static void delegate_begin(struct thread *t, const struct seccomp_notif *q) {
    CHECK(t->phase == IDLE);
    t->metadata = (struct metadata_operation){.request = *q, .descriptor = -1, .channel = -1};
    t->phase = DELEGATE_CANCEL;
    tracee_request(t, PTRACE_INTERRUPT, NULL, NULL, "interrupt-delegation");
}
static void buffer_setup(struct thread *t, const struct seccomp_notif *q) {
    size_t page=(size_t)getpagesize();
    size_t size=(sizeof(union md_adapter_frame)+page-1)/page*page*MD_ADAPTER_BUFFER_SLOTS;
    struct seccomp_notif_resp reply={.id=q->id};
    if (!t->ready || t->entered || t->phase!=IDLE
            || q->data.instruction_pointer!=RAW_GATE || q->data.args[1]!=size
            || q->data.args[2] || q->data.args[3] || q->data.args[4] || q->data.args[5]) reply.error=-EPERM;
    else reply.error=md_memory_buffers_prepare(t->memory,MD_ADAPTER_BUFFER_SLOTS,sizeof(union md_adapter_frame),
        offsetof(struct md_fs_buffer_frame,value));
    if (!reply.error) {
        struct seccomp_notif_addfd add={.id=q->id,.flags=SECCOMP_ADDFD_FLAG_SEND,
            .srcfd=md_buffers_fd(md_memory_buffers(t->memory)),.newfd_flags=O_CLOEXEC};
        if (ioctl(listener,SECCOMP_IOCTL_NOTIF_ADDFD,&add)>=0) return;
        reply.error=-errno;
    }
    CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
}
static void buffer_deliver(struct thread *t) {
    if (!t->buffer_delivery.files.table) return;
    int installed=md_fd_install_progress(&t->buffer_delivery);
    if (installed==MD_FD_INSTALL_WAIT) return;
    CHECK(!t->buffer_delivery.retire_error);
    t->buffer_delivered=1;
    if (installed<0) {
        struct seccomp_notif_resp reply={.id=t->buffer_delivery.notification,.error=installed};
        CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
    }
}
static void proc_deliver(struct thread *t) {
    if (!t->proc_delivery.files.table) return;
    int installed=md_fd_install_progress(&t->proc_delivery);
    if (installed==MD_FD_INSTALL_WAIT) return;
    CHECK(!t->proc_delivery.retire_error);
    close(t->proc_image_fd); t->proc_image_fd=-1;
    if (installed<0) {
        struct seccomp_notif_resp reply={.id=t->proc_delivery.notification,.error=installed};
        CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
    }
}
static void buffer_receive(struct thread *t, const struct seccomp_notif *q) {
    int error=0;
    if (!t->ready || q->data.instruction_pointer!=RAW_GATE
            || q->data.args[1] || q->data.args[2] || q->data.args[3] || q->data.args[4] || q->data.args[5]
            || !t->buffer.pool || t->buffer_call || t->buffer_open.fd<0 || t->buffer_open.task_path
            || t->buffer_delivery.files.table || t->buffer_delivered) error=-EPERM;
    else {
        error=md_fd_install_begin(&t->buffer_delivery,t->resources.files,listener,q->id,
            t->buffer_open.fd,t->buffer_open.origin,t->buffer_open.flags&O_CLOEXEC,fd_wakeup);
        if (!error) {
            /* EVENT_WAIT: the destination file table's preceding mutation.
             * Task cancellation retires this record before descriptor delivery. */
            buffer_deliver(t); return;
        }
    }
    struct seccomp_notif_resp reply={.id=q->id,.error=error};
    CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
}
static void handle_notification(const struct seccomp_notif *request) {
    int mapped=md_task_helper_notification(helpers,listener,request);
    if (mapped<0) errno=-mapped;
    CHECK(mapped>=0);
    if (mapped) return;
    struct seccomp_notif q = *request;
    CHECK(q.data.nr == SYS_fstat || q.data.nr == SYS_openat || q.data.nr == SYS_newfstatat
        || q.data.nr == SYS_getdents64 || q.data.nr == SYS_prctl);
    struct thread *t = find_thread((pid_t)q.pid);
    CHECK(t && t->born);
    if (q.data.nr == SYS_prctl) {
        if (q.data.args[0] == MD_GUEST_PROC_IMAGE) {
            struct seccomp_notif_resp reply={.id=q.id};
            struct thread *target=find_thread((pid_t)q.data.args[1]);
            int fd=!target || !debugger_allowed(t->pid,target->pid) ? -EACCES
                : q.data.instruction_pointer!=RAW_GATE || t->phase!=DISPATCHING
                    || t->proc_image_fd>=0 || q.data.args[4] || q.data.args[5] ? -EPERM
                : md_process_image_view(target->pid,target->process_image,(unsigned)q.data.args[2],
                    (unsigned)q.data.args[3],t->endpoint,t->pid);
            if (fd<0) reply.error=fd;
            else {
                reply.error=md_fd_install_begin(&t->proc_delivery,t->resources.files,listener,q.id,
                    fd,NULL,(unsigned)q.data.args[3]&O_CLOEXEC,fd_wakeup);
                if (!reply.error) {
                    t->proc_image_fd=fd;
                    /* EVENT_WAIT: destination table ownership; cancellation
                     * closes only the retained provider FD, never a guest slot. */
                    proc_deliver(t); return;
                }
                close(fd);
            }
            CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
        } else if (q.data.args[0] == MD_GUEST_FD_CHANNEL) {
            struct metadata_operation *op=&t->metadata;
            int value=-EPERM;
            if (q.data.instruction_pointer==RAW_GATE
                    && (t->phase==EXPORTING || t->phase==PROC_OPENING)
                    && op->transport && op->capture.channel && op->channel<0 && !op->checking
                    && md_fd_order_state(&op->files)==MD_RESOURCE_ORDER_RUNNING
                    && !q.data.args[1] && !q.data.args[2] && !q.data.args[3]
                    && !q.data.args[4] && !q.data.args[5]) {
                value=md_fd_channel_admit(op->transport,op->files.table,listener,q.id);
                if (value>=0) { op->channel=value; return; }
            }
            struct seccomp_notif_resp reply={.id=q.id,.error=value};
            CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
        } else if (q.data.args[0] == MD_GUEST_BUFFER) {
            if (q.data.args[1]==MD_FS_BUFFER_EXPORT || q.data.args[1]==MD_FS_BUFFER_IMPORT) {
                int result=q.data.instruction_pointer!=RAW_GATE || !t->ready
                    || q.data.args[2] || q.data.args[3] || q.data.args[4] || q.data.args[5]
                    ? -EPERM : q.data.args[1]==MD_FS_BUFFER_EXPORT
                        ? md_fs_buffer_export_install(t->buffer_call,listener,q.id)
                        : md_fd_return_install(&t->buffer_return,listener,q.id);
                if (result<0) {
                    struct seccomp_notif_resp reply={.id=q.id,.error=result};
                    CHECK(!ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&reply) || errno==ENOENT);
                }
            } else if (q.data.args[1]) buffer_setup(t,&q);
            else buffer_receive(t,&q);
        }
        else if (q.data.args[0] == MD_GUEST_SHM) shm_request(t,&q);
        else if (q.data.args[0] == MD_GUEST_IPC) ipc_request(t,&q);
        else image_request(t, &q);
        return;
    }
    if (q.data.nr == SYS_getdents64 && md_domain_restricted(t->resources.fs)) {
        CHECK(t->phase == IDLE);
        struct seccomp_notif_resp reply = {.id = q.id, .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE};
        CHECK(!ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply) || errno == ENOENT); return;
    }
    if (t->phase == EXPORT_NOTIFY) {
        struct metadata_operation *op = &t->metadata;
        CHECK(q.id != op->request.id && !memcmp(&q.data, &op->request.data, sizeof(q.data)));
        if (q.data.nr != SYS_fstat) { retained_result(t, &q); return; }
        struct seccomp_notif_resp reply = {.id = q.id, .error = op->error};
        CHECK(!ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply));
        t->phase = EXPORT_RETURN; return;
    }
    if (q.data.nr != SYS_fstat) {
        if (t->phase != IDLE) TRACE("PROBE unexpected notification pid=%d phase=%d nr=%d pc=%#llx fd=%llu\n",
            t->pid, t->phase, q.data.nr, q.data.instruction_pointer, q.data.args[0]);
        CHECK(t->phase == IDLE);
        if (!md_domain_restricted(t->resources.fs)) {
            delegate_begin(t, &q); return;
        }
        if ((int)q.data.args[0] < 0) {
            struct seccomp_notif_resp reply = {.id = q.id,
                .error = (int)q.data.args[0] == AT_FDCWD ? md_domain_path_error(t->resources.fs) : -EBADF};
            CHECK(!ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply) || errno == ENOENT); return;
        }
        export_begin(t, &q); return;
    }
    int fd = duplicate_fd(q.pid, (int)q.data.args[0]);
    if (md_task_descriptor_needs_export(fd) || fd == -ESRCH) {
        if (t->phase == IDLE && !md_domain_restricted(t->resources.fs)) {
            delegate_begin(t, &q); return;
        }
        export_begin(t, &q); return;
    }
    int error = fd < 0 ? fd : 0;
    struct stat st;
    if (!error) {
        error = descriptor_stat(t, fd, &st, q.data.instruction_pointer == RAW_GATE);
        close(fd);
    }
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &q.id)) { CHECK(errno == ENOENT); return; }
    if (!error) {
        struct iovec local = {&st, sizeof(st)}, remote = {(void *)q.data.args[1], sizeof(st)};
        ssize_t n = process_vm_writev(q.pid, &local, 1, &remote, 1, 0);
        if (n != sizeof(st)) error = n < 0 ? -errno : -EFAULT;
    }
    external_stats++;
    if (error && ++external_errors <= 8)
        TRACE("PROBE external fstat pid=%u fd=%llu result=%d\n", q.pid, q.data.args[0], error);
    struct seccomp_notif_resp reply = {.id = q.id, .error = error};
    CHECK(!ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply) || errno == ENOENT);
}
static void delegated_notification(const struct seccomp_notif *request) {
    handle_notification(request);
}
static void external_stat(void) {
    struct seccomp_notif q = {0};
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &q)) {
        CHECK(errno == ENOENT || errno == EINTR); return;
    }
    if (statistics) {
        if ((unsigned)q.data.nr < 512) statistics->calls[q.data.nr].notification++;
        else statistics->unknown++;
    }
    handle_notification(&q);
}
static int registers(pid_t pid, struct user_pt_regs *out) {
    struct iovec iov = {out, sizeof(*out)};
    if (!tracee_request(thread(pid), PTRACE_GETREGSET, (void *)NT_PRSTATUS, &iov, "get-registers")) return 0;
    CHECK(iov.iov_len == sizeof(*out)); return 1;
}
static int set_registers(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = {regs, sizeof(*regs)};
    return tracee_request(thread(pid), PTRACE_SETREGSET, (void *)NT_PRSTATUS, &iov, "set-registers");
}
static int skip(pid_t pid) {
    int nr = -1; struct iovec iov = {&nr, sizeof(nr)};
    return tracee_request(thread(pid), PTRACE_SETREGSET, (void *)NT_ARM_SYSTEM_CALL, &iov, "skip-syscall");
}
static void return_value(struct thread *t, struct user_pt_regs *regs, long value) {
    if (!skip(t->pid)) return;
    regs->regs[0] = (uint64_t)value;
    if (set_registers(t->pid, regs)) resume(t->pid, 0);
}
static int debugger_parent(pid_t pid) {
    struct thread *t=find_thread(pid);
    return t ? t->parent : 0;
}
static int debugger_group(pid_t pid) {
    struct thread *t=find_thread(pid);
    return t ? t->tgid : pid;
}
static uid_t debugger_uid(pid_t pid) {
    struct thread *t=find_thread(pid);
    CHECK(t);
    return t->identity.uid.real;
}
static int debugger_allowed(pid_t caller, pid_t pid) {
    struct thread *from=find_thread(caller), *to=find_thread(pid);
    if (!from || !to || md_domain_restricted(from->resources.fs)) return 0;
    return from->identity.uid.effective==to->identity.uid.real
        && from->identity.uid.effective==to->identity.uid.effective
        && from->identity.uid.effective==to->identity.uid.saved
        && from->identity.gid.effective==to->identity.gid.real
        && from->identity.gid.effective==to->identity.gid.effective
        && from->identity.gid.effective==to->identity.gid.saved;
}
static void debugger_complete(pid_t pid, struct user_pt_regs *regs, long value) {
    struct thread *t=find_thread(pid);
    TRACE("PROBE debugger result pid=%d nr=%llu target=%llu value=%ld\n",pid,regs->regs[8],regs->regs[0],value);
    if (t) return_value(t,regs,value);
}
static int debugger_attachable(pid_t caller, pid_t pid) {
    struct thread *t=find_thread(pid);
    if (!t || debugger_group(caller)==debugger_group(pid) || !debugger_allowed(caller,pid)
            || !t->entered || !t->process_image) return 0;
    char byte;
    struct iovec local={&byte,1}, remote={(void *)t->process_image,1};
    return process_vm_readv(pid,&local,1,&remote,1,0)==1;
}
static int debugger_interrupt(pid_t pid) {
    struct thread *t=find_thread(pid);
    if (!t) return -ESRCH;
    /* An owned stop already queued by clone is itself the interruption boundary. */
    if (t->kernel_stopped || (pid!=leader && t->born && !t->initial_stop)) return 0;
    return native_trace(PTRACE_INTERRUPT,pid,NULL,NULL) ? -errno : 0;
}
static int debugger_observe(pid_t owner) {
    struct thread *parent=find_thread(owner);
    if (!parent) return -ESRCH;
    /* EVENT_WAIT: a new trace relationship can select a wait already blocked
     * in the kernel, in any owner thread. INTERRUPT restarts it through the
     * debugger-aware path; cancellation/exit still owns the wait's lifetime. */
    for (struct thread *t=threads; t; t=t->next) if (t->pid && t->tgid==parent->tgid) {
        int error=debugger_interrupt(t->pid);
        if (error && error!=-ESRCH) return error;
    }
    return 0;
}
static int debugger_options(pid_t pid, unsigned long options) {
    struct thread *t=find_thread(pid);
    if (!t) return -ESRCH;
    int changed=((t->debug_options^options)&PTRACE_O_TRACEEXIT) && !t->terminal_observation;
    t->debug_options=options;
    if (!changed && !t->trace_options_dirty) return 0;
    t->trace_options_dirty=1;
    if (!t->kernel_stopped) return debugger_interrupt(pid);
    unsigned long required=t->terminal_observation ? PTRACE_O_TRACEEXIT : 0;
    if (native_trace(PTRACE_SETOPTIONS,pid,NULL,(void *)(trace_options|required|(options&PTRACE_O_TRACEEXIT)))) return -errno;
    t->trace_options_dirty=0;
    return 0;
}
static void debugger_usage(pid_t pid, struct rusage *usage) {
    struct thread *t=find_thread(pid);
    *usage=t ? t->usage : (struct rusage){0};
}
static int debugger_listen(pid_t pid) {
    struct thread *t=find_thread(pid);
    if (!t) return -ESRCH;
    if (native_trace(PTRACE_LISTEN,pid,NULL,NULL)) return -errno;
    t->listening=1; t->kernel_stopped=0;
    return 0;
}
static void debugger_wait_probe(pid_t pid, const struct user_pt_regs *original, enum md_debugger_wait_action action) {
    struct thread *t=find_thread(pid);
    if (!t) return;
    struct user_pt_regs regs=*original;
    TRACE("PROBE debugger wait pid=%d nr=%llu target=%llu action=%d phase=%d\n",pid,regs.regs[8],regs.regs[0],action,t->phase);
    if (action!=MD_DEBUG_WAIT_PROBE) regs.pc-=4;
    if (action==MD_DEBUG_WAIT_NATIVE) t->phase=IDLE;
    else {
        /* Only the nonblocking probe is shielded. A handler must not replace
         * the replayed syscall; native blocking waits retain ordinary signals. */
        if (!tracee_request(t,PTRACE_GETSIGMASK,(void *)sizeof(t->debug_wait_mask),&t->debug_wait_mask,"debug-wait-mask")
                || !shield(t)) return;
        regs.regs[regs.regs[8]==SYS_waitid ? 3 : 2]|=WNOHANG;
        t->phase=action==MD_DEBUG_WAIT_PROBE ? DEBUG_WAIT_EXIT : DEBUG_WAIT_ENTRY;
    }
    if (set_registers(pid,&regs)) resume(pid,0);
}
enum { COPY_GROUPS, COPY_CAP_HEADER, COPY_CAP_DATA, COPY_CAP_VERSION };
static void identity_copy_next(struct thread *t);
static void identity_copy_finish(struct thread *t, int error) {
    struct user_pt_regs r = t->original;
    if (!error && t->identity_stage == COPY_CAP_HEADER) {
        uint32_t version = t->identity_buffer[0];
        int pid = (int)t->identity_buffer[1];
        unsigned words = version == _LINUX_CAPABILITY_VERSION_1 ? 1
            : version == _LINUX_CAPABILITY_VERSION_2 || version == _LINUX_CAPABILITY_VERSION_3 ? 2 : 0;
        if (!words) {
            t->identity_buffer[0] = _LINUX_CAPABILITY_VERSION_3;
            t->identity_stage = COPY_CAP_VERSION; t->identity_loading = 0;
            t->identity_count = 1; t->identity_copied = 0;
            t->identity_result = r.regs[8] == SYS_capget && !r.regs[1] ? 0 : -EINVAL;
            identity_copy_next(t); return;
        }
        struct md_identity ids = md_identity_copy(&t->identity);
        if (pid && pid != t->pid) {
            md_identity_release(&ids);
            struct md_task_snapshot snapshot={0};
            error = r.regs[8] == SYS_capset ? -EPERM : md_task_registry_read(tasks, pid, 0, &snapshot);
            ids=md_identity_copy(&snapshot.identity);
            md_task_snapshot_release(&snapshot);
        }
        if (!error && r.regs[8] == SYS_capget && !r.regs[1]) {
            md_identity_release(&ids); t->identity_stage = COPY_CAP_DATA;
        } else if (!error) {
            if (r.regs[8] == SYS_capget) for (unsigned i = 0; i < words; i++) {
                t->identity_buffer[i*3] = ids.caps.effective >> (32*i);
                t->identity_buffer[i*3+1] = ids.caps.permitted >> (32*i);
                t->identity_buffer[i*3+2] = ids.caps.inheritable >> (32*i);
            }
            md_identity_release(&ids);
            t->identity_stage = COPY_CAP_DATA; t->identity_loading = r.regs[8] == SYS_capset;
            t->identity_address = r.regs[1]; t->identity_count = words*3; t->identity_copied = 0;
            identity_copy_next(t); return;
        } else md_identity_release(&ids);
    } else if (!error && t->identity_stage == COPY_CAP_DATA && r.regs[8] == SYS_capset) {
        uint32_t *v = t->identity_buffer;
        error = md_identity_capset(&t->identity, v[1] | ((uint64_t)v[4] << 32),
            v[0] | ((uint64_t)v[3] << 32), v[2] | ((uint64_t)v[5] << 32));
    }
    if (!error && t->identity_stage == COPY_CAP_VERSION) error = t->identity_result;
    if (!error && r.regs[8] == SYS_setgroups)
        error = md_identity_groups(&t->identity, t->identity_buffer, t->identity_count);
    r.regs[0] = (uint64_t)(error ? (long)error : r.regs[8] == SYS_getgroups ? (long)t->identity_count : 0);
    free(t->identity_buffer); t->identity_buffer = NULL;
    if (!set_registers(t->pid, &r) || !restore_mask(t)) return;
    t->phase = IDLE; resume(t->pid, 0);
}
static void identity_copy_next(struct thread *t) {
    if (t->identity_copied == t->identity_count) { identity_copy_finish(t, 0); return; }
    struct user_pt_regs r = t->original;
    unsigned count = t->identity_count - t->identity_copied;
    if (count > 16) count = 16;
    uintptr_t address = t->identity_address, offset = (uintptr_t)t->identity_copied * sizeof(uint32_t);
    if (address > UINTPTR_MAX - offset - count * sizeof(uint32_t)) { identity_copy_finish(t, -EFAULT); return; }
    int loading = t->identity_loading;
    r.pc = loading ? abi.load_groups : abi.store_groups;
    r.regs[0] = address + offset; r.regs[1] = count;
    if (!loading) for (unsigned i = 0; i < count; i++) r.regs[i+3] = t->identity_buffer[t->identity_copied+i];
    if (!set_registers(t->pid, &r)) return;
    t->phase = IDENTITY_COPY; resume(t->pid, 0);
}
static void identity_groups_call(struct thread *t, struct user_pt_regs *r) {
    int setting = r->regs[8] == SYS_setgroups;
    unsigned count = setting ? (unsigned)r->regs[0] : md_identity_group_count(&t->identity);
    int error = 0;
    if (setting && !md_identity_capable(&t->identity, CAP_SETGID)) error = -EPERM;
    else if ((int)r->regs[0] < 0 || (setting && (unsigned)r->regs[0] > MD_IDENTITY_GROUPS_MAX)
            || (!setting && r->regs[0] && (unsigned)r->regs[0] < count)) error = -EINVAL;
    if (error || (!setting && !r->regs[0])) { return_value(t, r, error ? error : (long)count); return; }
    if (!count) { if (setting) md_identity_groups(&t->identity, NULL, 0); return_value(t, r, 0); return; }
    uint32_t *buffer = malloc((size_t)count * sizeof(*buffer));
    if (!buffer) { return_value(t, r, -ENOMEM); return; }
    if (!setting) memcpy(buffer, md_identity_group_data(&t->identity), (size_t)count * sizeof(*buffer));
    struct iovec local = {buffer, (size_t)count * sizeof(*buffer)}, remote = {(void *)r->regs[1], local.iov_len};
    ssize_t copied = setting ? process_vm_readv(t->pid, &local, 1, &remote, 1, 0)
        : process_vm_writev(t->pid, &local, 1, &remote, 1, 0);
    if (copied == (ssize_t)local.iov_len) {
        error = setting ? md_identity_groups(&t->identity, buffer, count) : 0;
        free(buffer); return_value(t, r, error ? error : setting ? 0 : (long)count); return;
    }
    /* Task-affine copies preserve protected-memory and EFAULT semantics without
     * relaxing dumpability. Identity publishes only after the complete read. */
    t->identity_buffer = buffer; t->identity_count = count; t->identity_copied = 0; t->original = *r;
    t->identity_address = r->regs[1]; t->identity_loading = setting; t->identity_stage = COPY_GROUPS;
    if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(t->mask), &t->mask, "get-mask")
            || !shield(t) || !skip(t->pid)) return;
    identity_copy_next(t);
}
static int identity_call(struct thread *t, struct user_pt_regs *r, unsigned long cookie) {
    if (r->pc == RAW_GATE) return 0;
    long nr = r->regs[8], value;
    if (nr == SYS_prctl) {
        unsigned long args[4] = {r->regs[1], r->regs[2], r->regs[3], r->regs[4]};
        value = md_identity_cap_prctl(&t->identity, r->regs[0], args);
        if (value != -ENOTSUP) { return_value(t, r, value); return 1; }
    }
    if (nr == SYS_prctl && (r->regs[0] == PR_GET_NO_NEW_PRIVS || r->regs[0] == PR_SET_NO_NEW_PRIVS)) {
        CHECK(t->phase == IDLE && t->ready);
        if (r->regs[2] || r->regs[3] || r->regs[4]) value = -EINVAL;
        else if (r->regs[0] == PR_GET_NO_NEW_PRIVS) value = r->regs[1] ? -EINVAL : t->identity.no_new_privs;
        else value = md_identity_no_new_privs(&t->identity, r->regs[1]);
        return_value(t, r, value); return 1;
    }
    if (cookie != MD_INTERCEPT_IDENTITY) return 0;
    CHECK(t->ready && t->phase == IDLE);
    switch (nr) {
    case SYS_capget: case SYS_capset:
        t->identity_buffer = calloc(6, sizeof(uint32_t));
        if (!t->identity_buffer) { return_value(t, r, -ENOMEM); return 1; }
        t->identity_stage = COPY_CAP_HEADER; t->identity_address = r->regs[0];
        t->identity_loading = 1; t->identity_count = 2; t->identity_copied = 0; t->original = *r;
        if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(t->mask), &t->mask, "get-mask")
                || !shield(t) || !skip(t->pid)) return 1;
        identity_copy_next(t); return 1;
    case SYS_getgroups: case SYS_setgroups: identity_groups_call(t, r); return 1;
    case SYS_getuid: value = t->identity.uid.real; break;
    case SYS_geteuid: value = t->identity.uid.effective; break;
    case SYS_getgid: value = t->identity.gid.real; break;
    case SYS_getegid: value = t->identity.gid.effective; break;
    case SYS_getresuid: case SYS_getresgid: {
        const struct md_identity_ids *ids = nr == SYS_getresuid ? &t->identity.uid : &t->identity.gid;
        t->original = *r;
        if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(t->mask), &t->mask, "get-mask")
                || !shield(t) || !skip(t->pid)) return 1;
        r->pc = STORE_IDS; r->regs[3] = ids->real; r->regs[4] = ids->effective; r->regs[5] = ids->saved;
        if (!set_registers(t->pid, r)) return 1;
        t->phase = STORING_IDS; resume(t->pid, 0); return 1;
    }
    case SYS_setresuid:
        value = md_identity_setresuid(&t->identity, r->regs[0], r->regs[1], r->regs[2]); break;
    case SYS_setresgid:
        value = md_identity_setresgid(&t->identity, r->regs[0], r->regs[1], r->regs[2]); break;
    case SYS_setuid: value = md_identity_setuid(&t->identity, r->regs[0]); break;
    case SYS_setgid: value = md_identity_setgid(&t->identity, r->regs[0]); break;
    case SYS_setreuid: value = md_identity_setreuid(&t->identity, r->regs[0], r->regs[1]); break;
    case SYS_setregid: value = md_identity_setregid(&t->identity, r->regs[0], r->regs[1]); break;
    case SYS_setfsuid: value = md_identity_setfsuid(&t->identity, r->regs[0]); break;
    case SYS_setfsgid: value = md_identity_setfsgid(&t->identity, r->regs[0]); break;
    default: value = -ENOTSUP; break;
    }
    if ((nr == SYS_setresuid || nr == SYS_setresgid) && !value) {
        identity_changes++;
        TRACE("PROBE identity-change pid=%d uid=%u euid=%u suid=%u gid=%u egid=%u\n",
            t->pid, t->identity.uid.real, t->identity.uid.effective, t->identity.uid.saved,
            t->identity.gid.real, t->identity.gid.effective);
    }
    return_value(t, r, value); return 1;
}
static void dispatch_with_stack(struct thread *);
static int guest_root_path(struct thread *t, long nr, const char *path) {
    return nr == SYS_chroot && t->endpoint[0] && !md_domain_restricted(t->resources.fs)
        && (md_domain_scoped(t->resources.fs)
            || (strcmp(path, "/proc/self/fd") && strcmp(path, "/proc/self/fdinfo")));
}
static int domain_path_apply(struct thread *t, long nr, const char *path) {
    if (nr == SYS_chdir)
        return !strcmp(path, "/") ? md_domain_chdir_root(t->resources.fs) : -ENOTSUP;
    int error = md_domain_restrict(t->resources.fs, t->pid, path);
    if (!error) {
        root_changes++;
        /* CLONE_FS members may run without another ptrace stop. Revoke their
         * published eligibility before acknowledging the shared restriction. */
        if (broker) for (struct thread *member = threads; member; member = member->next)
            if (member->pid && member->resources.fs == t->resources.fs)
                CHECK(!md_broker_task(broker, member->pid, 0, RAW_GATE, abi.watch_gate + 4));
    }
    TRACE("PROBE root-change pid=%d result=%d\n", t->pid, error);
    return error;
}
static void domain_path_finish(struct thread *t, int error) {
    struct user_pt_regs r = t->original;
    if (!error && guest_root_path(t, r.regs[8], t->metadata.path)) {
        dispatch_with_stack(t); return;
    }
    if (!error) error = domain_path_apply(t, r.regs[8], t->metadata.path);
    r.regs[0] = (uint64_t)error;
    if (!set_registers(t->pid, &r) || !restore_mask(t)) return;
    t->phase = IDLE; resume(t->pid, 0);
}
static void domain_path_load(struct thread *t) {
    size_t offset = t->metadata.path_size;
    if (offset == sizeof(t->metadata.path)) { domain_path_finish(t, -ENAMETOOLONG); return; }
    if (t->original.regs[0] > UINTPTR_MAX - offset) { domain_path_finish(t, -EFAULT); return; }
    struct user_pt_regs r = t->original;
    r.pc = LOAD_BYTE; r.regs[0] += offset;
    if (!set_registers(t->pid, &r)) return;
    t->phase = DOMAIN_PATH; resume(t->pid, 0);
}
static void domain_path_call(struct thread *t, struct user_pt_regs *r) {
    char path[4096];
    int error = read_string(t->pid, r->regs[0], path, sizeof(path));
    if (error != -EPERM && error != -EACCES) {
        if (!error && guest_root_path(t, r->regs[8], path)) {
            CHECK(t->ready && t->phase == IDLE);
            t->original = *r;
            if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(t->mask), &t->mask, "get-mask")
                    || !shield(t) || !skip(t->pid)) return;
            dispatch_with_stack(t); return;
        }
        if (!error) error = domain_path_apply(t, r->regs[8], path);
        return_value(t, r, error); return;
    }
    CHECK(t->ready && t->phase == IDLE);
    t->original = *r; t->metadata.path_size = 0;
    if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(t->mask), &t->mask, "get-mask")
            || !shield(t) || !skip(t->pid)) return;
    domain_path_load(t);
}
static void fd_discard(struct thread *t) {
    if (t->fd_task) {
        md_fs_buffer_cancel(&t->buffer_call);
        t->fd_task=t->fd_running=0;
        return;
    }
    if (t->fd_running && t->fd_cwd && t->fd_registers.regs[8]!=SYS_openat)
        CHECK(!md_domain_set_cwd(t->fs_order.fs,NULL));
    md_fs_anchor_release(t->fd_origin); t->fd_origin=NULL;
    if (t->fs_order.fs && md_fs_order_cancel(&t->fs_order)==1)
        CHECK(!md_fs_order_complete(&t->fs_order));
    if (t->fd_running) CHECK(!md_fd_mutation_abandon(&t->fd_mutation,t->fd_order.table));
    else md_fd_mutation_discard(&t->fd_mutation);
    if (t->fd_order.table) {
        int running=md_fd_order_cancel(&t->fd_order);
        /* Called only after a terminal task event, never merely on timeout. */
        if (running==1) {
            if (t->fd_job==MD_FD_RECEIVE) CHECK(!md_fd_exchange_received(t->fd_exchange));
            CHECK(!md_fd_order_complete(&t->fd_order));
        }
    }
    t->fd_running=0; t->fd_job=0; t->fd_cwd=0; t->fd_capture=0;
    md_fd_exchange_close(fd_exchanges,t->fd_exchange); t->fd_exchange=NULL;
}
static void fd_finish(struct thread *t, long result) {
    if (t->fd_task) {
        /* The adapter must acknowledge execution. Fatal filter exits can
         * expose unchanged arguments as if they were a syscall result. */
        t->fd_task=t->fd_running=0;
        return;
    }
    long nr=t->fd_registers.regs[8];
    if (nr==SYS_clone && t->memory_action==MEMORY_FORK) {
        CHECK(!md_resource_order_complete(&t->memory_order)); t->memory_action=0;
    }
    int exec=nr==SYS_execve || nr==SYS_execveat;
    if (exec || nr==SYS_unshare || (nr==SYS_close_range && (t->fd_registers.regs[2]&CLOSE_RANGE_UNSHARE)))
        CHECK(!md_resources_unshare_finish(ipc,&t->resources,&t->resource_change,result));
    if (exec && !result) md_fd_origins_exec(t->resources.files);
    if (t->fd_cwd && nr!=SYS_openat && !result)
        CHECK(!md_domain_set_cwd(t->fs_order.fs,md_domain_restricted(t->fs_order.fs) ? NULL : t->fd_origin));
    md_fs_anchor_release(t->fd_origin); t->fd_origin=NULL;
    CHECK(!md_fd_mutation_finish(&t->fd_mutation,t->resources.files,result));
    if (t->fs_order.fs) CHECK(!md_fs_order_complete(&t->fs_order));
    CHECK(!md_fd_order_complete(&t->fd_order));
    t->fd_running=0; t->fd_cwd=0; t->fd_capture=0;
}
static void fd_start(struct thread *t) {
    if (md_fd_order_state(&t->fd_order)==MD_RESOURCE_ORDER_READY)
        CHECK(!md_fd_order_start(&t->fd_order));
    struct user_pt_regs *r=&t->fd_registers;
    int needs_fs=t->fd_job==MD_FD_INPUT ? (int)r->regs[2]==AT_FDCWD || (int)r->regs[3]==AT_FDCWD
        : !t->fd_job && (t->fd_cwd || r->regs[8]==SYS_clone
            || (r->regs[8]==SYS_unshare && (r->regs[0]&CLONE_FS)));
    if (needs_fs) {
        if (!t->fs_order.fs) {
            int ready=md_fs_order_begin(t->resources.fs,&t->fs_order,fd_wakeup);
            CHECK(ready>=0);
            /* EVENT_WAIT: the CLONE_FS owner completes its exact mutation;
             * terminal task cleanup cancels both ordered resource records. */
            if (!ready) return;
        }
        CHECK(!md_fs_order_start(&t->fs_order));
    }
    if (t->fd_job) {
        long result=0;
        if (t->fd_job==MD_FD_INPUT) {
            int bases[2]={(int)r->regs[2],(int)r->regs[3]};
            struct md_fs_anchor *cwd=NULL;
            if (needs_fs) {
                struct md_fs_location root;
                md_domain_paths(t->fs_order.fs,&root,&cwd);
            }
            result=md_fd_exchange_begin(fd_exchanges,t->pid,t->resources.files,bases,cwd,&t->fd_exchange);
            md_fs_anchor_release(cwd);
            if (t->fs_order.fs) CHECK(!md_fs_order_complete(&t->fs_order));
            if (!result) result=(long)md_fd_exchange_id(t->fd_exchange);
        }
        if (result<0) {
            CHECK(!md_fd_order_complete(&t->fd_order)); t->fd_job=0;
        }
        r->regs[0]=result; r->pc+=4;
        if (set_registers(t->pid,r)) resume(t->pid,0);
        return;
    }
    unsigned long args[6];
    for (unsigned i=0;i<6;++i) args[i]=r->regs[i];
    int error=0;
    if (r->regs[8]==SYS_execve || r->regs[8]==SYS_execveat || r->regs[8]==SYS_unshare
            || (r->regs[8]==SYS_close_range && (r->regs[2]&CLOSE_RANGE_UNSHARE)))
        error=md_resources_unshare_prepare(&t->resources,r->regs[8]==SYS_unshare ? r->regs[0] : CLONE_FILES,
            &t->resource_change);
    if (!error) error=md_fd_mutation_prepare(t->resources.files,r->regs[8],args,&t->fd_mutation);
    if (!error && t->fd_cwd && r->regs[8]==SYS_fchdir)
        t->fd_origin=md_fd_origins_get(t->resources.files,(int)r->regs[0],NULL);
    if (!error && t->fd_cwd && r->regs[8]==SYS_chdir && t->buffer.pool
            && t->buffer_open.task_path==MD_FS_TASK_CHDIR
            && r->regs[0]==md_memory_buffer_address(t->memory,&t->buffer)+offsetof(struct md_fs_buffer_frame,source))
        t->fd_origin=md_fs_anchor_retain(t->buffer_open.origin);
    if (!error && t->fd_capture) {
        if ((int)r->regs[4]==MD_FS_BUFFER_SOURCE) t->fd_origin=md_fs_anchor_retain(t->buffer_open.origin);
        else if ((int)r->regs[4]==AT_FDCWD) {
            struct md_fs_location root;
            md_domain_paths(t->fs_order.fs,&root,&t->fd_origin);
        } else t->fd_origin=md_fd_origins_get(t->resources.files,(int)r->regs[4],NULL);
        error=md_fd_origins_prepare(t->resources.files,t->fd_origin,
            r->regs[2]&O_CLOEXEC ? FD_CLOEXEC : 0,&t->fd_mutation.update);
        TRACE("PROBE path-capture pid=%d base=%d known=%d\n",t->pid,(int)r->regs[4],t->fd_origin!=NULL);
    }
    if (error) {
        md_resources_unshare_finish(ipc,&t->resources,&t->resource_change,-ECANCELED);
        fd_discard(t); return_value(t,r,error); return;
    }
    if (r->regs[8]==SYS_clone) { t->original=*r; t->phase=OBSERVING; }
    t->fd_running=1; resume(t->pid,0);
}
static void fd_begin(struct thread *t, const struct user_pt_regs *r, unsigned operation) {
    if (operation==MD_INTERCEPT_CWD && r->regs[8]==SYS_fchdir
            && md_fs_buffer_task_pending(t->buffer_call)) {
        CHECK(!t->fd_order.table && !t->fd_running && t->phase==DISPATCHING);
        int error=md_fs_buffer_task_start(t->buffer_call,(int)r->regs[0]);
        t->fd_registers=*r;
        if (error) { return_value(t,&t->fd_registers,error); return; }
        t->fd_task=t->fd_running=1;
        resume(t->pid,0); return;
    }
    if (!t->resources.files) { resume(t->pid,0); return; }
    CHECK(!t->fd_order.table && !t->fd_running);
    t->fd_job=0;
    t->fd_capture=operation==MD_INTERCEPT_CAPTURE;
    if (t->fd_capture && !t->terminal_observation) {
        /* Retain terminal registers independently of a guest debugger. Enable
         * once per task lifetime, not around each native descriptor operation. */
        t->terminal_observation=1; t->trace_options_dirty=1;
    }
    t->fd_cwd=operation==MD_INTERCEPT_CWD || (t->fd_capture && (int)r->regs[4]==AT_FDCWD);
    t->fd_registers=*r;
    int ready=md_fd_order_begin(t->resources.files,&t->fd_order,fd_wakeup);
    CHECK(ready>=0);
    if (ready) fd_start(t);
    /* EVENT_WAIT: another operation owns this file table. fd_ready signals its
     * exact completion; the launch deadline cancels the owned process tree. */
}
static void fd_control(struct thread *t, struct user_pt_regs *r) {
    unsigned operation=(unsigned)r->regs[0];
    uint64_t id=r->regs[1];
    long result=0;
    if (operation==MD_FD_INPUT || operation==MD_FD_RECEIVE || operation==MD_FD_USE) {
        if (t->fd_order.table || (operation==MD_FD_USE ? id || r->regs[2] || r->regs[3]
                : operation==MD_FD_INPUT ? t->fd_exchange!=NULL
                : !id || id!=md_fd_exchange_id(t->fd_exchange))) result=-EINVAL;
        else if (t->resources.files) {
            t->fd_registers=*r; t->fd_job=operation;
            int ready=md_fd_order_begin(t->resources.files,&t->fd_order,fd_wakeup);
            if (ready<0) { t->fd_job=0; result=ready; }
            else { if (ready) fd_start(t); return; }
        }
    } else if (operation==MD_FD_RELEASE) {
        if (id || r->regs[2] || r->regs[3] || t->fd_job!=MD_FD_USE
                || md_fd_order_state(&t->fd_order)!=MD_RESOURCE_ORDER_RUNNING) result=-EINVAL;
        else { CHECK(!md_fd_order_complete(&t->fd_order)); t->fd_job=0; }
    } else if (!id || id!=md_fd_exchange_id(t->fd_exchange)) result=-ESTALE;
    else if (operation==MD_FD_SENT || operation==MD_FD_RECEIVED) {
        if (t->fd_job!=(operation==MD_FD_SENT ? MD_FD_INPUT : MD_FD_RECEIVE)
                || md_fd_order_state(&t->fd_order)!=MD_RESOURCE_ORDER_RUNNING) result=-EINVAL;
        else {
            if (operation==MD_FD_RECEIVED) result=md_fd_exchange_received(t->fd_exchange);
            CHECK(!md_fd_order_complete(&t->fd_order)); t->fd_job=0;
        }
    } else if (operation==MD_FD_END) {
        if (t->fd_order.table) result=-EBUSY;
        else { md_fd_exchange_close(fd_exchanges,t->fd_exchange); t->fd_exchange=NULL; }
    } else result=-EINVAL;
    if (result<0) TRACE("PROBE fd-control pid=%d op=%u id=%llu result=%ld\n",t->pid,operation,
        (unsigned long long)id,result);
    r->regs[0]=result; r->pc+=4;
    if (set_registers(t->pid,r)) resume(t->pid,0);
}
static void buffer_reply_signal(struct thread *t, long result, const siginfo_t *signal) {
    struct user_pt_regs r=t->buffer_registers;
    r.regs[0]=result; r.pc+=4;
    if (signal && !tracee_request(t,PTRACE_SETSIGINFO,NULL,(void *)signal,"helper-signal")) return;
    if (set_registers(t->pid,&r)) resume(t->pid,signal ? signal->si_signo : 0);
}
static void buffer_reply(struct thread *t, long result) {
    buffer_reply_signal(t,result,NULL);
}
static void probe_complete(void *context, struct md_task_helper_result result) {
    struct probe_owner *owner=context;
    struct thread *t=owner->caller ? find_thread(owner->caller) : NULL;
    struct stat st;
    long error=result.value;
    if (!error && result.descriptor<0) error=-EPROTO;
    if (!error && fstat(result.descriptor,&st)) error=-errno;
    if (!error && !S_ISDIR(st.st_mode)) error=-ENOTDIR;
    if (result.descriptor>=0) close(result.descriptor);
    if (t && t->probe==owner) {
        t->probe=NULL; t->kernel_stopped=1;
        t->buffer_registers=owner->continuation;
        buffer_reply(t,error);
    }
    free(owner);
}
static void probe_begin(struct thread *t, const struct user_pt_regs *regs) {
    struct probe_owner *owner=calloc(1,sizeof(*owner));
    int error=owner ? 0 : -ENOMEM;
    if (!error) {
        *owner=(struct probe_owner){t->pid,*regs};
        t->terminal_observation=1; t->trace_options_dirty=1;
        error=debugger_options(t->pid,t->debug_options);
    }
    if (!error) {
        struct md_task_helper_request request={.kind=MD_TASK_HELPER_CAPTURE,
            .path="/proc/thread-self",.flags=O_PATH|O_DIRECTORY};
        error=md_task_helper_begin(helpers,t->pid,t->tgid,regs,&abi,t->memory,&t->buffer,
            &request,probe_complete,owner);
    }
    if (error) { free(owner); buffer_reply(t,error); }
    else { t->probe=owner; t->kernel_stopped=0; }
}
static void send_captured(void *context) {
    struct send_owner *owner=context;
    if (!owner->request) return;
    struct thread *t=find_thread(owner->caller);
    CHECK(t && t->send==owner && t->buffer_call==owner->request);
    CHECK(!md_fs_buffer_task_finish(&t->buffer_call,0));
    owner->request=NULL;
}
static void send_complete(void *context, struct md_task_helper_result result) {
    struct send_owner *owner=context;
    struct thread *t=owner->caller ? find_thread(owner->caller) : NULL;
    CHECK(result.descriptor<0);
    if (t && t->send==owner) {
        if (owner->request) md_fs_buffer_cancel(&t->buffer_call);
        t->send=NULL; t->kernel_stopped=1; t->buffer_registers=owner->continuation;
        buffer_reply_signal(t,result.value,result.signal.si_signo ? &result.signal : NULL);
    }
    free(owner);
}
static void send_begin(struct thread *t, const struct user_pt_regs *regs) {
    struct md_buffer_span span;
    int error=md_buffer_span(&t->buffer,&span);
    struct send_owner *owner=NULL;
    struct md_task_helper_request request={.kind=MD_TASK_HELPER_SEND,.captured=send_captured};
    if (!error) {
        struct md_fs_buffer_frame *frame=span.data;
        memcpy(&request.send,frame->value,sizeof(request.send));
        request.source=md_fs_buffer_task_send_source(t->buffer_call);
        error=request.source<0 ? request.source : md_fs_buffer_task_start(t->buffer_call,request.send.socket);
    }
    if (!error) {
        owner=calloc(1,sizeof(*owner));
        if (!owner) error=-ENOMEM;
    }
    if (!error) {
        *owner=(struct send_owner){t->pid,t->buffer_call,*regs};
        t->terminal_observation=1; t->trace_options_dirty=1;
        error=debugger_options(t->pid,t->debug_options);
    }
    if (!error) error=md_task_helper_begin(helpers,t->pid,t->tgid,regs,&abi,t->memory,&t->buffer,
        &request,send_complete,owner);
    if (error) {
        md_fs_buffer_cancel(&t->buffer_call); free(owner); buffer_reply(t,error);
    } else { t->send=owner; t->kernel_stopped=0; }
}
static void receive_captured(void *context) {
    struct receive_owner *owner=context;
    CHECK(!md_fd_order_complete(&owner->files));
}
static void receive_complete(void *context, struct md_task_helper_result result) {
    struct receive_owner *owner=context;
    struct thread *t=owner->caller ? find_thread(owner->caller) : NULL;
    CHECK(result.descriptor<0);
    if (owner->files.table && md_fd_order_cancel(&owner->files)==1)
        CHECK(!md_fd_order_complete(&owner->files));
    owner->ready=1; owner->received=result.received;
    if (t && t->receive==owner) {
        t->kernel_stopped=1; t->buffer_registers=owner->continuation;
        buffer_reply(t,result.value);
    } else { md_received_fds_close(&owner->received); free(owner); }
}
static void receive_start(struct thread *t) {
    struct receive_owner *owner=t->receive;
    if (!owner || owner->started || md_fd_order_state(&owner->files)!=MD_RESOURCE_ORDER_READY) return;
    int error=md_fd_order_start(&owner->files);
    if (!error) {
        t->terminal_observation=1; t->trace_options_dirty=1;
        error=debugger_options(t->pid,t->debug_options);
    }
    if (!error) {
        struct md_task_helper_request request={.kind=MD_TASK_HELPER_RECEIVE,
            .receive=owner->request,.captured=receive_captured};
        error=md_task_helper_begin(helpers,t->pid,t->tgid,&owner->continuation,&abi,t->memory,&t->buffer,
            &request,receive_complete,owner);
    }
    owner->started=1;
    if (error) receive_complete(owner,(struct md_task_helper_result){.value=error,.descriptor=-1});
    else t->kernel_stopped=0;
}
static void receive_begin(struct thread *t, const struct user_pt_regs *regs) {
    struct md_buffer_span span;
    int error=md_buffer_span(&t->buffer,&span);
    struct receive_owner *owner=NULL;
    if (!error) { owner=calloc(1,sizeof(*owner)); if (!owner) error=-ENOMEM; }
    if (!error) {
        *owner=(struct receive_owner){.caller=t->pid,.continuation=*regs,
            .request=((struct md_task_receive_frame *)span.data)->input};
        error=md_fd_order_begin(t->resources.files,&owner->files,fd_wakeup);
        if (error>0) error=0;
    }
    if (error) { free(owner); buffer_reply(t,error); }
    else { t->receive=owner; receive_start(t); }
}
static void capture_complete(void *context, struct md_task_helper_result result) {
    struct capture_owner *owner=context;
    struct thread *t=owner->caller ? find_thread(owner->caller) : NULL;
    if (t && t->capture==owner) { t->capture=NULL; t->kernel_stopped=1; }
    CHECK(!md_fs_buffer_capture_finish(owner->request,result.descriptor,(int)result.value));
    free(owner);
}
static void capture_start(struct thread *t, struct md_fs_buffer_request *request) {
    CHECK(!t->capture && !t->mapping);
    TRACE("PROBE buffer-capture pid=%d\n",t->pid);
    struct capture_owner *owner=calloc(1,sizeof(*owner));
    int error=owner ? md_fs_buffer_capture_start(request) : -ENOMEM;
    if (!error) {
        *owner=(struct capture_owner){.caller=t->pid,.request=request};
        t->terminal_observation=1; t->trace_options_dirty=1;
        error=debugger_options(t->pid,t->debug_options);
    }
    if (!error) {
        struct md_fs_task_capture target;
        error=md_fs_buffer_capture_target(request,&target);
        if (!error) {
            struct md_task_helper_request capture={.kind=MD_TASK_HELPER_CAPTURE,
                .path=target.path,.flags=target.flags};
            error=md_task_helper_begin(helpers,t->pid,t->tgid,&t->buffer_registers,&abi,
                t->memory,&t->buffer,&capture,capture_complete,owner);
        }
    }
    if (error) {
        free(owner);
        CHECK(!md_fs_buffer_capture_finish(request,-1,error));
    } else { t->capture=owner; t->kernel_stopped=0; }
}
static void buffer_complete(struct md_fs_buffer_request *request, pid_t pid, int error) {
    struct thread *t=find_thread(pid);
    CHECK(t && t->buffer_call==request);
    if (md_fs_buffer_capture_pending(request)) { capture_start(t,request); return; }
    if (!md_fs_buffer_ack_pending(request) && !md_fs_buffer_export_pending(request)
            && !md_fs_buffer_snapshot_pending(request) && !md_fs_buffer_task_pending(request)) t->buffer_call=NULL;
    if (!error) {
        CHECK(md_fs_buffer_exec_take(request,t->exec_images)>=0);
        if (!md_fs_buffer_task_pending(request)) CHECK(md_fs_buffer_open_take(request,&t->buffer_open)>=0);
    }
    TRACE("PROBE buffer-call pid=%d operation=%llu error=%d descriptor=%d\n",pid,t->buffer_registers.regs[1],error,t->buffer_open.fd>=0);
    buffer_reply(t,error);
}
static void buffer_take(struct thread *t) {
    int error=md_buffers_take(md_memory_buffers(t->memory),&t->buffer);
    if (error==-EAGAIN) return;
    t->buffer_waiting=0;
    uintptr_t address=error ? 0 : md_memory_buffer_address(t->memory,&t->buffer);
    if (!error && !address) { CHECK(!md_buffer_release(&t->buffer)); error=-EINVAL; }
    buffer_reply(t,error ? error : (long)address);
}
static void buffer_return_progress(struct thread *t) {
    if (!t->buffer_return_waiting) return;
    int result=md_fd_return_progress(&t->buffer_return,fd_wakeup);
    if (result==MD_FD_RETURN_WAIT) return;
    if (result>=0) {
        struct md_buffer_span span;
        CHECK(!md_buffer_span(&t->buffer,&span));
        struct md_fs_buffer_frame *frame=span.data;
        if (result==MD_FD_RETURN_CHECK) {
            frame->channel.number=t->buffer_return.endpoint;
            frame->channel.observation=(struct md_fd_channel_observation){0};
            result=MD_FS_BUFFER_CHANNEL_CHECK;
        } else { frame->receive.number=t->buffer_return.endpoint; result=0; }
    }
    t->buffer_return_waiting=0;
    buffer_reply(t,result);
}
static void adapter_progress(void) {
    CHECK(!md_fs_buffer_progress(buffer_service));
    for (struct thread *t=threads;t;t=t->next)
        if (t->pid) {
            if (t->mapping && !t->mapping->started) mapping_start(t);
            if (t->phase==MEMORY_WAIT) memory_start(t);
            if (t->buffer_waiting) buffer_take(t);
            receive_start(t);
            buffer_deliver(t);
            proc_deliver(t);
            buffer_return_progress(t);
        }
}
static void buffer_control(struct thread *t, const struct user_pt_regs *r) {
    long result=-EINVAL;
    if (t->buffer_waiting || t->buffer_return_waiting || (t->buffer_call && !md_fs_buffer_ack_pending(t->buffer_call)
            && !md_fs_buffer_export_pending(t->buffer_call)
            && !md_fs_buffer_snapshot_pending(t->buffer_call)
            && !md_fs_buffer_task_pending(t->buffer_call))) { CHECK(0); }
    t->buffer_registers=*r;
    if (!buffer_service && r->regs[0]!=MD_BUFFER_MAPPED && r->regs[0]!=MD_BUFFER_TAKE
            && r->regs[0]!=MD_BUFFER_RELEASE && r->regs[0]!=MD_BUFFER_PROBE) {
        buffer_reply(t,-ENOTSUP); return;
    }
    if (t->ipc_transport.packet && r->regs[0]!=MD_BUFFER_RELEASE) {
        buffer_reply(t,-EBUSY); return;
    }
    int snapshot=md_fs_buffer_snapshot_pending(t->buffer_call);
    if (t->buffer_call && r->regs[0]!=MD_FS_BUFFER_ACK && r->regs[0]!=MD_FS_BUFFER_SENT
            && r->regs[0]!=MD_FS_BUFFER_CHANNEL_OBSERVED
            && !(md_fs_buffer_task_pending(t->buffer_call)
                && (r->regs[0]==MD_BUFFER_RELEASE || r->regs[0]==MD_FS_BUFFER_TASK_DONE
                    || r->regs[0]==MD_FS_BUFFER_TASK_SEND))
            && !(snapshot && (r->regs[0]==MD_FS_BUFFER_SNAPSHOT_APPEND
                || r->regs[0]==MD_FS_BUFFER_SNAPSHOT_FINISH || r->regs[0]==MD_BUFFER_RELEASE))) {
        buffer_reply(t,-EBUSY); return;
    }
    if (t->buffer_return.files.table && r->regs[0]!=MD_FS_BUFFER_RIGHTS_READY
            && r->regs[0]!=MD_FS_BUFFER_RIGHTS_DONE && r->regs[0]!=MD_FS_BUFFER_CHANNEL_OBSERVED) {
        buffer_reply(t,-EBUSY); return;
    }
    switch (r->regs[0]) {
    case MD_FS_BUFFER_TASK_RECEIVE:
        if (t->phase!=DISPATCHING || t->receive || !t->buffer.pool || r->regs[1] || r->regs[2]
                || (t->original.regs[8]!=SYS_recvmsg && t->original.regs[8]!=SYS_recvmmsg)) break;
        /* EVENT_WAIT: private native receive, export and exact helper reaping.
         * Source capture alone holds the table turn, never the blocking IO. */
        receive_begin(t,r); return;
    case MD_FS_BUFFER_RECEIVED_DROP:
        if (!t->receive || !t->receive->ready || r->regs[1] || r->regs[2]) break;
        md_received_fds_close(&t->receive->received); free(t->receive); t->receive=NULL;
        result=0; break;
    case MD_FS_BUFFER_RECEIVED_CALL: {
        if (!t->receive || !t->receive->ready || !t->buffer.pool || r->regs[2]) break;
        struct md_buffer_span span;
        result=md_buffer_span(&t->buffer,&span);
        if (result) break;
        const struct md_fs_buffer_frame *frame=span.data;
        int borrowed[2]={-1,-1};
        for (unsigned i=0;i<2;++i) {
            int index=frame->input.base[i];
            if (index==-1) continue;
            if (index<0 || (unsigned)index>=t->receive->received.count) { result=-EBADF; break; }
            borrowed[i]=t->receive->received.fds[index];
        }
        if (result) break;
        result=md_fs_buffer_received_begin(buffer_service,t->pid,t->resources.fs,(unsigned)r->regs[1],
            &t->buffer,borrowed,&t->buffer_call);
        if (!result) { adapter_progress(); return; }
        break;
    }
    case MD_FS_BUFFER_RECEIVED_RIGHTS: {
        if (!t->receive || !t->receive->ready || !t->buffer.pool || r->regs[1] || r->regs[2]) break;
        struct md_buffer_span span;
        result=md_buffer_span(&t->buffer,&span);
        if (result) break;
        const struct md_fs_buffer_frame *frame=span.data;
        unsigned count=frame->rights.count;
        if (!count || count>253) { result=-EINVAL; break; }
        for (unsigned i=0;i<count;++i) {
            int index=frame->rights.index[i];
            if (index<1 || (unsigned)index>=t->receive->received.count) { result=-EBADF; break; }
            t->receive->outgoing[i]=t->receive->received.fds[index];
        }
        if (result) break;
        result=md_fd_return_vector_begin(&t->buffer_return,t->resources.files,t->receive->outgoing,count,fd_wakeup);
        if (result) break;
        t->buffer_return_waiting=1; buffer_return_progress(t); return;
    }
    case MD_FS_BUFFER_TASK_SEND:
        if (t->phase!=DISPATCHING || t->send || !t->buffer.pool || r->regs[1] || r->regs[2]) break;
        /* EVENT_WAIT: private-table send and exact helper reaping. Caller
         * cancellation aborts that helper; no shared-table cleanup syscall. */
        send_begin(t,r); return;
    case MD_BUFFER_PROBE:
        if (t->entered || t->phase!=IDLE || !t->buffer.pool || t->probe
                || t->capture || t->mapping || r->regs[1] || r->regs[2]) break;
        /* EVENT_WAIT: the production helper's private table is fully reaped
         * before readiness; the launch deadline bounds missing completion. */
        probe_begin(t,r); return;
    case MD_BUFFER_MAPPED:
        if (t->entered || t->phase!=IDLE) break;
        result=md_memory_buffers_mapped(t->memory,r->regs[1],r->regs[2]);
        TRACE("PROBE buffer-mapping pid=%d bytes=%llu result=%ld\n",t->pid,r->regs[2],result);
        break;
    case MD_BUFFER_TAKE:
        if (t->buffer.pool || r->regs[1] || r->regs[2]) break;
        t->buffer_waiting=1; buffer_take(t);
        /* EVENT_WAIT: a task or worker releases a mapped slot. Owned process
         * cancellation ends the wait; no polling or guest retry is required. */
        return;
    case MD_FS_BUFFER_CALL:
        if (!t->buffer.pool || t->buffer_open.fd>=0 || r->regs[2]) break;
        result=md_fs_buffer_begin(buffer_service,t->pid,t->resources.fs,(unsigned)r->regs[1],&t->buffer,&t->buffer_call);
        if (!result) {
            /* EVENT_WAIT: filesystem context admission and exact worker
             * completion; launch cancellation detaches, never replays a call. */
            adapter_progress(); return;
        }
        break;
    case MD_FS_BUFFER_PROC_LINK: {
        if (!t->buffer.pool || t->buffer_open.fd>=0 || t->phase!=DISPATCHING
                || !r->regs[1] || r->regs[1]>INT_MAX || r->regs[2]) break;
        struct thread *target=find_thread((pid_t)r->regs[1]);
        if (!target || !debugger_allowed(t->pid,target->pid)) { result=-EACCES; break; }
        struct md_buffer_span span;
        result=md_buffer_span(&t->buffer,&span);
        if (result) break;
        struct md_fs_buffer_frame *frame=span.data;
        result=md_process_image_link(target->pid,target->process_image,frame->reply.data,PATH_MAX);
        break;
    }
    case MD_FS_BUFFER_EXEC_PREPARE:
        if (!t->buffer.pool || t->buffer_open.fd>=0 || r->regs[1]!=MD_FS_OPEN_IMAGE || r->regs[2]
                || t->phase!=DISPATCHING || t->exec_images[0]>=0 || t->exec_images[1]>=0
                || (t->original.regs[8]!=SYS_execve && t->original.regs[8]!=SYS_execveat)) break;
        result=md_fs_buffer_exec_begin(buffer_service,t->pid,t->resources.fs,&t->buffer,&t->buffer_call);
        if (!result) { adapter_progress(); return; }
        break;
    case MD_FS_BUFFER_EXEC_CANCEL:
        if (r->regs[1] || r->regs[2] || t->phase!=DISPATCHING) break;
        exec_images_release(t); result=0; break;
    case MD_FS_BUFFER_SNAPSHOT_BEGIN:
        if (!t->buffer.pool || t->buffer_open.fd>=0 || r->regs[1]>UINT_MAX || r->regs[2]) break;
        result=md_fs_buffer_snapshot_begin(buffer_service,t->pid,t->resources.fs,
            &t->buffer,(unsigned)r->regs[1],&t->buffer_call);
        if (!result) { adapter_progress(); return; }
        break;
    case MD_FS_BUFFER_SNAPSHOT_APPEND:
    case MD_FS_BUFFER_SNAPSHOT_FINISH:
        if (!snapshot || r->regs[1] || r->regs[2]) break;
        result=md_fs_buffer_snapshot_advance(t->buffer_call,r->regs[0]==MD_FS_BUFFER_SNAPSHOT_FINISH);
        /* EVENT_WAIT: worker appends captured bytes or publishes the result;
         * cancellation retains ownership until the worker completes. */
        if (!result) return;
        md_fs_buffer_cancel(&t->buffer_call);
        break;
    case MD_BUFFER_RELEASE:
        if (r->regs[1] || r->regs[2]) break;
        md_fs_buffer_cancel(&t->buffer_call);
        md_fs_buffer_open_release(&t->buffer_open);
        md_ipc_transport_close(&t->ipc_transport);
        t->buffer_delivered=0;
        result=md_buffer_release(&t->buffer); break;
    case MD_FS_BUFFER_TASK_DONE:
        if (r->regs[2] || t->fd_running) break;
        result=md_fs_buffer_task_finish(&t->buffer_call,(long)r->regs[1]);
        break;
    case MD_BUFFER_IPC_PREPARE: {
        if (!t->buffer.pool || t->buffer_open.fd>=0 || t->phase!=DISPATCHING
                || r->regs[1] || r->regs[2]) break;
        struct md_ipc_request call={.nr=t->original.regs[8]};
        for (unsigned i=0;i<6;++i) call.args[i]=t->original.regs[i];
        struct md_buffer_span span;
        result=!shm_store ? -ENOTSUP : !ipc ? md_ipc_open(shm_store,&ipc) : 0;
        if (!result) result=md_buffer_span(&t->buffer,&span);
        if (!result) result=md_ipc_transport_prepare(ipc,&t->ipc_transport,&call,
            t->ipc_pending!=NULL,span.data,span.size);
        break;
    }
    case MD_BUFFER_SHM_STAT: {
        if (!t->buffer.pool || t->buffer_open.fd>=0 || t->phase!=DISPATCHING || r->regs[2]
                || t->original.regs[8]!=SYS_shmctl
                || ((unsigned)t->original.regs[1]&~IPC_64)!=IPC_STAT
                || r->regs[1]!=t->original.regs[0]) break;
        struct md_buffer_span span;
        result=!shm_store ? -ENOTSUP : !shm ? md_shm_open(shm_store,&shm) : 0;
        if (!result) result=md_buffer_span(&t->buffer,&span);
        if (!result) {
            unsigned long args[4]={r->regs[1],0,0,0};
            result=md_shm_call(shm,t->shm_space,NULL,&t->identity,t->tgid,
                MD_SHM_STAT,args,span.data);
        }
        break;
    }
    case MD_FS_BUFFER_ACK:
        if (r->regs[2] || (long)r->regs[1]>0 || (long)r->regs[1]<-4095) break;
        result=md_fs_buffer_ack(t->buffer_call,(int)r->regs[1]);
        /* EVENT_WAIT: worker commits or rejects reserved records/cursor;
         * process cancellation retires an unconfirmed delivery. */
        if (!result) return;
        md_fs_buffer_cancel(&t->buffer_call);
        break;
    case MD_FS_BUFFER_SENT:
        if (r->regs[2] || (long)r->regs[1]>0 || (long)r->regs[1]<-4095) break;
        result=md_fs_buffer_export_sent(t->buffer_call,(int)r->regs[1]);
        if (!result) { adapter_progress(); return; }
        break;
    case MD_FS_BUFFER_CHANNEL_OBSERVED:
        if (!t->buffer.pool || r->regs[1] || r->regs[2]) break;
        if (t->buffer_call) {
            result=md_fs_buffer_channel_observed(t->buffer_call);
            if (!result) { adapter_progress(); return; }
        } else if (t->buffer_return.checking) {
            struct md_buffer_span span;
            result=md_buffer_span(&t->buffer,&span);
            if (result) break;
            const struct md_fs_buffer_frame *frame=span.data;
            result=md_fd_return_observed(&t->buffer_return,&frame->channel.observation);
            if (!result) { t->buffer_return_waiting=1; buffer_return_progress(t); return; }
        }
        break;
    case MD_FS_BUFFER_RIGHTS_BEGIN: {
        if (!t->buffer.pool || t->buffer_open.fd<0 || t->buffer_delivered || t->buffer_delivery.files.table
                || !(t->buffer_open.flags&O_PATH) || r->regs[1] || r->regs[2]) break;
        struct md_buffer_span span;
        result=md_buffer_span(&t->buffer,&span);
        if (result) break;
        struct md_fs_buffer_frame *frame=span.data;
        if (frame->transfer!=MD_FS_BUFFER_RIGHTS) { result=-EINVAL; break; }
        result=md_fd_return_begin(&t->buffer_return,t->resources.files,t->buffer_open.fd,
            t->buffer_open.origin,t->buffer_open.flags&O_CLOEXEC ? FD_CLOEXEC : 0,
            (void *)frame->receipt,fd_wakeup);
        if (result) break;
        t->buffer_return_waiting=1;
        /* EVENT_WAIT: destination table and shared channel become available;
         * terminal cleanup publishes the exact receipt and drains queued rights. */
        buffer_return_progress(t); return;
    }
    case MD_FS_BUFFER_RIGHTS_READY:
        if (!t->buffer_return.files.table || t->buffer_return.endpoint<0 || t->buffer_return.offered
                || r->regs[1] || r->regs[2]) break;
        t->buffer_return_waiting=1; buffer_return_progress(t); return;
    case MD_FS_BUFFER_RIGHTS_DONE: {
        if (!t->buffer.pool || r->regs[2] || (long)r->regs[1]<-4095) break;
        struct md_buffer_span span;
        result=md_buffer_span(&t->buffer,&span);
        if (result) break;
        const struct md_fs_buffer_frame *frame=span.data;
        result=!t->buffer_return.files.table && (long)r->regs[1]<0 ? (long)r->regs[1]
            : md_fd_return_finish(&t->buffer_return,(long)r->regs[1],frame->receive.token);
        t->buffer_delivered=1;
        break;
    }
    }
    buffer_reply(t,result); adapter_progress();
}
static void fd_progress(void) {
    uint64_t value;
    while (read(fd_ready,&value,sizeof(value))<0 && errno==EINTR) { }
    for (struct thread *t=threads;t;t=t->next)
        if (t->pid) {
            if (!t->fd_running && (md_fd_order_state(&t->fd_order)==MD_RESOURCE_ORDER_READY
                    || md_fs_order_state(&t->fs_order)==MD_RESOURCE_ORDER_READY)) fd_start(t);
            export_progress(t);
        }
    adapter_progress();
}
static int domain_call(struct thread *t, struct user_pt_regs *r, unsigned long cookie) {
    long nr = r->regs[8];
    if (nr == SYS_socket) {
        int error = md_domain_socket_error((int)r->regs[0], (int)r->regs[2]);
        if (error) { return_value(t, r, error); return 1; }
    }
    if (nr == SYS_unshare) {
        CHECK(t->phase == IDLE);
        fd_begin(t,r,0);
        return 1;
    }
    if (nr == SYS_setns) { return_value(t, r, -ENOTSUP); return 1; }
    if (nr == SYS_clone3) { return_value(t, r, -ENOSYS); return 1; }
    if (nr == SYS_clone) {
        if (!md_resources_clone_supported(r->regs[0])) {
            return_value(t, r, -EINVAL); return 1;
        }
        t->cloning = r->regs[0]; return 0;
    }
    if (nr == SYS_chroot) {
        if ((admitted_path || virtual_identity) && !md_identity_may_chroot(&t->identity)) return_value(t, r, -EPERM);
        else domain_path_call(t, r);
        return 1;
    }
    if (!md_domain_restricted(t->resources.fs)) return 0;
    if (t->phase==PROC_OPENING && t->metadata.task_open && cookie==MD_INTERCEPT_NATIVE
            && nr==SYS_openat && (int)r->regs[0]==t->metadata.proc_directory
            && r->regs[1]==abi.proc_open_path && r->regs[2]==(O_RDONLY|O_DIRECTORY|O_CLOEXEC)
            && md_fd_order_state(&t->metadata.files)==MD_RESOURCE_ORDER_RUNNING) {
        resume(t->pid,0); return 1;
    }
    /* Read-only launch identity is independent of the restricted filesystem. */
    if (nr == SYS_uname && cookie == MD_INTERCEPT_DISPATCH) return 0;
    if (nr == SYS_kill || nr == SYS_tgkill || nr == SYS_tkill) {
        long target = (long)r->regs[nr == SYS_tgkill ? 1 : 0];
        struct thread *destination = target > 0 ? find_thread(target) : NULL;
        if (destination && destination->born) {
            resume(t->pid, 0); return 1;
        }
        return_value(t, r, -EPERM); return 1;
    }
    unsigned long args[6];
    for (unsigned i = 0; i < 6; i++) args[i] = r->regs[i];
    if (md_domain_native_call(nr, args)) {
        if (cookie == MD_INTERCEPT_OBSERVE || cookie == MD_INTERCEPT_WATCH || cookie==MD_INTERCEPT_FD) return 0;
        resume(t->pid, 0); return 1;
    }
    int error = cookie == MD_INTERCEPT_DISPATCH ? md_domain_path_error(t->resources.fs) : -EPERM;
    if (nr == SYS_chdir) {
        domain_path_call(t, r); return 1;
    }
    if (error && ++restricted_denials <= 32)
        TRACE("PROBE restricted pid=%d nr=%ld result=%d\n", t->pid, nr, error);
    return_value(t, r, error); return 1;
}
static int descriptor_call(struct thread *t, struct user_pt_regs *r, unsigned long cookie) {
    if (cookie != MD_INTERCEPT_DISPATCH || r->regs[8] != SYS_lseek) return 0;
    CHECK(t->ready && t->phase == IDLE);
    int fd = duplicate_fd(t->pid, (int)r->regs[0]);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return 0; }
    /* A retained open-file description needs no namespace lookup or guest
     * memory access. Never cache FD numbers or resume against a replaceable FD.
     * Original seccomp admission and domain checks precede this operation. */
    off_t result = lseek(fd, (off_t)r->regs[1], (int)r->regs[2]);
    long value = result < 0 ? -errno : result;
    close(fd);
    if (statistics) statistics->native_seeks++;
    return_value(t, r, value); return 1;
}
static int debug_syscall_exit(struct thread *t, const struct user_pt_regs *regs) {
    int active=t->debug_call_active;
    t->debug_call_active=t->debug_adapter=0;
    return active && md_debugger_syscall(debugger,t->pid,regs,0);
}
static void resume(pid_t pid, int sig) {
    struct thread *t = thread(pid);
    if (t->resume_lost) return;
    if (t->terminal_stop) {
        /* No guest instruction or syscall remains after the exit event. Keep
         * ownership until waitpid reaps it, without resuming adapter/debug steps. */
        if (tracee_request(t,PTRACE_CONT,NULL,NULL,"continue-exit")) t->kernel_stopped=0;
        return;
    }
    CHECK(!md_task_registry_publish(tasks, t->pid, t->tgid, &t->identity, &t->resources));
    enum phase phase = t->phase;
    if (t->trace_options_dirty && debugger_options(pid,t->debug_options)) return;
    if (phase!=IDLE && t->debug_call_active) t->debug_adapter=1;
    if (phase==IDLE && t->entered && t->process_image) {
        if (t->debug_call_active && t->debug_adapter) {
            struct user_pt_regs regs;
            if (!registers(pid,&regs)) return;
            if (debug_syscall_exit(t,&regs)) return;
        }
        if (md_debugger_boundary(debugger,pid)) return;
    }
    if (phase==IDLE && t->debug_step_call) {
        t->debug_step_call=0;
        siginfo_t info={.si_signo=SIGTRAP,.si_code=TRAP_TRACE};
        if (md_debugger_stop(debugger,pid,(SIGTRAP<<8)|0x7f,&info,0)) return;
    }
    if (broker) CHECK(!md_broker_task(broker, pid,
        t->ready && phase == IDLE && t->endpoint[0] && !md_domain_restricted(t->resources.fs), RAW_GATE, abi.watch_gate + 4));
    if (!native_trace(t->fd_running || phase == OBSERVING || phase == EXPORT_ENTRY || phase == EXPORT_NOTIFY
            || phase == EXPORT_RETURN || phase == EXECUTING || phase == WATCH_CANCEL
            || phase == WATCH_ENTRY || phase == WATCH_READ || phase==DEBUG_WAIT_ENTRY || phase==DEBUG_WAIT_EXIT
            || phase==IPC_WAIT_ENTRY || phase==IPC_WAITING
            || (phase==IDLE && t->entered && t->process_image
                && (md_debugger_syscall_mode(debugger,pid) || md_debugger_observing(debugger,pid))) ? PTRACE_SYSCALL
                : phase==IDLE && t->entered && md_debugger_step(debugger,pid) ? PTRACE_SINGLESTEP : PTRACE_CONT,
            pid, NULL, (void *)(uintptr_t)sig)) { t->kernel_stopped=0; return; }
    CHECK(errno == ESRCH);
    /* EVENT_WAIT: thread-group exit or exec may win a stopped-thread resume.
     * A terminal stop may still precede reaping. Only the exact exit/exec event
     * releases ownership; the process deadline bounds a missing event. */
    t->resume_lost = 1;
}
static int shield(struct thread *t) {
    uint64_t mask = UINT64_MAX;
    int sync[] = {SIGKILL, SIGSTOP, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGSYS};
    for (unsigned i = 0; i < sizeof(sync) / sizeof(*sync); i++) mask &= ~(UINT64_C(1) << (sync[i] - 1));
    return tracee_request(t, PTRACE_SETSIGMASK, (void *)sizeof(mask), &mask, "shield-signals");
}
static int restore_mask(struct thread *t) {
    return tracee_request(t, PTRACE_SETSIGMASK, (void *)sizeof(t->mask), &t->mask, "restore-mask");
}
static void dispatch(struct thread *t) {
    struct user_pt_regs regs = t->original;
    regs.pc = DISPATCH; regs.sp = t->stack; regs.regs[30] = DONE;
    regs.regs[0] = t->original.regs[8];
    for (unsigned i = 0; i < 6; i++) regs.regs[i + 1] = t->original.regs[i];
    regs.regs[7] = md_domain_scoped(t->resources.fs);
    if (!set_registers(t->pid, &regs)) return;
    t->phase = DISPATCHING; resume(t->pid, 0);
}
static void dispatch_with_stack(struct thread *t) {
    if (!t->stack) t->stack = md_memory_stack_take(t->memory);
    if (t->stack) dispatch(t);
    else {
        struct user_pt_regs regs = t->original; regs.pc = ALLOCATE;
        if (!set_registers(t->pid, &regs)) return;
        t->phase = ALLOCATING; resume(t->pid, 0);
    }
}
static int helper_newborn(pid_t pid) {
    struct thread *t=find_thread(pid);
    if (!t) return 0;
    CHECK(!t->born && t->initial_stop);
    release_thread(t);
    return 1;
}
static void mapping_complete(void *context, struct md_task_helper_result result) {
    long value=result.value;
    CHECK(result.descriptor==-1);
    struct mapping_owner *owner=context;
    if (value>=0) {
        unsigned long args[4]={(unsigned long)value};
        CHECK(!md_shm_call(shm,owner->space,&owner->pending,NULL,owner->group,MD_SHM_ATTACHED,args,NULL));
    } else CHECK(!md_shm_abort(shm,&owner->pending));
    CHECK(!md_shm_space_release(shm,owner->space));
    if (owner->request.source>=0) close(owner->request.source);
    if (owner->order.queue && md_resource_order_cancel(&owner->order)==1)
        CHECK(!md_resource_order_complete(&owner->order));
    md_memory_release(owner->memory);
    struct thread *t=owner->caller ? find_thread(owner->caller) : NULL;
    if (t && t->mapping==owner) {
        struct user_pt_regs regs=owner->continuation;
        regs.pc+=4; regs.regs[0]=value;
        t->mapping=NULL; t->kernel_stopped=1;
        if (set_registers(t->pid,&regs)) resume(t->pid,0);
    }
    free(owner);
}
static void mapping_start(struct thread *t) {
    struct mapping_owner *owner=t->mapping;
    if (md_resource_order_state(&owner->order)!=MD_RESOURCE_ORDER_READY) return;
    CHECK(!md_resource_order_start(&owner->order));
    t->terminal_observation=1; t->trace_options_dirty=1;
    int error=debugger_options(t->pid,t->debug_options);
    if (!error) {
        struct md_task_helper_request request={.kind=MD_TASK_HELPER_MAP,.mapping=owner->request};
        error=md_task_helper_begin(helpers,t->pid,t->tgid,&owner->continuation,&abi,
            owner->memory,&t->buffer,&request,mapping_complete,owner);
        if (!error) {
            owner->started=1; t->kernel_stopped=0;
            close(owner->request.source); owner->request.source=-1;
        }
    }
    if (error) mapping_complete(owner,(struct md_task_helper_result){.value=error,.descriptor=-1});
}
static void mapping_begin(struct thread *t, struct user_pt_regs *regs) {
    long error=!shm_store ? -ENOTSUP : !shm ? md_shm_open(shm_store,&shm) : 0;
    if (!error && (t->phase!=DISPATCHING || t->original.regs[8]!=SYS_shmat
            || t->mapping || !t->buffer.pool || t->buffer_call || t->ipc_transport.packet)) error=-EPERM;
    unsigned flags=t->original.regs[2];
    uintptr_t address=t->original.regs[1];
    if (flags&SHM_RND) address&=~(md_page_size-1);
    if (!error && ((flags&~(SHM_RDONLY|SHM_RND|SHM_EXEC)) || (address&(md_page_size-1)))) error=-EINVAL;
    struct mapping_owner *owner=error ? NULL : calloc(1,sizeof(*owner));
    if (!error && !owner) error=-ENOMEM;
    int fd=-1;
    if (!error) {
        *owner=(struct mapping_owner){.caller=t->pid,.group=t->tgid,.continuation=*regs,
            .request={.source=-1}};
        owner->space=md_shm_space_fork(shm,t->shm_space,1);
        owner->memory=md_memory_fork(t->memory,1);
        if (!owner->space || !owner->memory) error=-ENOMEM;
    }
    if (!error) {
        unsigned long args[4]={t->original.regs[0],flags};
        fd=(int)md_shm_call(shm,owner->space,&owner->pending,&t->identity,t->tgid,MD_SHM_OPEN,args,NULL);
        if (fd<0) error=fd;
    }
    if (!error) {
        owner->request=(struct md_task_mapping_request){.source=fd,.address=address,
            .size=md_shm_pending_size(owner->pending),.flags=MAP_SHARED|(address ? MAP_FIXED_NOREPLACE : 0),
            .protection=PROT_READ|((flags&SHM_RDONLY) ? 0 : PROT_WRITE)|((flags&SHM_EXEC) ? PROT_EXEC : 0)};
        fd=-1;
        error=md_memory_order_begin(owner->memory,&owner->order,fd_wakeup);
        if (error>=0) { t->mapping=owner; mapping_start(t); return; }
    }
    if (fd>=0) close(fd);
    if (!error) return;
    t->mapping=NULL;
    if (owner) {
        CHECK(!md_shm_abort(shm,&owner->pending));
        CHECK(!md_shm_space_release(shm,owner->space));
        if (owner->request.source>=0) close(owner->request.source);
        md_memory_release(owner->memory);
        free(owner);
    }
    regs->pc+=4; regs->regs[0]=error;
    if (set_registers(t->pid,regs)) resume(t->pid,0);
}
static void memory_start(struct thread *t) {
    if (md_resource_order_state(&t->memory_order)!=MD_RESOURCE_ORDER_READY) return;
    CHECK(!md_resource_order_start(&t->memory_order));
    struct user_pt_regs regs=t->original;
    if (t->memory_action==MEMORY_DETACH) {
        if (!tracee_request(t,PTRACE_GETSIGMASK,(void *)sizeof(t->mask),&t->mask,"memory-mask")
                || !shield(t) || !skip(t->pid)) return;
        dispatch_with_stack(t);
    } else if (t->memory_action==MEMORY_FORK) {
        t->phase=IDLE;
        fd_begin(t,&regs,MD_INTERCEPT_FD);
    } else {
        int overlap=md_shm_intersects(t->shm_space,regs.regs[0],regs.regs[1]);
        if (regs.regs[8]==SYS_mremap && (regs.regs[3]&MREMAP_FIXED))
            overlap|=md_shm_intersects(t->shm_space,regs.regs[4],regs.regs[2]);
        if (overlap && regs.regs[8]==SYS_mremap) {
            CHECK(!md_resource_order_complete(&t->memory_order)); t->memory_action=0;
            t->phase=IDLE; return_value(t,&regs,-ENOTSUP);
        } else { t->phase=OBSERVING; resume(t->pid,0); }
    }
}
static void memory_begin(struct thread *t, const struct user_pt_regs *regs, enum memory_action action) {
    CHECK(!t->memory_order.queue && !t->memory_action);
    t->original=*regs; t->memory_action=action; t->phase=MEMORY_WAIT;
    CHECK(md_memory_order_begin(t->memory,&t->memory_order,fd_wakeup)>=0);
    /* EVENT_WAIT: address-space publication precedes competing unmap/fork;
     * task exit cancels its queued turn. fd_ready drives progress, not polling. */
    memory_start(t);
}
static void ipc_wait_complete(struct thread *t) {
    struct user_pt_regs returned;
    if (!registers(t->pid,&returned) || !shield(t)) return;
    ipc_unwatch(t);
    long value=(long)returned.regs[0];
    int interrupted=value<=-512 && value>=-516;
    if (value<0 && !(t->ipc_waking && interrupted)) t->ipc_cancel=interrupted ? -EINTR : value;
    t->ipc_waking=0;
    dispatch_with_stack(t);
}
static int interrupted_operation(struct thread *t) {
    if (t->phase==MEMORY_WAIT || t->mapping) return 1;
    /* EVENT_WAIT: INTERRUPT cancels the exact notification. Under SYSCALL the
     * acknowledgement is a syscall-exit stop; under CONT it is EVENT_STOP. */
    if (t->phase==EXPORT_CANCEL) { export_start(t); return 1; }
    if (t->phase==PROC_CANCEL) { proc_query_start(t); return 1; }
    if (t->phase==IPC_WAITING && t->ipc_waking) { ipc_wait_complete(t); return 1; }
    if (t->phase!=DELEGATE_CANCEL) return 0;
    const struct seccomp_notif *q=&t->metadata.request;
    CHECK(ioctl(listener,SECCOMP_IOCTL_NOTIF_ID_VALID,&q->id)==-1 && errno==ENOENT);
    struct user_pt_regs regs;
    if (!registers(t->pid,&regs)) return 1;
    regs.pc=q->data.instruction_pointer; regs.regs[8]=q->data.nr;
    for (unsigned i=0;i<6;i++) regs.regs[i]=q->data.args[i];
    t->original=regs; calls++; t->calls++;
    if (!tracee_request(t,PTRACE_GETSIGMASK,(void *)sizeof(t->mask),&t->mask,"get-mask") || !shield(t)) return 1;
    if (!t->stack) t->stack=md_memory_stack_take(t->memory);
    if (t->stack) dispatch(t);
    else {
        regs.pc=ALLOCATE;
        if (set_registers(t->pid,&regs)) { t->phase=ALLOCATING; resume(t->pid,0); }
    }
    return 1;
}
static void drain(void) {
    struct signalfd_siginfo info;
    while (read(signal_fd, &info, sizeof(info)) == sizeof(info)) {
        if (info.ssi_signo != SIGCHLD && !cancelling) {
            TRACE("PROBE cancelled signal=%u\n", info.ssi_signo);
            result = 128 + info.ssi_signo; cancelling = 1;
            cancellation_deadline = md_event_now() + 2000000000LL;
            CHECK(!md_process_signal_children(SIGTERM));
        }
    }
    CHECK(errno == EAGAIN);
}
static pid_t wait_event(int *status, struct rusage *usage, int64_t deadline) {
    for (;;) {
        pid_t pid = wait4(-1, status, __WALL | WNOHANG, md_debugger_active(debugger) ? usage : NULL);
        if (pid > 0) return pid;
        CHECK(pid == 0 || errno == EINTR);
        /* EVENT_WAIT: ptrace stop/exit or cancellation via signalfd; expiry
         * fails and cancels the owned tree, never counts as readiness. */
        struct pollfd events[] = {{signal_fd, POLLIN, 0}, {broker ? -1 : listener, POLLIN, 0},
            {md_fs_worker_fd(filesystem), POLLIN, 0}, {fd_ready,POLLIN,0}, {ipc_events,POLLIN,0}};
        int64_t bound = cancelling ? cancellation_deadline : deadline;
        long outcome = md_event_wait(events, 5, bound);
        if (outcome == -ETIMEDOUT && cancelling == 1) {
            /* EVENT_WAIT: graceful cancellation expired; drain killed children
             * for at most ten seconds before reporting incomplete cleanup. */
            cancelling = 2; cancellation_deadline = md_event_now() + 10000000000LL;
            CHECK(!md_process_signal_children(SIGKILL)); continue;
        }
        if (outcome < 0) {
            if (diagnostics) {
                for (struct thread *t=threads;t;t=t->next) if (t->pid)
                    TRACE("PROBE pending pid=%d phase=%d fdJob=%u fdRunning=%d files=%d fs=%d bufferWaiting=%d\n",
                        t->pid,t->phase,t->fd_job,t->fd_running,md_fd_order_state(&t->fd_order),
                        md_fs_order_state(&t->fs_order),t->buffer_waiting);
                md_fs_buffer_describe(buffer_service,STDERR_FILENO);
            }
            errno = (int)-outcome;
        }
        CHECK(outcome >= 0);
        if (events[0].revents) { drain(); continue; }
        if (events[2].revents) { CHECK(!md_fs_worker_dispatch(filesystem)); adapter_progress(); }
        if (events[3].revents) fd_progress();
        if (events[4].revents) ipc_events_ready();
        if (events[1].revents & POLLIN) external_stat();
        if (events[1].revents & POLLHUP) { close(listener); listener = -1; }
    }
}
int main(int argc, char **argv) {
    CHECK(argc >= 2 && md_launch_identity(getuid(), geteuid(), getgid(), getegid()));
    md_page_size = (size_t)sysconf(_SC_PAGESIZE);
    CHECK(md_page_size >= 4096 && md_page_size <= 65536 && !(md_page_size & (md_page_size - 1)));
    int argument = 1;
    int command_access = 0, command_owner = -1;
    char command_directory[PATH_MAX];
    long seconds = 0;
    while (argument < argc) {
        if (!strcmp(argv[argument], "--diagnostics")) diagnostics = 1;
        else if (!strcmp(argv[argument], "--magicdesk") && !command_access) command_access = 1;
        else if (!strcmp(argv[argument], "--statistics")) {
            CHECK(!statistics);
            statistics = calloc(1, sizeof(*statistics));
            CHECK(statistics);
        } else break;
        argument++;
    }
    if (argument < argc && !strcmp(argv[argument], "--deadline-seconds")) {
        CHECK(argument + 2 < argc);
        char *end;
        seconds = strtol(argv[argument + 1], &end, 10);
        CHECK(!*end && seconds >= 1 && seconds <= 3600);
        argument += 2;
    }
    setvbuf(stderr, NULL, _IONBF, 0);
    struct md_debugger_host debug_host={.parent=debugger_parent,.group=debugger_group,.uid=debugger_uid,.allowed=debugger_allowed,
        .attachable=debugger_attachable,.observe=debugger_observe,.interrupt=debugger_interrupt,.options=debugger_options,
        .listen=debugger_listen,.usage=debugger_usage,.wait_probe=debugger_wait_probe,
        .complete=debugger_complete,.resume=resume};
    debugger=md_debugger_create(&debug_host); CHECK(debugger);
    if (argument < argc && !strcmp(argv[argument], "--admit-elf")) {
        CHECK(argument + 2 < argc);
        admitted_path = argv[argument + 1]; argument += 2;
        CHECK(admitted_path[0] == '/');
    }
    const char *selected_user = NULL, *selected_groups = NULL;
    launch_identity = md_identity_new(getuid(), getgid());
    tasks = md_task_registry_create(); CHECK(tasks);
    struct md_identity owner = md_identity_new(getuid(), getgid());
    CHECK(!md_task_registry_publish(tasks, getpid(), getpid(), &owner, NULL));
    if (argument < argc && !strcmp(argv[argument], "--user")) {
        CHECK(argument + 2 < argc);
        selected_user = argv[argument + 1]; virtual_identity = 1; argument += 2;
    } else {
        int count = getgroups(0, NULL); CHECK(count >= 0);
        gid_t *groups = count ? malloc((size_t)count * sizeof(*groups)) : NULL;
        CHECK(!count || groups);
        CHECK(getgroups(count, groups) == count && !md_identity_groups(&launch_identity, groups, (unsigned)count));
        free(groups);
    }
    if (argument < argc && !strcmp(argv[argument], "--groups")) {
        CHECK(virtual_identity && argument + 2 < argc);
        selected_groups = argv[argument + 1]; argument += 2;
    }
    struct md_fs_attachment attachments[MD_FS_MOUNTS_MAX];
    unsigned attachment_count = 0;
    while (argument < argc && (!strcmp(argv[argument], "--bind") || !strcmp(argv[argument], "--bind-ro"))) {
        CHECK(argument+2 < argc && attachment_count < MD_FS_MOUNTS_MAX);
        attachments[attachment_count++] = (struct md_fs_attachment){
            .source=argv[argument+1], .target=argv[argument+2], .readonly=!strcmp(argv[argument], "--bind-ro")};
        argument += 3;
    }
    const char *store = NULL, *endpoint = NULL;
    if (argument < argc && !strcmp(argv[argument], "--store")) {
        CHECK(argument + 4 < argc && !strcmp(argv[argument + 2], "--endpoint"));
        store = argv[argument + 1]; endpoint = argv[argument + 3]; argument += 4;
        shm_store = store;
    }
    if (selected_user) {
        uint32_t uid, gid;
        if (!md_guest_user_parse(selected_user, &uid, &gid)) launch_identity = md_identity_new(uid, gid);
        else {
            struct md_inode_store *accounts = NULL;
            CHECK(store && !md_inode_store_open(store, 0, &accounts));
            struct md_filesystem view = {.store=accounts};
            CHECK(!md_fs_mounts_open(&view, attachments, attachment_count));
            int resolved = md_guest_user_resolve(&view, selected_user, &launch_identity);
            md_fs_mounts_close(&view); md_inode_store_close(accounts);
            if (resolved) { errno = -resolved; CHECK(!resolved); }
        }
    }
    if (selected_groups) {
        const char *p = selected_groups;
        uint32_t *groups = malloc(MD_IDENTITY_GROUPS_MAX * sizeof(*groups)); CHECK(groups);
        unsigned count = 0;
        while (*p) {
            CHECK(count < MD_IDENTITY_GROUPS_MAX && *p >= '0' && *p <= '9');
            uint64_t value = 0;
            do { value = value * 10 + (unsigned)(*p++ - '0'); CHECK(value < UINT32_MAX); }
            while (*p >= '0' && *p <= '9');
            groups[count++] = (uint32_t)value;
            if (*p) { CHECK(*p++ == ',' && *p); }
        }
        CHECK(!md_identity_groups(&launch_identity, groups, count));
        free(groups);
    }
    int inherited_no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    CHECK(inherited_no_new_privs >= 0);
    launch_identity.no_new_privs = (unsigned)inherited_no_new_privs;
    CHECK(argument < argc);
    if (command_access) {
        CHECK(attachment_count < MD_FS_MOUNTS_MAX);
        command_owner = md_guest_command_access(store, &attachments[attachment_count], command_directory);
        if (command_owner < 0) { errno = -command_owner; perror("MagicDesk command access"); return 125; }
        ++attachment_count;
    } else {
        unsetenv("MAGICDESK_COMMAND_ENDPOINT"); unsetenv("MAGICDESK_COMMAND_BUILD");
    }
    struct md_process_signals inherited;
    CHECK(md_process_signals_open(&inherited) >= 0);
    signal_fd = inherited.fd;
    CHECK(!prctl(PR_SET_CHILD_SUBREAPER, 1) && !atexit(cleanup));
    int channel[2]; CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channel));
    int tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    int headless = tty < 0;
    if (tty >= 0) close(tty);
    pid_t parent = getpid();
    leader = fork(); CHECK(leader >= 0);
    if (!leader) {
        if (command_owner >= 0) close(command_owner);
        close(channel[0]); close(signal_fd);
        CHECK(!md_process_signals_restore(&inherited));
        CHECK(!prctl(PR_SET_PDEATHSIG, SIGKILL) && getppid() == parent);
        /* Headless group signals belong to the guest tree, not its guardians.
         * A controlling PTY retains its caller's foreground job-control group. */
        if (headless) CHECK(!setpgid(0, 0));
        char byte = 'r'; CHECK(write(channel[1], &byte, 1) == 1);
        /* EVENT_WAIT: supervisor's attach acknowledgement; the outer timeout cancels. */
        CHECK(read(channel[1], &byte, 1) == 1 && byte == 'g'); close(channel[1]);
        execv(argv[argument], argv + argument); _exit(127);
    }
    thread(leader)->born = 1; close(channel[1]);
    int keep[] = {signal_fd, channel[0], command_owner};
    CHECK(!md_process_close_fds(keep, command_owner >= 0 ? 3 : 2));
    fd_exchanges=md_fd_exchanges_create(); CHECK(fd_exchanges);
    const struct md_task_helper_callbacks helper_callbacks={.trace=native_trace,.newborn=helper_newborn};
    helpers=md_task_helpers_new(&helper_callbacks); CHECK(helpers);
    fd_ready=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK); CHECK(fd_ready>=0);
    CHECK(!md_resource_wakeup_create(fd_ready,&fd_wakeup));
    /* EVENT_WAIT: child readiness precedes attaching; timeout cancels this tree. */
    CHECK(md_event_wait_fd(channel[0], POLLIN, md_event_now() + 5000000000LL) >= 0);
    char byte; CHECK(read(channel[0], &byte, 1) == 1 && byte == 'r');
    CHECK(!native_trace(PTRACE_SEIZE, leader, NULL, (void *)trace_options));
    if (store) {
        /* The guest was forked with the caller's mask. Only the native owner
         * uses zero; creation requests already contain the guest's masked mode. */
        umask(0);
        CHECK(!md_task_registry_publish(tasks, leader, leader, &thread(leader)->identity, NULL));
        int startup = md_fs_worker_start(store, endpoint, admitted_path, tasks, fd_exchanges, attachments, attachment_count, statistics != NULL, &filesystem);
        if (startup) errno = -startup;
        CHECK(!startup);
        struct md_mount_namespace *mounts=md_fs_worker_mounts(filesystem);
        struct md_task_resources owner_resources={.mounts=mounts};
        CHECK(!md_task_registry_publish(tasks,getpid(),getpid(),&owner,&owner_resources));
        CHECK(!md_resources_init(&thread(leader)->resources,mounts));
        CHECK(!md_task_registry_publish(tasks,leader,leader,&thread(leader)->identity,&thread(leader)->resources));
        broker = md_broker_create(filesystem, statistics != NULL, delegated_notification); CHECK(broker);
        buffer_service=md_fs_buffer_service_new(filesystem,tasks,fd_wakeup,buffer_complete); CHECK(buffer_service);
        const char *program = "", *cwd = "/";
        for (int i = argument+1; i+1 < argc; ++i) {
            if (!strcmp(argv[i], "--cwd")) cwd = argv[++i];
            else if (!strcmp(argv[i], "--namespace") && i+2 < argc) { program = argv[i+2]; break; }
        }
        CHECK(!md_launch_register(&registration, store, program, cwd, launch_identity.uid.effective));
    }
    byte = 'g'; CHECK(write(channel[0], &byte, 1) == 1); close(channel[0]);
    int64_t deadline = seconds ? md_event_now() + seconds * 1000000000LL : INT64_MAX;
    while (live || md_fs_buffer_children(buffer_service) || md_task_helpers_count(helpers)) {
        int status; struct rusage usage; pid_t pid = wait_event(&status, &usage, deadline);
        int opened=md_fs_buffer_child(buffer_service,pid,status);
        CHECK(opened>=0);
        if (opened) continue;
        int mapped=md_task_helper_event(helpers,pid,status);
        if (mapped<0) errno=-mapped;
        CHECK(mapped>=0);
        if (mapped) { adapter_progress(); continue; }
        struct thread *t = thread(pid);
        t->kernel_stopped=1;
        if (md_debugger_active(debugger)) t->usage=usage;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            if (pid == leader && !cancelling) result = code;
            if (code) TRACE("PROBE exit pid=%d status=%d ready=%d calls=%u\n", pid, code, t->ready, t->calls);
            md_debugger_exit(debugger,pid,status);
            release_thread(t); continue;
        }
        CHECK(WIFSTOPPED(status));
        if (statistics) statistics->stops++;
        unsigned event = (unsigned)status >> 16;
        CHECK(!t->resume_lost || event==PTRACE_EVENT_EXEC || event==PTRACE_EVENT_EXIT);
        int sig = WSTOPSIG(status);
        if (event==PTRACE_EVENT_EXIT) {
            /* ESRCH invalidates the preceding stop, not this newly observed
             * terminal stop. Registers may be inspected here, never fabricated. */
            TRACE("PROBE terminal-stop pid=%d lost=%d\n",pid,t->resume_lost);
            t->resume_lost=0; t->terminal_stop=1;
            if (t->fd_running && t->fd_capture) {
                struct user_pt_regs terminal;
                if (!registers(pid,&terminal)) continue;
                long publication;
                if (terminal.pc==abi.capture_gate && terminal.regs[8]==SYS_openat
                        && md_fd_mutation_terminal_open(&t->fd_mutation,terminal.regs[0],&publication))
                    fd_finish(t,publication);
            }
            adapter_discard(t);
            unsigned long message;
            if (!tracee_request(t,PTRACE_GETEVENTMSG,NULL,&message,"debug-exit")) continue;
            if (!md_debugger_event(debugger,pid,event,message)) resume(pid,0);
        } else if (event==PTRACE_EVENT_VFORK_DONE) {
            unsigned long child;
            if (!tracee_request(t,PTRACE_GETEVENTMSG,NULL,&child,"vfork-complete")) continue;
            if (!md_debugger_event(debugger,pid,event,child)) resume(pid,0);
        } else if (event == PTRACE_EVENT_EXEC) {
            /* A non-leader exec replaces the task behind the leader's PID. */
            md_broker_forget(broker, pid);
            unsigned long old; CHECK(!native_trace(PTRACE_GETEVENTMSG, pid, NULL, &old));
            t->debug_exec_old=(pid_t)old;
            struct thread *executing=old && old!=(unsigned)pid ? find_thread((pid_t)old) : t;
            if (executing) {
                if (executing->fd_running) fd_finish(executing,0);
                else CHECK(!md_resources_exec(&executing->resources));
            }
            if (old && old != (unsigned)pid) {
                md_debugger_rekey(debugger,(pid_t)old,pid);
                struct thread *former = find_thread((pid_t)old);
                if (former) {
                    t->terminal_observation=former->terminal_observation;
                    t->debug_options=former->debug_options;
                    t->trace_options_dirty=former->trace_options_dirty;
                    release_operation(t);
                    CHECK(!md_resources_unshare_finish(ipc, &t->resources, &t->resource_change, -ECANCELED));
                    CHECK(!md_resources_release(ipc, &t->resources));
                    t->resources = former->resources;
                    former->resources = (struct md_task_resources){0};
                    exec_images_release(t);
                    memcpy(t->exec_images,former->exec_images,sizeof(t->exec_images));
                    former->exec_images[0]=former->exec_images[1]=-1;
                    md_identity_release(&t->identity);
                    t->identity = md_identity_copy(&former->identity);
                    md_watch_activation_release(t->watch_activation);
                    t->watch_activation = former->watch_activation; former->watch_activation = NULL;
                    memcpy(t->endpoint, former->endpoint, sizeof(t->endpoint));
                    release_thread(former);
                }
            }
            fd_discard(t);
            adapter_discard(t);
            t->exec_images_ready=t->exec_images[0]>=0;
            md_memory_stack_return(t->memory, t->stack);
            CHECK(!md_shm_space_release(shm,t->shm_space));
            t->shm_space = md_shm_space_new(); CHECK(t->shm_space);
            ipc_unwatch(t);
            CHECK(!md_ipc_cancel(ipc,&t->ipc_pending)); t->ipc_cancel=t->ipc_waking=0;
            md_ipc_transport_close(&t->ipc_transport);
            md_memory_release(t->memory); t->memory = md_memory_new(); CHECK(t->memory);
            t->phase = IDLE; t->stack = 0; t->ready = 0; t->resume_lost = 0; t->terminal_stop=0; images++;
            t->mapped_image = 0; t->entered = 0;
            t->process_image=0;
            resume(pid, 0); adapter_progress();
        } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            unsigned long child;
            if (!tracee_request(t, PTRACE_GETEVENTMSG, NULL, &child, "birth-event")) continue;
            struct thread *c = thread(child);
            CHECK(!c->born);
            c->born = 1; c->ready = t->ready;
            c->parent=t->pid; c->entered=t->entered;
            c->process_image=t->process_image;
            c->debug_call_active=t->debug_call_active;
            c->debug_options=t->debug_options;
            c->terminal_observation=t->terminal_observation;
            c->shm_filter = t->shm_filter;
            md_identity_release(&c->identity);
            c->identity = md_identity_copy(&t->identity);
            c->tgid = t->cloning & CLONE_THREAD ? t->tgid : c->pid;
            CHECK(!md_shm_space_release(shm,c->shm_space));
            c->shm_space = md_shm_space_fork(shm,t->shm_space,!!(t->cloning & CLONE_VM)); CHECK(c->shm_space);
            CHECK(!md_resources_release(ipc, &c->resources));
            if (t->resources.fs) CHECK(!md_resources_fork(&t->resources, t->cloning, &c->resources));
            if (t->fd_running) fd_finish(t,(long)child);
            md_memory_release(c->memory);
            c->memory = md_memory_fork(t->memory, !!(t->cloning & CLONE_VM)); CHECK(c->memory);
            md_watch_activation_release(c->watch_activation);
            c->watch_activation = md_watch_activation_fork(t->watch_activation, !!(t->cloning & CLONE_THREAD));
            CHECK(c->watch_activation);
            t->cloning = 0;
            memcpy(c->endpoint, t->endpoint, sizeof(c->endpoint));
            if (cancelling) CHECK(!md_process_signal_children(cancelling == 1 ? SIGTERM : SIGKILL));
            /* EVENT_WAIT: a newborn stop and its parent's birth event can
             * arrive in either order. Both must precede the child's resume. */
            int debug_birth=md_debugger_birth(debugger,pid,c->pid,event); CHECK(debug_birth>=0);
            c->debug_birth=debug_birth;
            if (c->initial_stop) {
                if (!c->debug_birth || !md_debugger_newborn(debugger,c->pid)) resume(c->pid,0);
                c->debug_birth=0;
            }
            if (!debug_birth) resume(pid, 0);
        } else if (event == PTRACE_EVENT_STOP) {
            if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                if (t->phase==IDLE && md_debugger_stop(debugger,pid,status,NULL,0)) continue;
                /* EVENT_WAIT: preserve the kernel group-stop until SIGCONT or
                 * exit. CONT here would silently discard the application's stop.
                 * Keep the operation phase intact across the listening state. */
                t->listening = 1; group_stops++;
                if (native_trace(PTRACE_LISTEN, pid, NULL, NULL)) {
                    CHECK(errno == ESRCH); t->resume_lost = 1;
                } else t->kernel_stopped=0;
                continue;
            }
            int wake = t->listening;
            if (wake) { CHECK(sig == SIGTRAP); t->listening = 0; group_wakes++; }
            if (interrupted_operation(t)) continue;
            if (wake) { resume(pid, 0); continue; }
            if (t->phase==IDLE && t->entered && md_debugger_boundary(debugger,pid)) {
                t->initial_stop=1; continue;
            }
            CHECK(sig == SIGTRAP);
            if (t->initial_stop) {
                /* SIGCONT can clear a pending group-stop before this tracee
                 * reports it. The kernel then reports EVENT_STOP/SIGTRAP without
                 * an earlier LISTEN. This is not a second newborn stop. */
                CHECK(t->born); raced_wakes++; resume(pid, 0); continue;
            }
            t->initial_stop = 1;
            if (t->born) {
                if (!t->debug_birth || !md_debugger_newborn(debugger,pid)) resume(pid,0);
                t->debug_birth=0;
            }
        }
        else if (event == PTRACE_EVENT_SECCOMP) {
            unsigned long cookie;
            if (!tracee_request(t, PTRACE_GETEVENTMSG, NULL, &cookie, "seccomp-event")) continue;
            struct user_pt_regs regs;
            if (!registers(pid, &regs)) continue;
            if (cookie==MD_INTERCEPT_TASK) { return_value(t,&regs,-EPERM); continue; }
            if (regs.regs[8]==SYS_ptrace && t->phase==IDLE)
                TRACE("PROBE guest debugger caller=%d request=%llu target=%llu address=%#llx data=%#llx\n",
                    pid,regs.regs[0],regs.regs[1],regs.regs[2],regs.regs[3]);
            if (t->phase==IDLE && (regs.regs[8]==SYS_ptrace || regs.regs[8]==SYS_wait4)
                    && md_debugger_call(debugger,pid,&regs)) continue;
            if (statistics) {
                if (regs.regs[8] < 512) statistics->calls[regs.regs[8]].trace++;
                else statistics->unknown++;
            }
            if (regs.regs[8] == SYS_prctl && regs.regs[0] == MD_GUEST_WATCH_FILTER
                    && regs.pc == RAW_GATE && t->phase == DISPATCHING) {
                long value = regs.regs[2] == 0 ? md_watch_activation_has(t->watch_activation, (unsigned)regs.regs[1])
                    : regs.regs[2] == 1 ? md_watch_activation_mark(t->watch_activation, (unsigned)regs.regs[1]) : -EINVAL;
                return_value(t, &regs, value); continue;
            }
            if (regs.regs[8] == SYS_prctl && regs.regs[0] == MD_GUEST_SHM_FILTER
                    && regs.pc == RAW_GATE && t->phase == DISPATCHING) {
                long value = regs.regs[1] == 0 ? t->shm_filter : regs.regs[1] == 1 ? 0 : -EINVAL;
                if (regs.regs[1] == 1) for (struct thread *member = threads; member; member = member->next)
                    if (member->pid && member->tgid == t->tgid) member->shm_filter = 1;
                return_value(t,&regs,value); continue;
            }
            if (identity_call(t, &regs, cookie)) continue;
            if (domain_call(t, &regs, cookie)) continue;
            if (cookie==MD_INTERCEPT_FD || cookie==MD_INTERCEPT_CWD || cookie==MD_INTERCEPT_CAPTURE) {
                if (cookie==MD_INTERCEPT_FD && regs.regs[8]==SYS_clone && t->shm_filter
                        && !(regs.regs[0]&CLONE_VM)) {
                    memory_begin(t,&regs,MEMORY_FORK); continue;
                }
                int delivery=cookie==MD_INTERCEPT_CAPTURE && (int)regs.regs[4]==MD_FS_BUFFER_SOURCE;
                int capture_flags=delivery ? t->buffer_open.fd>=0
                    && regs.regs[2]==(O_PATH|(t->buffer_open.flags&(O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW)))
                    && regs.regs[1]==md_memory_buffer_address(t->memory,&t->buffer)+offsetof(struct md_fs_buffer_frame,source)
                    : (regs.regs[2]==(O_PATH|O_CLOEXEC) || regs.regs[2]==(O_PATH|O_DIRECTORY|O_CLOEXEC))
                        && ((int)regs.regs[4]>=0 || (int)regs.regs[4]==AT_FDCWD);
                if (cookie==MD_INTERCEPT_CAPTURE
                        && (regs.pc!=abi.capture_gate || regs.regs[8]!=SYS_openat
                            || (int)regs.regs[0]!=AT_FDCWD || regs.regs[3]
                            || !capture_flags)) {
                    return_value(t,&regs,-EINVAL); continue;
                }
                fd_begin(t,&regs,(unsigned)cookie); continue;
            }
            if (cookie == MD_INTERCEPT_MEMORY) {
                CHECK(t->phase == IDLE);
                memory_begin(t,&regs,MEMORY_KERNEL); continue;
            }
            if (descriptor_call(t, &regs, cookie)) continue;
            if (cookie == MD_INTERCEPT_WATCH) {
                CHECK(t->ready && t->phase == IDLE);
                t->original = regs;
                t->watch_wait = 0;
                if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(t->mask), &t->mask, "watch-mask")
                        || !shield(t) || !skip(pid)) continue;
                t->phase = WATCH_CANCEL; resume(pid, 0); continue;
            }
            if (cookie == MD_INTERCEPT_NATIVE) {
                if (t->phase==IDLE && md_debugger_step(debugger,pid)) {
                    t->debug_step_call=1; t->original=regs; t->phase=OBSERVING;
                }
                if (diagnostics && statistics && t->phase == IDLE && regs.regs[8] < 512
                        && statistics->calls[regs.regs[8]].trace <= 4) {
                    TRACE("PROBE native arguments pid=%d nr=%llu args=%#llx,%#llx,%#llx,%#llx,%#llx,%#llx\n",
                        pid,regs.regs[8],regs.regs[0],regs.regs[1],regs.regs[2],regs.regs[3],regs.regs[4],regs.regs[5]);
                    t->original=regs; t->phase=OBSERVING;
                }
                resume(pid, 0); continue;
            }
            if (cookie == MD_INTERCEPT_EXEC) {
                CHECK(t->phase == DISPATCHING);
                if (!restore_mask(t)) continue;
                t->phase = EXECUTING; fd_begin(t,&regs,0); continue;
            }
            if (cookie == MD_INTERCEPT_OBSERVE) {
                CHECK(t->ready && t->phase == IDLE);
                t->filter_length = describe_filter(pid, &regs);
                t->original = regs; t->phase = OBSERVING;
                resume(pid, 0); continue;
            }
            if (cookie != MD_INTERCEPT_DISPATCH || !t->ready || t->phase != IDLE)
                TRACE("PROBE unexpected TRACE pid=%d cookie=%lu ready=%d phase=%d pc=%#llx nr=%llu adapted=%llu\n",
                    pid, cookie, t->ready, t->phase, regs.pc, regs.regs[8], t->original.regs[8]);
            CHECK(cookie == MD_INTERCEPT_DISPATCH && t->ready && t->phase == IDLE);
            t->original = regs; calls++; t->calls++;
            t->debug_step_call=md_debugger_step(debugger,pid);
            if (regs.regs[8]==SYS_shmdt) { memory_begin(t,&regs,MEMORY_DETACH); continue; }
            if (!tracee_request(t, PTRACE_GETSIGMASK, (void *)sizeof(t->mask), &t->mask, "get-mask")
                    || !shield(t) || !skip(pid)) continue;
            dispatch_with_stack(t);
        } else if (!event && sig == (SIGTRAP | 0x80)) {
            if (t->fd_running) {
                struct user_pt_regs returned;
                if (!registers(pid,&returned)) continue;
                long nr=t->fd_registers.regs[8];
                fd_finish(t,(long)returned.regs[0]);
                if (nr!=SYS_clone && nr!=SYS_execve && nr!=SYS_execveat) {
                    /* Bootstrap descriptor operations are not completion of
                     * the guest exec; only an entered image exposes stops. */
                    if (t->phase==IDLE && t->entered && t->process_image) {
                        if (debug_syscall_exit(t,&returned)) continue;
                        t->debug_step_call=md_debugger_step(debugger,pid);
                    }
                    resume(pid,0); continue;
                }
            }
            if (interrupted_operation(t)) continue;
            if (t->phase==DEBUG_WAIT_ENTRY) {
                t->phase=DEBUG_WAIT_EXIT; resume(pid,0); continue;
            }
            if (t->phase==DEBUG_WAIT_EXIT) {
                struct user_pt_regs regs;
                if (!registers(pid,&regs)) continue;
                if (!tracee_request(t,PTRACE_SETSIGMASK,(void *)sizeof(t->debug_wait_mask),&t->debug_wait_mask,"debug-wait-unmask")) continue;
                t->phase=IDLE;
                md_debugger_wait_complete(debugger,pid,(long)regs.regs[0]); continue;
            }
            if (t->phase==IDLE) {
                struct ptrace_syscall_info info;
                struct user_pt_regs regs;
                if (!registers(pid,&regs)) continue;
                CHECK(native_trace(PTRACE_GET_SYSCALL_INFO,pid,(void *)sizeof(info),&info)>=0);
                if (info.op==PTRACE_SYSCALL_INFO_ENTRY) {
                    t->debug_call_active=md_debugger_syscall_mode(debugger,pid);
                    if (regs.regs[8]==SYS_waitid && md_debugger_call(debugger,pid,&regs)) continue;
                    if (t->entered && t->process_image && md_debugger_syscall(debugger,pid,&regs,1)) continue;
                } else {
                    if (debug_syscall_exit(t,&regs)) continue;
                }
                resume(pid,0); continue;
            }
            if (t->phase == WATCH_CANCEL) {
                struct user_pt_regs regs = t->original; regs.pc = abi.watch_gate;
                if (!set_registers(pid, &regs)) continue;
                t->phase = WATCH_ENTRY; resume(pid, 0); continue;
            }
            if (t->phase == WATCH_ENTRY) {
                /* Restore before the blocking syscall, not after readiness. */
                if (!restore_mask(t)) continue;
                t->phase = WATCH_READ; resume(pid, 0); continue;
            }
            if (t->phase==IPC_WAIT_ENTRY) {
                int error=ipc_watch(t);
                if (error) {
                    t->ipc_cancel=error;
                    if (skip(pid)) dispatch_with_stack(t);
                    continue;
                }
                if (!restore_mask(t)) continue;
                t->phase=IPC_WAITING; resume(pid,0); continue;
            }
            if (t->phase==IPC_WAITING) {
                ipc_wait_complete(t); continue;
            }
            if (t->phase == WATCH_READ) {
                struct user_pt_regs returned;
                if (!registers(pid, &returned)) continue;
                long value = (long)returned.regs[0];
                if (value == MD_WATCH_TASK_AFFINE || (t->watch_wait == 1 && value > 0)) {
                    if (!shield(t)) continue;
                    t->watch_wait = 0;
                    dispatch_with_stack(t); continue;
                }
                struct user_pt_regs regs = t->original; regs.regs[0] = returned.regs[0];
                if (!set_registers(pid, &regs)) continue;
                if (t->stack) { md_memory_stack_return(t->memory, t->stack); t->stack = 0; }
                md_fs_worker_wake(filesystem);
                t->phase = IDLE; resume(pid, 0); continue;
            }
            if (t->phase == EXPORT_ENTRY) {
                t->phase = EXPORT_NOTIFY;
                resume(pid, 0); continue;
            }
            if (t->phase == EXPORT_RETURN || t->phase == EXPORT_NOTIFY) {
                struct metadata_operation *op = &t->metadata;
                if (!registers(pid, &op->returned)) continue;
                if (t->phase == EXPORT_NOTIFY || (long)op->returned.regs[0] < 0)
                    op->error = (int)op->returned.regs[0];
                /* A newer policy can complete the replay without notifying us,
                 * even with ERRNO|0. Preserve that result and leave output alone. */
                if (t->phase == EXPORT_NOTIFY) op->copied = op->output_size;
                store_next(t); continue;
            }
            if (t->phase == OBSERVING) {
                struct user_pt_regs regs;
                if (!registers(pid, &regs)) continue;
                if (t->original.regs[8] == SYS_clone) t->cloning = 0;
                if ((long)regs.regs[0] >= 0 && (t->original.regs[8] == SYS_munmap || t->original.regs[8] == SYS_mmap)) {
                    size_t length = t->original.regs[1], page = (size_t)getpagesize();
                    CHECK(length <= SIZE_MAX-(page-1));
                    CHECK(!md_shm_unmapped(shm,t->shm_space,t->original.regs[0],(length+page-1)&~(page-1),t->tgid));
                }
                TRACE("PROBE native syscall pid=%d nr=%llu arg0=%#llx arg1=%#llx result=%lld\n",
                    pid, t->original.regs[8], t->original.regs[0], t->original.regs[1], (long long)regs.regs[0]);
                if (!regs.regs[0] && ((t->original.regs[8] == SYS_seccomp
                            && t->original.regs[0] == SECCOMP_SET_MODE_FILTER)
                        || (t->original.regs[8] == SYS_prctl && t->original.regs[0] == PR_SET_SECCOMP)))
                    TRACE("PROBE installed-filter pid=%d instructions=%d\n", pid, t->filter_length);
                if (t->memory_action==MEMORY_KERNEL) {
                    CHECK(!md_resource_order_complete(&t->memory_order)); t->memory_action=0;
                }
                t->phase = IDLE; resume(pid, 0); continue;
            }
            if (t->phase!=EXECUTING) {
                struct user_pt_regs unexpected;
                if (registers(pid,&unexpected)) fprintf(stderr,"guest-runtime: unexpected syscall-stop pid=%d phase=%d pc=%#llx nr=%llu result=%lld\n",
                    pid,t->phase,unexpected.pc,unexpected.regs[8],(long long)unexpected.regs[0]);
            }
            CHECK(t->phase == EXECUTING);
            if (!shield(t)) continue;
            t->phase = DISPATCHING; resume(pid, 0);
        } else if (!event && sig == SIGTRAP) {
            struct user_pt_regs regs;
            if (!registers(pid, &regs)) continue;
            if (abi.export_control && regs.pc==abi.export_control && t->ready) {
                export_control(t,&regs); continue;
            }
            if (abi.fd_control && regs.pc==abi.fd_control && t->ready) {
                fd_control(t,&regs); continue;
            }
            if (abi.buffer_control && regs.pc==abi.buffer_control && t->ready && (buffer_service || !t->entered)) {
                buffer_control(t,&regs); continue;
            }
            if (abi.task_control && regs.pc==abi.task_control && t->ready) {
                mapping_begin(t,&regs); continue;
            }
            if (regs.pc==abi.enter && t->phase==IDLE && t->entered) {
                t->process_image=regs.regs[2];
                uint64_t entry=regs.regs[0], stack=regs.regs[1];
                regs=(struct user_pt_regs){.pc=entry,.sp=stack};
                if (!set_registers(pid,&regs)) continue;
                if (!md_debugger_exec(debugger,pid,t->debug_exec_old ? t->debug_exec_old : pid)) resume(pid,0);
                continue;
            }
            if (!t->ready && t->phase == IDLE && regs.regs[2] == MD_INTERCEPTION_MAGIC) {
                if (!t->resources.fs) CHECK(!md_resources_init(&t->resources,md_fs_worker_mounts(filesystem)));
                struct md_interception_abi received;
                struct iovec local = {&received, sizeof(received)}, remote = {(void *)regs.regs[3], sizeof(received)};
                CHECK(process_vm_readv(pid, &local, 1, &remote, 1, 0) == sizeof(received));
                CHECK(received.magic == MD_INTERCEPTION_MAGIC && received.size == sizeof(received)
                    && received.ready == regs.pc && received.copy_end > received.copy_begin);
                CHECK(!abi.magic || !memcmp(&abi, &received, sizeof(abi)));
                abi = received;
            }
            if (regs.pc == LOADED_BYTE && t->phase == DOMAIN_PATH) {
                t->metadata.path[t->metadata.path_size++] = (char)regs.regs[2];
                if (regs.regs[2]) domain_path_load(t); else domain_path_finish(t, 0);
                continue;
            }
            if (regs.pc == STORED_IDS && t->phase == STORING_IDS) {
                regs = t->original; regs.regs[0] = 0;
                if (!set_registers(pid, &regs) || !restore_mask(t)) continue;
                t->phase = IDLE; resume(pid, 0); continue;
            }
            if (t->phase == IDENTITY_COPY && (regs.pc == abi.loaded_groups || regs.pc == abi.stored_groups)) {
                unsigned count = t->identity_count - t->identity_copied;
                if (count > 16) count = 16;
                if (regs.pc == abi.loaded_groups)
                    for (unsigned i = 0; i < count; i++) t->identity_buffer[t->identity_copied+i] = regs.regs[i+3];
                t->identity_copied += count; identity_copy_next(t); continue;
            }
            if (regs.pc == EXPORTED && (t->phase == EXPORTING || t->phase == PROC_OPENING)) {
                export_finish(t); continue;
            }
            if (regs.pc == LOADED_BYTE && t->phase == LOADING_PATH) {
                struct metadata_operation *op = &t->metadata;
                op->path[op->path_size++] = (char)regs.regs[2];
                if (regs.regs[2]) load_path(t); else replay(t);
                continue;
            }
            if (regs.pc == STORED && t->phase == STORING) {
                t->metadata.copied += 16; store_next(t); continue;
            }
            if (regs.pc == READY && t->phase == IDLE) {
                CHECK(!read_string(pid, regs.regs[1], t->endpoint, sizeof(t->endpoint)));
                if (admitted_path && !admission.image) {
                    int error = md_admission_open(&admission, t->endpoint, admitted_path);
                    if (error) TRACE("PROBE admission error=%d\n", error);
                    CHECK(!error);
                }
                if ((int)regs.regs[0] >= 0) {
                    CHECK(listener == -1);
                    listener = duplicate_fd(pid, (int)regs.regs[0]); CHECK(listener >= 0);
                    if (broker) md_broker_listen(broker, listener);
                }
                t->ready = 1; regs.pc += 4;
                if (!set_registers(pid, &regs)) continue;
                describe_process(pid, 0);
                TRACE("PROBE guest image ready pid=%d\n", pid); resume(pid, 0);
            } else if (regs.pc == ALLOCATED && t->phase == ALLOCATING) {
                CHECK((long)regs.regs[0] > 0 && !(regs.regs[0] & (md_page_size - 1)));
                t->stack = regs.regs[0]; CHECK(!md_memory_stack_add(t->memory, t->stack)); dispatch(t);
            } else if (regs.pc == DONE && t->phase == DISPATCHING) {
                long value = regs.regs[0];
                if (t->memory_action==MEMORY_DETACH) {
                    CHECK(!md_resource_order_complete(&t->memory_order)); t->memory_action=0;
                }
                if (value==MD_IPC_WAIT) {
                    int64_t deadline=md_ipc_deadline(t->ipc_pending);
                    int64_t remaining=0;
                    if (deadline!=INT64_MAX) {
                        int64_t now=md_event_now(); CHECK(now>=0);
                        remaining=deadline>now ? deadline-now : 0;
                    }
                    regs=t->original; regs.pc=abi.ipc_wait; regs.sp=t->stack;
                    regs.regs[30]=DONE;
                    regs.regs[1]=remaining/1000000000LL; regs.regs[2]=remaining%1000000000LL;
                    regs.regs[3]=deadline!=INT64_MAX;
                    if (!set_registers(pid,&regs)) continue;
                    /* EVENT_WAIT: IPC mutation or owner death; semtimedop's
                     * deadline returns EAGAIN. Signals interrupt, never restart
                     * the guest IPC operation. The supervisor stays runnable. */
                    t->phase=IPC_WAIT_ENTRY; resume(pid,0); continue;
                }
                if (value == MD_WATCH_WAIT || value == MD_WATCH_NATIVE) {
                    regs = t->original; regs.pc = RAW_GATE - 4;
                    t->watch_wait = value == MD_WATCH_WAIT ? 1 : 2;
                    if (t->watch_wait == 1) {
                        /* EVENT_WAIT: native MSG_PEEK waits for queue readiness
                         * without consuming it. Original signals/restart policy
                         * apply; the namespace owner never waits on this reader. */
                        regs.regs[8] = SYS_recvfrom;
                        regs.regs[1] = t->stack - 16; regs.regs[2] = 1;
                        regs.regs[3] = MSG_PEEK; regs.regs[4] = regs.regs[5] = 0;
                    }
                    if (!set_registers(pid, &regs)) continue;
                    t->phase = WATCH_ENTRY; resume(pid, 0); continue;
                }
                if (value < 0 && t->original.regs[8] == SYS_fstat) {
                    if (++fstat_failures <= 8)
                        TRACE("PROBE fstat failed pid=%d fd=%llu result=%ld\n", pid, t->original.regs[0], value);
                }
                regs = t->original; regs.regs[0] = value;
                if (!set_registers(pid, &regs) || !restore_mask(t)) continue;
                md_memory_stack_return(t->memory, t->stack); t->stack = 0;
                t->phase = IDLE; resume(pid, 0);
            } else {
                siginfo_t info;
                if (t->phase==IDLE && !native_trace(PTRACE_GETSIGINFO,pid,NULL,&info)
                        && md_debugger_stop(debugger,pid,status,&info,0)) continue;
                TRACE("PROBE guest SIGTRAP pid=%d pc=%#llx lr=%#llx phase=%d\n",
                    pid, regs.pc, regs.regs[30], t->phase);
                describe_process(pid, regs.pc);
                resume(pid, SIGTRAP);
            }
        } else {
            siginfo_t debug_info;
            TRACE("PROBE signal stop pid=%d signal=%d phase=%d\n",pid,sig,t->phase);
            if (t->phase==IDLE && !native_trace(PTRACE_GETSIGINFO,pid,NULL,&debug_info)
                    && md_debugger_stop(debugger,pid,status,&debug_info,0)) continue;
            struct user_pt_regs regs;
            if ((sig == SIGSYS || sig == SIGSEGV || sig == SIGBUS || sig == SIGABRT || sig == SIGILL)
                    && !registers(pid, &regs)) continue;
            if ((sig == SIGSEGV || sig == SIGBUS) && t->phase == DOMAIN_PATH
                    && regs.pc == LOAD_BYTE) {
                domain_path_finish(t, -EFAULT); continue;
            }
            if ((sig == SIGSEGV || sig == SIGBUS) && t->phase == IDENTITY_COPY
                    && ((regs.pc >= abi.load_groups && regs.pc < abi.loaded_groups)
                        || (regs.pc >= abi.store_groups && regs.pc < abi.stored_groups))) {
                identity_copy_finish(t, -EFAULT); continue;
            }
            if ((sig == SIGSEGV || sig == SIGBUS) && t->phase == STORING_IDS) {
                if (regs.pc >= STORE_IDS && regs.pc < STORED_IDS) {
                    regs = t->original; regs.regs[0] = (uint64_t)-EFAULT;
                    if (!set_registers(pid, &regs) || !restore_mask(t)) continue;
                    t->phase = IDLE; resume(pid, 0); continue;
                }
            }
            if (sig == SIGSEGV && t->phase == LOADING_PATH && regs.pc == LOAD_BYTE) {
                t->metadata.error = -EFAULT; replay(t); continue;
            }
            if (sig == SIGSEGV && t->phase == STORING && regs.pc == STORE) {
                t->metadata.error = -EFAULT; store_next(t); continue;
            }
            if (sig == SIGSEGV && t->phase == DISPATCHING) {
                if (regs.pc >= COPY_BEGIN && regs.pc < COPY_END) {
                    copy_faults++;
                    regs.regs[0] = (uint64_t)-EFAULT; regs.pc = regs.regs[30];
                    if (set_registers(pid, &regs)) resume(pid, 0);
                    continue;
                }
            }
            if (sig == SIGSYS || sig == SIGSEGV || sig == SIGABRT || sig == SIGILL) {
                siginfo_t info;
                if (!tracee_request(t, PTRACE_GETSIGINFO, NULL, &info, "signal-info")) continue;
                signals++;
                if (sig == SIGSYS) {
                    unsigned i;
                    for (i = 0; i < 64; i++) {
                        struct denial *d = &denials[i];
                        if (!d->count) *d = (struct denial){.nr = info.si_syscall,
                            .adapted = t->phase == IDLE ? 0 : t->original.regs[8], .phase = t->phase};
                        if (d->nr == (unsigned)info.si_syscall && d->phase == t->phase
                                && d->adapted == (t->phase == IDLE ? 0 : t->original.regs[8])) {
                            d->count++; break;
                        }
                    }
                    if (i == 64 || denials[i].count > 4) { resume(pid, sig); continue; }
                }
                TRACE("PROBE signal pid=%d signal=%d code=%d pc=%#llx nr=%llu phase=%d adapted=%llu address=%p\n",
                    pid, sig, info.si_code, regs.pc, regs.regs[8], t->phase, t->original.regs[8], info.si_addr);
                if (sig == SIGSYS)
                    TRACE("PROBE application SIGSYS syscall=%d cookie=%d call=%p\n", info.si_syscall, info.si_errno, info.si_call_addr);
            }
            resume(pid, sig);
        }
    }
    for (unsigned i = 0; i < 64 && denials[i].count; i++)
        TRACE("PROBE SIGSYS summary nr=%u phase=%d adapted=%u count=%u\n",
            denials[i].nr, denials[i].phase, denials[i].adapted, denials[i].count);
    TRACE("PROBE complete status=%d threads=%u images=%u adapted=%u signals=%u copyFaults=%u fstatFailures=%u sandboxSupportEstablished=false\n",
        result, total, images, calls, signals, copy_faults, fstat_failures);
    TRACE("PROBE external metadata calls=%u errors=%u\n", external_stats, external_errors);
    TRACE("PROBE protected metadata calls=%u\n", protected_stats);
    TRACE("PROBE retained requests=%u errors=%u\n", retained_calls, retained_errors);
    TRACE("PROBE proc-root domain=1 changes=%u denials=%u\n",
        root_changes, restricted_denials);
    TRACE("PROBE job-control stops=%u wakes=%u racedWakes=%u\n",
        group_stops, group_wakes, raced_wakes);
    TRACE("PROBE identity admittedImages=%u changes=%u hostUid=%u\n",
        admitted_images, identity_changes, getuid());
    close(signal_fd); return result;
}
static void report_statistics(void) {
    if (statistics) {
        struct rusage usage;
        if (!getrusage(RUSAGE_SELF, &usage)) fprintf(stderr, "MD_CPU supervisor userUs=%llu systemUs=%llu\n",
            (unsigned long long)usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec,
            (unsigned long long)usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec);
        fprintf(stderr, "MD_SUPERVISOR stops=%llu rpcCalls=%llu rpcNs=%llu\n",
            (unsigned long long)statistics->stops, (unsigned long long)statistics->rpc.calls,
            (unsigned long long)statistics->rpc.nanoseconds);
        fprintf(stderr, "MD_INTERCEPTION ptraceRequests=%llu unknown=%llu nativeSeeks=%llu\n",
            (unsigned long long)statistics->ptrace_requests, (unsigned long long)statistics->unknown,
            (unsigned long long)statistics->native_seeks);
        for (unsigned nr = 0; nr < 512; nr++)
            if (statistics->calls[nr].trace || statistics->calls[nr].notification)
                fprintf(stderr, "MD_SYSCALL nr=%u trace=%llu notification=%llu\n", nr,
                    (unsigned long long)statistics->calls[nr].trace,
                    (unsigned long long)statistics->calls[nr].notification);
    }
}
