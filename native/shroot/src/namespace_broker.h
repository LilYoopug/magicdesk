#ifndef MD_NAMESPACE_BROKER_H
#define MD_NAMESPACE_BROKER_H
#include "fs_worker.h"
#include "fs_buffer_service.h"
#include "fs_operation.h"
#include <sys/resource.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
static inline int md_broker_filesystem_call(int nr) {
    return nr==SYS_openat || nr==SYS_fsopen || nr==SYS_newfstatat || nr==SYS_fstat
        || nr==SYS_getdents64 || nr==SYS_readlinkat;
}
struct md_broker_completion {
    struct seccomp_data call;
    unsigned operation, flags;
    int notification_live;
    struct md_fs_result result;
    struct md_fs_buffer_open opened;
};
struct md_namespace_broker;
enum { MD_BROKER_READ=1, MD_BROKER_OPEN=2 };
struct md_namespace_broker *md_broker_create(struct md_fs_worker *, int statistics,
        void (*delegate)(const struct seccomp_notif *));
void md_broker_listen(struct md_namespace_broker *, int listener);
/* Supervisor callback takes a completed operation, never permission to replay
 * it. The callback consumes opened ownership before returning. */
void md_broker_completion_handler(struct md_namespace_broker *,void (*)(pid_t,struct md_broker_completion *));
/* A stopped receiver has taken the retained result. Until this acknowledgement,
 * a kernel restart delegates without executing the operation a second time. */
void md_broker_completion_taken(struct md_namespace_broker *,pid_t);
void md_broker_control_factory(struct md_namespace_broker *,md_control_factory);
/* Retain a real kernel event while its admitted worker operation retires.
 * No synchronous worker wait or filesystem IO occurs on the supervisor. */
int md_broker_hold_event(struct md_namespace_broker *,pid_t,int,const struct rusage *);
pid_t md_broker_take_event(struct md_namespace_broker *,int *,struct rusage *);
/* Publish before resuming a tracee; forget retires its eligibility. */
int md_broker_task(struct md_namespace_broker *, int pid, int eligible, uintptr_t raw_gate, uintptr_t watch_gate);
void md_broker_forget(struct md_namespace_broker *, int pid);
struct md_fd_origins;
struct md_fd_object;
/* Publish one already completed open before resuming its receiver. The caller
 * retains source until clear (also on cancellation); the broker pins the table
 * and origin, and admits only the exact task and seccomp call snapshot. The
 * stopped-call carrier uses fstat's existing notification route with unchanged
 * user registers; task-affine delivery uses gettid at the admission gate. Neither
 * carrier executes its native syscall when it matches the pending result. */
int md_broker_result_begin(struct md_namespace_broker *, int pid, const struct seccomp_data *,
        struct md_fd_origins *, int source, struct md_fd_object *, unsigned flags);
/* Retire one pending result. Returns 1 with the kernel-confirmed response, 0
 * without a confirmed response, or a negative cleanup error. Does not infer
 * why an unconfirmed syscall returned; its stopped receiver owns that check. */
int md_broker_result_finish(struct md_namespace_broker *, int pid, long *value);
void md_broker_destroy(struct md_namespace_broker *);
#endif
