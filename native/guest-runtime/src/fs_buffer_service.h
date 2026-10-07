#ifndef MD_FS_BUFFER_SERVICE_H
#define MD_FS_BUFFER_SERVICE_H
#include "interception_buffers.h"
#include "resource_order.h"
#include "file_open.h"
#include <sys/types.h>
struct md_fs_worker;
struct md_task_registry;
struct md_guest_domain;
struct md_fs_buffer_service;
struct md_fs_buffer_request;
struct md_fs_anchor;
struct md_fs_task_capture;
struct md_fs_buffer_open {
    int fd; unsigned flags, task_path; struct md_fs_anchor *origin;
    struct md_open_completion completion;
};
/* Transfer the completed result lease to its receiving task; no guest FD yet. */
int md_fs_buffer_open_take(struct md_fs_buffer_request *, struct md_fs_buffer_open *);
void md_fs_buffer_open_release(struct md_fs_buffer_open *);
/* A successful watch/directory read retains its request through copy
 * acknowledgement. Only directory reads retain their exact OFD turn;
 * no filesystem or file-table turn is held across copying. */
int md_fs_buffer_ack_pending(const struct md_fs_buffer_request *);
int md_fs_buffer_ack(struct md_fs_buffer_request *, int copied);
/* Captured context and table turn survive the task-local, export-only send.
 * The install function returns an ADDFD_SEND result, not a generic FD number. */
int md_fs_buffer_export_pending(const struct md_fs_buffer_request *);
int md_fs_buffer_export_install(struct md_fs_buffer_request *, int listener, uint64_t notification);
int md_fs_buffer_export_sent(struct md_fs_buffer_request *, int error);
int md_fs_buffer_channel_observed(struct md_fs_buffer_request *);
/* Unknown cwd is captured by a private-table task helper. The request retains
 * its FS/table turns and buffer until that helper has been reaped. Finish
 * always consumes the owned descriptor, including after cancellation. */
int md_fs_buffer_capture_pending(const struct md_fs_buffer_request *);
int md_fs_buffer_capture_start(struct md_fs_buffer_request *);
int md_fs_buffer_capture_target(const struct md_fs_buffer_request *, struct md_fs_task_capture *);
int md_fs_buffer_capture_finish(struct md_fs_buffer_request *, int descriptor, int error);
struct md_fs_buffer_service *md_fs_buffer_service_new(struct md_fs_worker *, struct md_task_registry *,
        struct md_resource_wakeup *, void (*complete)(struct md_fs_buffer_request *, pid_t, int));
/* Cancel requests and reap owned children, then stop/join the worker before
 * destroy. Records retain buffers independently of a dead/replaced task. */
void md_fs_buffer_service_destroy(struct md_fs_buffer_service *);
int md_fs_buffer_begin(struct md_fs_buffer_service *, pid_t, struct md_guest_domain *, unsigned operation,
        const struct md_interception_buffer *, struct md_fs_buffer_request **);
/* Inspect one captured rights vector using a shared custody reference. No
 * application table/FS turn or per-descriptor duplication is needed. */
struct md_received_fds;
int md_fs_buffer_inspect_begin(struct md_fs_buffer_service *, pid_t, struct md_guest_domain *,
        const struct md_interception_buffer *, struct md_received_fds *, struct md_fs_buffer_request **);
/* In the completion callback only: 1 means a successfully inspected message
 * (possibly native, with NULL expanded custody); 0 means another operation. */
int md_fs_buffer_inspect_take(struct md_fs_buffer_request *, struct md_received_fds **);
/* Prepared executable descriptions stay outside the guest table until exec. */
int md_fs_buffer_exec_begin(struct md_fs_buffer_service *, pid_t, struct md_guest_domain *,
        const struct md_interception_buffer *, struct md_fs_buffer_request **);
int md_fs_buffer_exec_take(struct md_fs_buffer_request *, int descriptors[2]);
int md_fs_buffer_snapshot_begin(struct md_fs_buffer_service *, pid_t, struct md_guest_domain *,
        const struct md_interception_buffer *, unsigned flags, struct md_fs_buffer_request **);
int md_fs_buffer_snapshot_pending(const struct md_fs_buffer_request *);
int md_fs_buffer_snapshot_advance(struct md_fs_buffer_request *, int finish);
/* A descriptor-based cwd change retains both resource turns until adapter
 * acknowledgement, not ambiguous terminal registers. Only its original
 * descriptor may enter this continuation. A pre-entry denial can also finish. */
int md_fs_buffer_task_pending(const struct md_fs_buffer_request *);
int md_fs_buffer_task_start(struct md_fs_buffer_request *, int descriptor);
int md_fs_buffer_task_finish(struct md_fs_buffer_request **, long result);
int md_fs_buffer_progress(struct md_fs_buffer_service *);
/* Deferred opens are owned children, reaped by the supervisor's SIGCHLD loop.
 * A cancelled request retains its child record until the exact terminal event. */
int md_fs_buffer_children(const struct md_fs_buffer_service *);
int md_fs_buffer_child(struct md_fs_buffer_service *, pid_t, int status);
void md_fs_buffer_cancel(struct md_fs_buffer_request **);
/* Supervisor-thread diagnostics at a failed wait boundary, never polling. */
void md_fs_buffer_describe(struct md_fs_buffer_service *, int fd);
#endif
