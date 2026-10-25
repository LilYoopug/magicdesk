#ifndef MD_IPC_IO_HOST_H
#define MD_IPC_IO_HOST_H
#include "ipc_io.h"
#include "received_fds.h"
#include "ipc_io_job.h"
#include <stdint.h>

struct md_ipc_io {
    char *data, *control;
    size_t capacity, control_capacity, done;
    int initialized, stream, nonblocking, sending;
    int native_wait, native_ready;
    long native_result;
    struct md_ipc_io_job job;
    struct msghdr message;
    struct iovec vector;
    struct md_ipc_io_batch *batch;
    int64_t deadline;
};
void md_ipc_io_release(struct md_ipc_io *);
int md_ipc_io_prepare(struct md_ipc_io *, struct md_ipc_io_message *, int, int, int);
int md_ipc_io_prepare_batch(struct md_ipc_io *, struct md_ipc_io_message *, int fd, int flags, unsigned count);
int md_ipc_io_copy(struct md_ipc_io *, struct md_ipc_io_message *, size_t, size_t, int, int);
int md_ipc_io_event(const struct md_ipc_io *, int socket);
void md_ipc_io_interrupt(struct md_ipc_io *);
int md_ipc_io_select(struct md_ipc_io *, struct md_ipc_io_message *, unsigned);

/* The operation owner pins custody and shared storage across readiness waits. */
int md_ipc_io_receive(struct md_ipc_io *, struct md_received_fds **, struct md_ipc_io_message *, int flags, long *result);
int md_ipc_io_send(struct md_ipc_io *, const struct md_received_fds *, struct md_ipc_io_message *, int flags, long *result);
#endif
