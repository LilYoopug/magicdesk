#ifndef MD_IPC_IO_HOST_H
#define MD_IPC_IO_HOST_H
#include "ipc_io.h"
#include "received_fds.h"

/* The operation owner pins custody and shared storage across readiness waits. */
int md_ipc_io_receive(struct md_received_fds **, struct md_ipc_io_message *, int flags, long *result);
int md_ipc_io_send(const struct md_received_fds *, struct md_ipc_io_message *, int flags, long *result);
#endif
