#ifndef MD_IPC_IO_H
#define MD_IPC_IO_H
#include <sys/socket.h>
#include <stddef.h>

enum { MD_IPC_TASK_IO=8, MD_IPC_IO_DATA=65536, MD_IPC_IO_CONTROL=4096 };
/* Pointer-free shared message. The event-loop owner supplies captured native
 * descriptors; the adapter alone copies application vectors and addresses. */
struct md_ipc_io_message {
    size_t size, control_size;
    unsigned address_size, flags;
    struct sockaddr_storage address;
    _Alignas(struct cmsghdr) char control[MD_IPC_IO_CONTROL];
    char data[MD_IPC_IO_DATA];
};
#endif
