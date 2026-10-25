#ifndef MD_IPC_IO_H
#define MD_IPC_IO_H
#include <sys/socket.h>
#include <stddef.h>
#include <time.h>

enum { MD_IPC_TASK_IO=8, MD_IPC_IO_DATA=65536, MD_IPC_IO_CONTROL=4096, MD_IPC_IO_BATCH=1024 };
enum { MD_IPC_IO_CONTROL_BYTES=1, MD_IPC_IO_READ_BYTES=2 };
struct md_ipc_io_layout {
    size_t size, control_size;
    unsigned address_size;
    int vector_error;
};
/* Pointer-free shared message. The event-loop owner supplies captured native
 * descriptors; the adapter alone copies application vectors and addresses. */
struct md_ipc_io_message {
    size_t size, control_size;
    unsigned address_size, flags;
    size_t offset, length;
    unsigned transfer;
    unsigned batch_count, batch_index, timed;
    int vector_error;
    struct timespec timeout;
    struct sockaddr_storage address;
    _Alignas(struct cmsghdr) char control[MD_IPC_IO_CONTROL];
    /* Receive layouts retire before payload publication, sharing its storage. */
    union {
        char data[MD_IPC_IO_DATA];
        struct md_ipc_io_layout layouts[MD_IPC_IO_BATCH];
    };
};
_Static_assert(sizeof(struct md_ipc_io_layout)*MD_IPC_IO_BATCH<=MD_IPC_IO_DATA,"batch layout storage");
static inline int md_ipc_io_inline(const struct md_ipc_io_message *io) {
    return !io->batch_count && io->size<=sizeof(io->data)
        && io->control_size<=sizeof(io->control);
}
#endif
