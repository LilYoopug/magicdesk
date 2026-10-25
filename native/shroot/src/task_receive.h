#ifndef MD_TASK_RECEIVE_H
#define MD_TASK_RECEIVE_H
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "fd_capture.h"
#include "ipc_io.h"

struct md_task_receive {
    uintptr_t messages, timeout;
    int socket, flags;
    unsigned count, batch, inline_receive, batch_prepared;
    /* Adapter owns no allocation/output work when no message was received. */
    unsigned finish_error;
};
/* Shared only with the private-table helper. User buffers contain lease indices
 * until the final kernel receive publishes real caller-owned descriptors. */
struct md_task_receive_frame {
    struct md_task_receive input;
    long result;
    int io_completed;
    unsigned cursor, offset, total, count;
    int descriptors[253];
    uint64_t token;
    struct iovec vector;
    struct msghdr message;
    union { struct cmsghdr align; char bytes[CMSG_SPACE(253*sizeof(int))]; } control;
    struct md_fd_capture_frame capture;
    /* Optional entry snapshot; only a completed, owned receive sets prepared. */
    unsigned prepared;
    struct msghdr original;
    struct iovec vectors[8];
    struct md_ipc_io_message io;
};
static inline size_t md_task_receive_capacity(size_t capacity) {
    size_t extra=CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(struct ucred));
    return capacity > 16*1024*1024-extra ? 0 : CMSG_ALIGN(capacity+extra);
}
/* Allocation-free private-header traversal. 1 exposes the next export vector,
 * 0 means complete; only confirmed native messages are visited. */
long md_task_receive_collect(struct md_task_receive_frame *);
#endif
