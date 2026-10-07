#ifndef MD_TASK_SEND_H
#define MD_TASK_SEND_H
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

enum { MD_TASK_SEND_INPUTS=254 };
/* keep is the ordered capture input. Final sends borrow retained descriptions;
 * socket selects their private execution slot and token_slot receives rights. */
struct md_task_send {
    uintptr_t message, token_slot;
    int socket, flags;
    unsigned sendto;
    struct iovec payload;
    unsigned count;
    int keep[MD_TASK_SEND_INPUTS];
};
/* SEND_CAPTURED scratch, separate from the outgoing message/control. The
 * kernel receives rights directly into the outgoing SCM_RIGHTS block. */
struct md_task_send_import {
    uint64_t token;
    struct iovec vector;
    struct msghdr message;
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } anchor;
};
#endif
