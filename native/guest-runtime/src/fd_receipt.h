#ifndef MD_FD_RECEIPT_H
#define MD_FD_RECEIPT_H
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

enum { MD_FD_RECEIPT_MAX=2 };
/* Kernel recvmsg output in a retained shared mapping. Pointer fields belong to
 * the receiving task; the supervisor reads only lengths and control bytes,
 * after syscall completion or the task's terminal event. */
struct md_fd_receipt {
    struct msghdr message;
    struct iovec vector;
    unsigned char byte;
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(MD_FD_RECEIPT_MAX*sizeof(int))]; } control;
};
static inline void md_fd_receipt_reset(struct md_fd_receipt *r) {
    memset(r,0,sizeof(*r));
    r->vector=(struct iovec){&r->byte,1};
    r->message=(struct msghdr){.msg_iov=&r->vector,.msg_iovlen=1,
        .msg_control=r->control.bytes,.msg_controllen=sizeof(r->control.bytes)};
}
static inline int md_fd_receipt_read(const struct md_fd_receipt *r, int fds[MD_FD_RECEIPT_MAX]) {
    size_t length=r->message.msg_controllen;
    if (!length || !r->control.align.cmsg_len) return 0;
    const struct cmsghdr *c=&r->control.align;
    if (length>sizeof(r->control.bytes) || length<CMSG_LEN(0)
            || c->cmsg_len<CMSG_LEN(0) || c->cmsg_len>length
            || c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS) return -EPROTO;
    size_t bytes=c->cmsg_len-CMSG_LEN(0);
    if (bytes%sizeof(int) || bytes>MD_FD_RECEIPT_MAX*sizeof(int)) return -EPROTO;
    unsigned count=bytes/sizeof(int);
    memcpy(fds,CMSG_DATA(c),bytes);
    for (unsigned i=0;i<count;++i) if (fds[i]<0 || (i && fds[i]==fds[0])) return -EPROTO;
    return (int)count;
}
#endif
