#ifndef MD_FD_RECEIPT_H
#define MD_FD_RECEIPT_H
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

enum { MD_FD_RECEIPT_MAX=253 };
/* Kernel recvmsg output in a retained shared mapping. Pointer fields belong to
 * the receiving task; the supervisor reads only lengths and control bytes,
 * after syscall completion or the task's terminal event. */
struct md_fd_receipt {
    struct msghdr message;
    struct iovec vector;
    unsigned char byte;
    _Alignas(struct cmsghdr) unsigned char control[];
};
/* Capacity belongs to the retained operation, never to the writable mapping.
 * A receipt contains one rights parcel; payload/address publication is separate. */
static inline size_t md_fd_receipt_size(unsigned capacity) {
    return capacity && capacity<=MD_FD_RECEIPT_MAX
        ? offsetof(struct md_fd_receipt,control)+CMSG_SPACE(capacity*sizeof(int)) : 0;
}
static inline int md_fd_receipt_reset(struct md_fd_receipt *r, unsigned capacity) {
    size_t size=md_fd_receipt_size(capacity);
    if (!r || !size) return -EINVAL;
    memset(r,0,size);
    r->vector=(struct iovec){&r->byte,1};
    r->message=(struct msghdr){.msg_iov=&r->vector,.msg_iovlen=1,
        .msg_control=r->control,.msg_controllen=CMSG_LEN(capacity*sizeof(int))};
    return 0;
}
static inline int md_fd_receipt_read(const struct md_fd_receipt *r, unsigned capacity, int *fds) {
    if (!r || !fds || !md_fd_receipt_size(capacity)) return -EINVAL;
    size_t length=r->message.msg_controllen;
    if (length>CMSG_LEN(capacity*sizeof(int))) return -EPROTO;
    const struct cmsghdr *c=(const void *)r->control;
    if (!length || !c->cmsg_len) return 0;
    if (length<CMSG_LEN(0)
            || c->cmsg_len<CMSG_LEN(0) || c->cmsg_len>length
            || c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS) return -EPROTO;
    size_t bytes=c->cmsg_len-CMSG_LEN(0);
    if (bytes%sizeof(int) || bytes>capacity*sizeof(int) || length>CMSG_SPACE(bytes)) return -EPROTO;
    unsigned count=bytes/sizeof(int);
    const int *numbers=(const void *)CMSG_DATA(c);
    for (unsigned i=0;i<count;++i) {
        if (numbers[i]<0) return -EPROTO;
        for (unsigned j=0;j<i;++j) if (numbers[i]==numbers[j]) return -EPROTO;
    }
    memcpy(fds,CMSG_DATA(c),bytes);
    return (int)count;
}
#endif
