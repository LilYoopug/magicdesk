#define _GNU_SOURCE
#include "ipc_io_host.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int waiting(int fd, int flags, int error) {
    if (error!=EAGAIN && error!=EWOULDBLOCK) return 0;
    int mode=fcntl(fd,F_GETFL);
    return mode>=0 && !(mode&O_NONBLOCK) && !(flags&MSG_DONTWAIT);
}
int md_ipc_io_receive(struct md_received_fds **custody, struct md_ipc_io_message *io, int flags, long *result) {
    if (!*custody || (*custody)->count!=1 || io->size>sizeof(io->data)
            || io->control_size>sizeof(io->control) || io->address_size>sizeof(io->address)) {
        *result=-EINVAL; return 0;
    }
    int error=md_received_fds_reserve(custody,254);
    if (error) { *result=error; return 0; }
    struct md_received_fds *fds=*custody;
    struct iovec data={io->data,io->size};
    struct msghdr message={.msg_iov=&data,.msg_iovlen=1,
        .msg_control=io->control,.msg_controllen=io->control_size,
        .msg_name=io->address_size ? &io->address : NULL,.msg_namelen=io->address_size};
    ssize_t n=recvmsg(fds->fds[0],&message,flags|MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if (n<0) {
        error=errno; *result=-error;
        return waiting(fds->fds[0],flags,error);
    }
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&message);h;h=CMSG_NXTHDR(&message,h)) {
        if (h->cmsg_level!=SOL_SOCKET || h->cmsg_type!=SCM_RIGHTS) continue;
        unsigned count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
        int *received=(void *)CMSG_DATA(h);
        for (unsigned i=0;i<count;++i) {
            if (fds->count==fds->capacity) { close(received[i]); error=EPROTO; continue; }
            fds->fds[fds->count]=received[i]; received[i]=(int)fds->count++;
        }
    }
    io->control_size=message.msg_controllen; io->address_size=message.msg_namelen;
    io->flags=message.msg_flags;
    *result=error ? -error : n;
    return 0;
}
int md_ipc_io_send(const struct md_received_fds *fds, struct md_ipc_io_message *io, int flags, long *result) {
    if (!fds || !fds->count || io->size>sizeof(io->data)
            || io->control_size>sizeof(io->control) || io->address_size>sizeof(io->address)) {
        *result=-EINVAL; return 0;
    }
    struct iovec data={io->data,io->size};
    struct msghdr message={.msg_iov=&data,.msg_iovlen=1,
        .msg_control=io->control,.msg_controllen=io->control_size,
        .msg_name=io->address_size ? &io->address : NULL,.msg_namelen=io->address_size};
    unsigned cursor=1;
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&message);h;h=CMSG_NXTHDR(&message,h)) {
        if (h->cmsg_len<CMSG_LEN(0) || (char *)h+h->cmsg_len>io->control+io->control_size) {
            *result=-EINVAL; return 0;
        }
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
            unsigned count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
            if (count>fds->count-cursor) { *result=-EINVAL; return 0; }
            memcpy(CMSG_DATA(h),fds->fds+cursor,count*sizeof(int)); cursor+=count;
        } else if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDENTIALS
                && h->cmsg_len==CMSG_LEN(sizeof(struct ucred))) {
            struct ucred native={getpid(),getuid(),getgid()};
            memcpy(CMSG_DATA(h),&native,sizeof(native));
        }
    }
    if (cursor!=fds->count) { *result=-EPROTO; return 0; }
    ssize_t n=sendmsg(fds->fds[0],&message,flags|MSG_DONTWAIT|MSG_NOSIGNAL);
    if (n<0) { int error=errno; *result=-error; return waiting(fds->fds[0],flags,error); }
    *result=n; return 0;
}
