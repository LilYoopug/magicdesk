#define _GNU_SOURCE
#include "fd_channel.h"
#include "fd_origins.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct md_fd_channel {
    atomic_uint refs;
    int receive, send;
    struct md_resource_queue output;
    uint64_t sequence;
    struct md_fd_channel_capture *inputs;
};
int md_fd_channel_new(struct md_fd_channel **out) {
    if (!out || *out) return -EINVAL;
    struct md_fd_channel *c=calloc(1,sizeof(*c));
    if (!c) return -ENOMEM;
    int pair[2];
    if (socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair)) {
        int error=-errno; free(c); return error;
    }
    int yes=1;
    if (setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&yes,sizeof(yes))) {
        int error=-errno; close(pair[0]); close(pair[1]); free(c); return error;
    }
    int error=md_resource_queue_init(&c->output);
    if (error) { close(pair[0]); close(pair[1]); free(c); return error; }
    atomic_init(&c->refs,1); c->receive=pair[0]; c->send=pair[1]; *out=c; return 0;
}
struct md_fd_channel *md_fd_channel_retain(struct md_fd_channel *c) {
    if (c) atomic_fetch_add_explicit(&c->refs,1,memory_order_relaxed);
    return c;
}
void md_fd_channel_release(struct md_fd_channel *c) {
    if (!c || atomic_fetch_sub_explicit(&c->refs,1,memory_order_acq_rel)!=1) return;
    close(c->send); close(c->receive); md_resource_queue_destroy(&c->output); free(c);
}
int md_fd_channel_endpoint(const struct md_fd_channel *c) { return c ? c->send : -1; }
int md_fd_channel_resolve(struct md_fd_channel *c, struct md_fd_origins *files, int number,
        const struct md_fd_channel_observation *observation) {
    if (!c || !observation) return -EINVAL;
    struct md_fd_channel_observation observed=*observation;
    if (observed.error==-EBADF || observed.error==-ENOTSOCK)
        return md_fd_origins_channel_resolve(files,number,c,0,0);
    if (observed.error) return observed.error<0 && observed.error>=-4095 ? observed.error : -EPROTO;
    if (!observed.cookie || observed.length!=sizeof(observed.cookie) || (observed.flags&~FD_CLOEXEC)) return -EPROTO;
    uint64_t cookie=0; socklen_t length=sizeof(cookie);
    if (getsockopt(c->send,SOL_SOCKET,SO_COOKIE,&cookie,&length)) return -errno;
    if (length!=sizeof(cookie)) return -EPROTO;
    return md_fd_origins_channel_resolve(files,number,c,observed.cookie==cookie,observed.flags);
}
int md_fd_channel_admit(struct md_fd_channel *c, struct md_fd_origins *files,
        int listener, uint64_t notification) {
    struct md_fd_origin_update update={0};
    int error=md_fd_origins_prepare_channel(files,c,FD_CLOEXEC,&update);
    if (error) return error;
    struct seccomp_notif_addfd add={.id=notification,.flags=SECCOMP_ADDFD_FLAG_SEND,
        .srcfd=md_fd_channel_endpoint(c),.newfd_flags=O_CLOEXEC};
    int installed=ioctl(listener,SECCOMP_IOCTL_NOTIF_ADDFD,&add);
    if (installed<0) error=-errno;
    md_fd_origins_finish(&update,installed);
    return error ? error : installed;
}
int md_fd_channel_output_begin(struct md_fd_channel *c, struct md_resource_order *order,
        struct md_resource_wakeup *wake) {
    return c ? md_resource_order_begin(&c->output,order,wake) : -EINVAL;
}
int md_fd_channel_output_send(struct md_fd_channel *c, int fd, uint64_t *request) {
    if (!c || fd<0 || !request) return -EINVAL;
    if (c->sequence==UINT64_MAX) return -EOVERFLOW;
    uint64_t id=++c->sequence;
    struct iovec vector={&id,sizeof(id)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=sizeof(control)};
    struct cmsghdr *h=CMSG_FIRSTHDR(&message);
    h->cmsg_level=SOL_SOCKET; h->cmsg_type=SCM_RIGHTS; h->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h),&fd,sizeof(fd));
    ssize_t n;
    do n=sendmsg(c->receive,&message,MSG_NOSIGNAL|MSG_DONTWAIT); while (n<0 && errno==EINTR);
    if (n<0) return -errno;
    if (n!=sizeof(id)) return -EIO;
    *request=id; return 0;
}
int md_fd_channel_output_discard(struct md_fd_channel *c) {
    if (!c) return -EINVAL;
    for (;;) {
        uint64_t id;
        struct iovec vector={&id,sizeof(id)};
        /* No control buffer: the kernel releases rights without installing
         * scratch FDs, including when the supervisor's own table is full. */
        struct msghdr message={.msg_iov=&vector,.msg_iovlen=1};
        ssize_t n=recvmsg(c->send,&message,MSG_DONTWAIT);
        if (n<0 && errno==EINTR) continue;
        if (n<0) return errno==EAGAIN ? 0 : -errno;
        if (!n) return -EPIPE;
    }
}
void md_fd_channel_input_close(struct md_fd_channel_input *message) {
    for (unsigned i=0;i<message->count;++i) close(message->fd[i]);
    message->count=0;
}
static int read_input(struct md_fd_channel *c, struct md_fd_channel_input *out) {
    if (!c || !out) return -EINVAL;
    *out=(struct md_fd_channel_input){0};
    struct iovec vector={&out->request,sizeof(out->request)};
    union { struct cmsghdr align;
        char bytes[CMSG_SPACE(2*sizeof(int))+CMSG_SPACE(sizeof(struct ucred))]; } control={0};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=sizeof(control)};
    ssize_t n;
    do n=recvmsg(c->receive,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC); while (n<0 && errno==EINTR);
    if (n<0) return errno==EAGAIN ? 0 : -errno;
    if (!n && !message.msg_controllen) return -EPIPE;
    int invalid=n!=sizeof(out->request) || !out->request || (message.msg_flags&(MSG_TRUNC|MSG_CTRUNC));
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&message);h;h=CMSG_NXTHDR(&message,h)) {
        if (h->cmsg_level!=SOL_SOCKET) { invalid=1; continue; }
        size_t size=h->cmsg_len-CMSG_LEN(0);
        if (h->cmsg_type==SCM_RIGHTS) {
            if (size%sizeof(int)) invalid=1;
            for (size_t i=0;i<size/sizeof(int);++i) {
                int fd; memcpy(&fd,CMSG_DATA(h)+i*sizeof(fd),sizeof(fd));
                if (out->count<2) out->fd[out->count++]=fd;
                else { close(fd); invalid=1; }
            }
        } else if (h->cmsg_type==SCM_CREDENTIALS && size==sizeof(struct ucred) && !out->peer) {
            struct ucred peer; memcpy(&peer,CMSG_DATA(h),sizeof(peer));
            out->peer=peer.pid;
            if (peer.pid<=0 || peer.uid!=getuid()) invalid=1;
        } else invalid=1;
    }
    if (!out->peer || !out->count) invalid=1;
    if (invalid) { md_fd_channel_input_close(out); return -EPROTO; }
    return 1;
}
static int dispatch_inputs(struct md_fd_channel *c) {
    for (;;) {
        struct md_fd_channel_input input;
        int result=read_input(c,&input);
        if (result==-EPROTO) continue;
        if (result<=0) return result;
        struct md_fd_channel_capture *r=c->inputs;
        while (r && r->request!=input.request) r=r->next;
        if (r && !r->input.count && r->peer==input.peer && r->expected==input.count) {
            r->input=input; input.count=0;
        }
        md_fd_channel_input_close(&input);
    }
}
static void release_capture(struct md_fd_channel_capture *r) {
    struct md_fd_channel *c=r->channel;
    struct md_fd_channel_capture **p=&c->inputs;
    while (*p && *p!=r) p=&(*p)->next;
    if (*p) *p=r->next;
    md_fd_channel_input_close(&r->input);
    *r=(struct md_fd_channel_capture){0};
    md_fd_channel_release(c);
}
int md_fd_channel_capture_begin(struct md_fd_channel *c, pid_t peer, unsigned count,
        struct md_fd_channel_capture *r) {
    if (!c || !r || r->channel || peer<=0 || !count || count>2) return -EINVAL;
    if (c->sequence==UINT64_MAX) return -EOVERFLOW;
    *r=(struct md_fd_channel_capture){.channel=md_fd_channel_retain(c),.request=++c->sequence,
        .peer=peer,.expected=count,.next=c->inputs};
    c->inputs=r; return 0;
}
int md_fd_channel_capture_finish(struct md_fd_channel_capture *r, struct md_fd_channel_input *out) {
    if (!r || !r->channel || !out) return -EINVAL;
    *out=(struct md_fd_channel_input){0};
    int result=dispatch_inputs(r->channel);
    if (!result && !r->input.count) result=-EPROTO;
    if (!result) { *out=r->input; r->input.count=0; }
    release_capture(r); return result;
}
void md_fd_channel_capture_cancel(struct md_fd_channel_capture *r) {
    if (!r || !r->channel) return;
    dispatch_inputs(r->channel);
    release_capture(r);
}
