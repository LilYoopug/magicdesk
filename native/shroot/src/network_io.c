#define _GNU_SOURCE
#include "network_io.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int packet_info(struct md_ipc_io_message *message,int sending,struct in_pktinfo **out,size_t *bytes) {
    *out=NULL;
    if (message->control_size>sizeof(message->control)) return -EMSGSIZE;
    size_t offset=0;
    while (message->control_size-offset>=sizeof(struct cmsghdr)) {
        struct cmsghdr *c=(void *)(message->control+offset);
        if (c->cmsg_len<CMSG_LEN(0) || c->cmsg_len>message->control_size-offset) return -EINVAL;
        if (c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_PKTINFO) {
            size_t size=c->cmsg_len-CMSG_LEN(0);
            if (size!=sizeof(**out) && (sending || !(message->flags&MSG_CTRUNC)
                    || size>sizeof(**out))) return -EINVAL;
            if (*out) return -EINVAL;
            *out=(void *)CMSG_DATA(c);
            if (bytes) *bytes=size;
        } else if (sending && !(c->cmsg_level==IPPROTO_IP
                && (c->cmsg_type==IP_TTL || c->cmsg_type==IP_TOS))) return -EOPNOTSUPP;
        size_t step=CMSG_ALIGN(c->cmsg_len);
        if (step>message->control_size-offset) break;
        offset+=step;
    }
    return 0;
}
int md_network_io_sending(const struct md_network_io *n) {
    return n->number==SYS_sendto || n->number==SYS_sendmsg;
}
int md_network_io_flags(const struct md_network_io *n) {
    return (int)n->args[n->number==SYS_sendmsg || n->number==SYS_recvmsg ? 2 : 3];
}
void md_network_io_release(struct md_network_io *n,struct md_ipc_io *io) {
    if (io->job.started) md_ipc_io_interrupt(io);
    if ((n->number==SYS_accept || n->number==SYS_accept4) && io->native_ready && io->native_result>=0) {
        close((int)io->native_result); io->native_ready=0;
    }
    md_fd_object_release(n->endpoint);
    *n=(struct md_network_io){0};
}
int md_network_io_progress(struct md_network_io *n,struct md_ipc_io *io,struct md_received_fds **fds,
        struct md_ipc_io_message *message,long *result) {
    int fd=(*fds)->fds[0];
    long nr=n->number;
    if (nr==SYS_bind) {
        *result=md_network_endpoint_bind(n->endpoint,fd,n->identity,(void *)&message->address,message->address_size);
        return 0;
    }
    if (nr==SYS_getsockname || nr==SYS_getpeername) {
        *result=md_network_endpoint_name(n->endpoint,fd,nr==SYS_getpeername,&message->address,&message->address_size);
        return 0;
    }
    if (nr==SYS_listen) {
        struct sockaddr_in any={.sin_family=AF_INET};
        *result=md_network_endpoint_autobind(n->endpoint,fd,n->identity,(void *)&any,sizeof(any));
        if (!*result) *result=md_network_endpoint_listen(n->endpoint,fd,(int)n->args[1]);
        return 0;
    }
    if (nr==SYS_sendto || nr==SYS_recvfrom || nr==SYS_sendmsg || nr==SYS_recvmsg) {
        int sending=md_network_io_sending(n),flags=md_network_io_flags(n);
        if (!n->started) {
            struct in_pktinfo *info=NULL;
            int error=sending ? packet_info(message,1,&info,NULL) : 0;
            if (!error && sending && info && !message->address_size)
                error=md_network_endpoint_name(n->endpoint,fd,1,&message->address,&message->address_size);
            if (!error && sending && message->address_size) {
                error=md_network_endpoint_autobind(n->endpoint,fd,n->identity,
                    (void *)&message->address,message->address_size);
                if (!error) error=md_network_endpoint_destination_info(n->endpoint,(void *)&message->address,message->address_size,
                    info,&n->destination,&n->length);
                if (!error) { message->address=n->destination; message->address_size=n->length; }
            }
            /* Receive the transport peer even when the caller omits msg_name:
             * ancillary destination/interface data needs the same translation. */
            if (!sending) message->address_size=sizeof(message->address);
            if (!error && !io->initialized) error=md_ipc_io_prepare(io,message,fd,flags,sending);
            if (error) { *result=error; return 0; }
            n->started=1;
        }
        int waiting=sending ? md_ipc_io_send(io,*fds,message,flags,result)
            : md_ipc_io_receive(io,fds,message,flags,result);
        if (!waiting && !sending && *result>=0 && message->address_size) {
            struct in_pktinfo *info=NULL;
            struct in_pktinfo translated;
            size_t bytes=0;
            int error=packet_info(message,0,&info,&bytes);
            if (!error) error=md_network_endpoint_source_info(n->endpoint,&message->address,&message->address_size,
                info ? &translated : NULL);
            /* Even a truncated cmsg must expose guest fields, never the
             * backing loopback interface index or address prefix. */
            if (!error && info) memcpy(info,&translated,bytes);
            if (error) *result=error;
        }
        return waiting;
    }
    if (nr!=SYS_connect && nr!=SYS_accept && nr!=SYS_accept4) { *result=-EOPNOTSUPP; return 0; }
    if (!n->started) {
        int error=0;
        long args[5]={fd,0,0,0,0};
        if (nr==SYS_connect) {
            error=md_network_endpoint_autobind(n->endpoint,fd,n->identity,
                (void *)&message->address,message->address_size);
            if (!error) error=md_network_endpoint_destination(n->endpoint,(void *)&message->address,message->address_size,
                &n->destination,&n->length);
            args[1]=(long)&n->destination; args[2]=n->length;
        } else {
            args[3]=(nr==SYS_accept4 ? n->args[3] : 0)|SOCK_CLOEXEC;
            nr=SYS_accept4;
        }
        if (error) { *result=error; return 0; }
        io->initialized=1; io->deadline=INT64_MAX;
        error=md_ipc_io_job_start(&io->job,nr,args);
        if (error) { *result=error; return 0; }
        n->started=1; return 1;
    }
    if (!io->native_ready) {
        io->native_result=md_ipc_io_job_finish(&io->job,0); io->native_ready=1;
    }
    *result=io->native_result;
    if (n->number==SYS_connect) {
        if (!*result || *result==-EINPROGRESS || *result==-EALREADY)
            md_network_endpoint_connected(n->endpoint,fd,(void *)&message->address,message->address_size);
        io->native_ready=0;
    }
    return 0;
}
