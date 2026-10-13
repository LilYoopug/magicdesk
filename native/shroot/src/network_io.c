#define _GNU_SOURCE
#include "network_io.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

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
            int error=0;
            if (sending && message->address_size) {
                error=md_network_endpoint_autobind(n->endpoint,fd,n->identity,
                    (void *)&message->address,message->address_size);
                if (!error) error=md_network_endpoint_destination(n->endpoint,(void *)&message->address,message->address_size,
                    &n->destination,&n->length);
                if (!error) { message->address=n->destination; message->address_size=n->length; }
            }
            if (!error && !io->initialized) error=md_ipc_io_prepare(io,message,fd,flags,sending);
            if (error) { *result=error; return 0; }
            n->started=1;
        }
        int waiting=sending ? md_ipc_io_send(io,*fds,message,flags,result)
            : md_ipc_io_receive(io,fds,message,flags,result);
        if (!waiting && !sending && *result>=0 && message->address_size) {
            int error=md_network_endpoint_source(n->endpoint,&message->address,&message->address_size);
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
