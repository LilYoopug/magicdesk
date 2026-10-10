#define _GNU_SOURCE
#include "network_calls.h"
#include "adapter_buffer.h"
#include "fs_buffer.h"
#include "fd_filter.h"
#include "interception.h"
#include "socket_ancillary.h"
#include "socket_payload.h"
#include "task_receive.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

enum { BUFFER_SIZE=4096 };
long md_network_open(const unsigned long *a) {
    long memory=md_adapter_buffer_take(); if (memory<0) return memory;
    long result=md_guest_buffer_control(MD_BUFFER_NETWORK_OPEN,0,0);
    if (!result) result=md_adapter_receive_fd((void *)memory,a[1]&SOCK_CLOEXEC,MD_FS_BUFFER_RIGHTS_BEGIN);
    long released=md_adapter_buffer_release();
    if (result>=0) {
        long armed=released ? released : md_fd_filter_arm(MD_FD_SELECTOR_PROC,(int)result);
        if (armed<0) { RAW1(close,result); return armed; }
    }
    return result;
}
static long output(void *target, void *length_address, const void *data, long size) {
    unsigned length;
    long error=md_read_memory(&length,length_address,sizeof(length));
    if (!error) error=md_write_memory(target,data,length<(unsigned)size ? length : (unsigned)size);
    if (!error) { length=(unsigned)size; error=md_write_memory(length_address,&length,sizeof(length)); }
    return error;
}
static int queue_option(unsigned long level,unsigned long option) {
    if (level!=SOL_SOCKET) return 0;
    switch (option) {
    case SO_SNDTIMEO: case SO_RCVTIMEO: case SO_SNDBUF: case SO_RCVBUF:
        return 1;
    default: return 0;
    }
}
static long data_message(long nr,const unsigned long *a) {
    int sending=nr==SYS_sendto || nr==SYS_sendmsg;
    int header=nr==SYS_sendmsg || nr==SYS_recvmsg;
    struct iovec vector={(void *)a[1],a[2]};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,.msg_name=(void *)a[4]};
    struct md_socket_vectors vectors;
    long result=0;
    if (header) {
        result=md_read_memory(&message,(void *)a[1],sizeof(message));
        if (result) return result;
        if (sending && message.msg_controllen) return -EOPNOTSUPP;
        result=md_socket_vectors_open(&vectors,&message);
        if (result) return result;
    } else if (a[4]) {
        if (sending) message.msg_namelen=a[5];
        else result=md_read_memory(&message.msg_namelen,(void *)a[5],sizeof(message.msg_namelen));
    }
    long address=result ? result : md_adapter_buffer_take();
    if (address>=0) {
        struct md_task_receive_frame *frame=(void *)address;
        frame->input=(struct md_task_receive){.socket=(int)a[0]};
        frame->io.batch_count=0;
        result=md_socket_capture_inputs(md_guest_buffer_control(MD_BUFFER_NETWORK_DATA,0,0),
            &frame->capture,&frame->input.socket,1);
        if (result==MD_IPC_TASK_IO) result=md_socket_payload_prepare(&frame->io,&message,sending);
        if (!result) result=md_guest_buffer_control(MD_FS_BUFFER_IPC_RECEIVE,0,0);
        if (!sending && result>=0) {
            result=md_socket_payload_scatter(&frame->io,&message,result,0);
            long error=0;
            if (result>=0 && header) {
                error=md_write_memory((char *)a[1]+offsetof(struct msghdr,msg_namelen),
                    &message.msg_namelen,sizeof(message.msg_namelen));
                if (!error) error=md_write_memory((char *)a[1]+offsetof(struct msghdr,msg_controllen),
                    &message.msg_controllen,sizeof(message.msg_controllen));
                if (!error) error=md_write_memory((char *)a[1]+offsetof(struct msghdr,msg_flags),
                    &message.msg_flags,sizeof(message.msg_flags));
            } else if (result>=0 && a[4]) error=md_write_memory((void *)a[5],&message.msg_namelen,sizeof(message.msg_namelen));
            if (error) result=error;
        }
        long dropped=md_guest_buffer_control(MD_FS_BUFFER_RECEIVED_DROP,0,0);
        long released=md_adapter_buffer_release();
        if (result>=0 && (dropped || released)) result=dropped ? dropped : released;
    } else result=address;
    if (header) md_socket_vectors_close(&vectors);
    return result;
}
static long data_send_batch(const unsigned long *a) {
    unsigned count=(unsigned)a[2];
    if (count>1024) count=1024;
    for (unsigned i=0;i<count;++i) {
        struct mmsghdr *item=(struct mmsghdr *)a[1]+i;
        unsigned long one[6]={a[0],(uintptr_t)&item->msg_hdr,a[3]};
        long result=data_message(SYS_sendmsg,one);
        if (result<0) return i ? (long)i : result;
        unsigned length=(unsigned)result;
        long error=md_write_memory(&item->msg_len,&length,sizeof(length));
        if (error) return i ? (long)i : error;
    }
    return count;
}
long md_network_data_call(long nr,const unsigned long *a) {
    if (nr==SYS_read || nr==SYS_write || nr==SYS_readv || nr==SYS_writev
            || (nr==SYS_sendto && !a[4]) || (nr==SYS_recvfrom && !a[4])
            || nr==SYS_getsockopt || (nr==SYS_ioctl && (a[1]==FIONBIO || a[1]==FIONREAD || a[1]==TIOCOUTQ)))
        return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
    if (nr==SYS_setsockopt) {
        if (a[1]==SOL_SOCKET && a[2]==SO_BINDTODEVICE) return -EOPNOTSUPP;
        return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
    }
    if (nr==SYS_sendto || nr==SYS_recvfrom || nr==SYS_sendmsg || nr==SYS_recvmsg)
        return data_message(nr,a);
    if (nr==SYS_sendmmsg) return data_send_batch(a);
    if (nr!=SYS_bind && nr!=SYS_connect && nr!=SYS_accept && nr!=SYS_accept4 && nr!=SYS_listen
            && nr!=SYS_getsockname && nr!=SYS_getpeername) return -EOPNOTSUPP;
    long address=md_adapter_buffer_take(); if (address<0) return address;
    struct md_task_receive_frame *frame=(void *)address;
    frame->input=(struct md_task_receive){.socket=(int)a[0]};
    frame->io.address_size=frame->io.control_size=frame->io.flags=frame->io.batch_count=0;
    frame->io.size=0;
    long result=0;
    if (nr==SYS_bind || nr==SYS_connect) {
        if (a[2]>sizeof(frame->io.address)) result=-EINVAL;
        else {
            frame->io.address_size=a[2];
            result=md_read_memory(&frame->io.address,(void *)a[1],a[2]);
        }
    }
    if (!result) result=md_socket_capture_inputs(md_guest_buffer_control(MD_BUFFER_NETWORK_DATA,0,0),
        &frame->capture,&frame->input.socket,1);
    if (result==MD_IPC_TASK_IO) result=md_guest_buffer_control(MD_FS_BUFFER_IPC_RECEIVE,0,0);
    if (!result && (nr==SYS_getsockname || nr==SYS_getpeername || ((nr==SYS_accept || nr==SYS_accept4) && a[1])))
        result=output((void *)a[1],(void *)a[2],&frame->io.address,frame->io.address_size);
    long dropped=md_guest_buffer_control(MD_FS_BUFFER_RECEIVED_DROP,0,0);
    if (!result && dropped) result=dropped;
    if (!result && (nr==SYS_accept || nr==SYS_accept4)) {
        struct md_fs_buffer_frame *delivery=(void *)address;
        delivery->transfer=MD_FS_BUFFER_RIGHTS;
        result=md_adapter_receive_fd(delivery,nr==SYS_accept4 ? a[3]&SOCK_CLOEXEC : 0,MD_FS_BUFFER_RIGHTS_BEGIN);
    }
    long released=md_adapter_buffer_release();
    if (result>=0 && (nr==SYS_accept || nr==SYS_accept4)) {
        long armed=released ? released : md_fd_filter_arm(MD_FD_SELECTOR_PROC,(int)result);
        if (armed<0) { RAW1(close,result); return armed; }
    }
    return result ? result : released;
}
long md_network_call(long nr, const unsigned long *a) {
    /* These options describe the real message queue, not a host interface or
     * peer identity. Let the kernel own validation, dup sharing and timeouts. */
    if ((nr==SYS_setsockopt || nr==SYS_getsockopt) && queue_option(a[1],a[2]))
        return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
    if (nr==SYS_ioctl && (a[1]==FIONBIO || a[1]==FIONREAD || a[1]==TIOCOUTQ))
        return RAW3(ioctl,a[0],a[1],a[2]);
    if (nr==SYS_read || nr==SYS_readv || nr==SYS_recvfrom || nr==SYS_recvmsg || nr==SYS_recvmmsg) {
        if (nr==SYS_recvfrom && a[4]) {
            long result=RAW6(recvfrom,a[0],a[1],a[2],a[3],0,0);
            struct sockaddr_nl source={.nl_family=AF_NETLINK};
            long error=result<0 ? 0 : output((void *)a[4],(void *)a[5],&source,sizeof(source));
            return error ? error : result;
        }
        if (nr==SYS_recvmsg) {
            struct msghdr original;
            long error=md_read_memory(&original,(void *)a[1],sizeof(original)); if (error) return error;
            struct msghdr native=original;
            native.msg_name=NULL; native.msg_namelen=0;
            long result=RAW3(recvmsg,a[0],&native,a[2]); if (result<0) return result;
            if (original.msg_name) {
                struct sockaddr_nl source={.nl_family=AF_NETLINK};
                size_t size=original.msg_namelen<sizeof(source) ? original.msg_namelen : sizeof(source);
                error=md_write_memory(original.msg_name,&source,size);
                original.msg_namelen=sizeof(source);
            }
            original.msg_controllen=native.msg_controllen; original.msg_flags=native.msg_flags;
            if (!error) error=md_write_memory((void *)a[1],&original,sizeof(original));
            return error ? error : result;
        }
        if (nr==SYS_recvmmsg) return -EOPNOTSUPP;
        return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
    }
    size_t size=0; const void *input=NULL;
    struct msghdr message={0};
    struct iovec vectors[64];
    if (nr==SYS_sendmsg) {
        long error=md_read_memory(&message,(void *)a[1],sizeof(message)); if (error) return error;
        if (a[2]&~(MSG_DONTWAIT|MSG_NOSIGNAL) || message.msg_controllen) return -EOPNOTSUPP;
        if (message.msg_iovlen>64) return -EMSGSIZE;
        if (message.msg_name) {
            struct sockaddr_nl address;
            if (message.msg_namelen!=sizeof(address)) return -EINVAL;
            error=md_read_memory(&address,message.msg_name,sizeof(address)); if (error) return error;
            if (address.nl_family!=AF_NETLINK || address.nl_pid || address.nl_groups) return -EOPNOTSUPP;
        }
        error=md_read_memory(vectors,message.msg_iov,message.msg_iovlen*sizeof(*vectors)); if (error) return error;
        for (size_t i=0;i<message.msg_iovlen;++i) {
            if (vectors[i].iov_len>BUFFER_SIZE-size) return -EMSGSIZE;
            size+=vectors[i].iov_len;
        }
    }
    else if (nr==SYS_ioctl) { size=sizeof(struct ifreq); input=(void *)a[2]; }
    else if (nr==SYS_bind) { size=a[2]; input=(void *)a[1]; }
    else if (nr==SYS_write || nr==SYS_sendto) {
        size=a[2]; input=(void *)a[1];
        if (nr==SYS_sendto) {
            if (a[3]&~(MSG_DONTWAIT|MSG_NOSIGNAL)) return -EOPNOTSUPP;
            if (a[4]) {
                struct sockaddr_nl address;
                if (a[5]!=sizeof(address)) return -EINVAL;
                long error=md_read_memory(&address,(void *)a[4],sizeof(address)); if (error) return error;
                if (address.nl_family!=AF_NETLINK || address.nl_pid || address.nl_groups) return -EOPNOTSUPP;
            }
        }
    } else if (nr==SYS_setsockopt) { size=a[4]; input=(void *)a[3]; }
    else if (nr!=SYS_getsockname && nr!=SYS_getsockopt) return -EOPNOTSUPP;
    if (size>BUFFER_SIZE) return -EMSGSIZE;
    long memory=md_adapter_buffer_take(); if (memory<0) return memory;
    long result=0;
    if (nr==SYS_sendmsg) {
        size_t offset=0;
        for (size_t i=0;!result && i<message.msg_iovlen;++i) {
            result=md_read_memory((char *)memory+offset,vectors[i].iov_base,vectors[i].iov_len);
            offset+=vectors[i].iov_len;
        }
    } else if (size) result=md_read_memory((void *)memory,input,size);
    if (!result) result=md_guest_buffer_control(MD_BUFFER_NETWORK_CALL,size,0);
    if (!result && nr==SYS_ioctl) result=md_write_memory((void *)a[2],(void *)memory,size);
    else if (result>=0 && (nr==SYS_getsockname || nr==SYS_getsockopt))
        result=output((void *)a[nr==SYS_getsockname ? 1 : 3],(void *)a[nr==SYS_getsockname ? 2 : 4],(void *)memory,result);
    long released=md_adapter_buffer_release(); return result ? result : released;
}
