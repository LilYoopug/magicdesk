#define _GNU_SOURCE
#include "network_packet.h"
#include "adapter_buffer.h"
#include "fs_buffer.h"
#include "raw.h"
#include <errno.h>
#include <limits.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>

static long receive_state(void) {
    long memory=md_adapter_buffer_take();
    if (memory<0) return memory;
    long result=md_guest_buffer_control(MD_BUFFER_NETWORK_CALL,0,0);
    long released=md_adapter_buffer_release(); return result<0 ? result : released ? released : result;
}
static long receive_credentials(struct md_network_packet *packet) {
    long memory=md_adapter_buffer_take();
    if (memory<0) return memory;
    memcpy((void *)memory,packet,sizeof(*packet));
    long result=md_guest_buffer_control(MD_BUFFER_NETWORK_CREDENTIALS,0,0);
    if (!result) memcpy(packet,(void *)memory,sizeof(*packet));
    long released=md_adapter_buffer_release();
    return result ? result : released;
}
static long address(void *target,socklen_t capacity,void *length,const struct md_network_packet *packet,int ethernet) {
    struct sockaddr_nl source={.nl_family=AF_NETLINK,.nl_pid=packet->port,
        .nl_groups=packet->group ? 1U<<(packet->group-1) : 0};
    const void *value=ethernet ? (const void *)&packet->ethernet : (const void *)&source;
    socklen_t size=ethernet ? sizeof(packet->ethernet) : sizeof(source);
    long error=md_write_memory(target,value,capacity<size ? capacity : size);
    return error ? error : md_write_memory(length,&size,sizeof(size));
}
static long control_item(struct msghdr *message,size_t *used,int level,int type,const void *data,size_t length) {
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))]; } packet={0};
    struct cmsghdr *h=&packet.alignment;
    size_t capacity=message->msg_control ? message->msg_controllen-*used : 0;
    size_t size=CMSG_LEN(length),space=CMSG_SPACE(length);
    if (capacity<size) message->msg_flags|=MSG_CTRUNC;
    if (capacity<sizeof(*h)) return 0;
    h->cmsg_level=level; h->cmsg_type=type;
    h->cmsg_len=capacity<size ? capacity : size;
    memcpy(CMSG_DATA(h),data,length);
    long error=md_write_memory((char *)message->msg_control+*used,packet.bytes,h->cmsg_len);
    *used+=capacity<space ? capacity : space;
    return error;
}
long md_network_packet_receive(long nr,const unsigned long *a) {
    if (nr==SYS_recvmmsg) return -EOPNOTSUPP;
    struct msghdr original={0};
    struct iovec scalar={(void *)a[1],a[2]},local[9];
    long error=0;
    int flags=0;
    if (nr==SYS_recvmsg) {
        error=md_read_memory(&original,(void *)a[1],sizeof(original)); flags=(int)a[2];
    } else if (nr==SYS_readv) {
        original.msg_iov=(void *)a[1]; original.msg_iovlen=a[2];
    } else {
        original.msg_iov=&scalar; original.msg_iovlen=1;
        if (nr==SYS_recvfrom) {
            flags=(int)a[3]; original.msg_name=(void *)a[4];
            if (a[4]) error=md_read_memory(&original.msg_namelen,(void *)a[5],sizeof(original.msg_namelen));
        }
    }
    if (error) return error;
    if (original.msg_iovlen>1024) return -EMSGSIZE;
    size_t bytes=(original.msg_iovlen+1)*sizeof(struct iovec);
    struct iovec *vectors=local;
    if (bytes>sizeof(local)) {
        long memory=RAW6(mmap,0,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (memory<0) return memory;
        vectors=(void *)memory;
    }
    struct md_network_packet packet={0};
    vectors[0]=(struct iovec){&packet,sizeof(packet)};
    if (nr==SYS_recvmsg || nr==SYS_readv)
        error=md_read_memory(vectors+1,original.msg_iov,original.msg_iovlen*sizeof(struct iovec));
    else vectors[1]=scalar;
    size_t total=0;
    for (size_t i=1;!error && i<=original.msg_iovlen;++i) {
        if (vectors[i].iov_len>(size_t)LONG_MAX-total) error=-EINVAL;
        else total+=vectors[i].iov_len;
    }
    void *head=NULL;
    struct iovec first={0};
    size_t head_size=0,count=original.msg_iovlen+1;
    if (!error && original.msg_iovlen==1024) {
        /* Keep the native 1024-vector ABI. Only its first fragment needs a
         * bounded staging area when the private prefix exhausts that limit. */
        first=vectors[1];
        head_size=sizeof(packet)+(first.iov_len<MD_NETWORK_PACKET_MAX ? first.iov_len : MD_NETWORK_PACKET_MAX);
        long memory=RAW6(mmap,0,head_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (memory<0) error=memory;
        else {
            head=(void *)memory; vectors[0]=(struct iovec){head,head_size};
            memmove(vectors+1,vectors+2,1023*sizeof(*vectors)); --count;
        }
    }
    long options=error ? error : receive_state();
    struct msghdr native={.msg_iov=vectors,.msg_iovlen=count};
    long result=options<0 ? options : RAW3(recvmsg,a[0],&native,flags);
    if (head) {
        if (result>=(long)sizeof(packet)) {
            memcpy(&packet,head,sizeof(packet));
            size_t copied=(size_t)result<head_size ? (size_t)result : head_size;
            error=md_write_memory(first.iov_base,(char *)head+sizeof(packet),copied-sizeof(packet));
        }
        RAW2(munmap,head,head_size);
    }
    if (vectors!=local) RAW2(munmap,vectors,bytes);
    if (error) return error;
    if (result<0) return result;
    if (result<(long)sizeof(packet) || packet.group>32) return -EPROTO;
    result-=sizeof(packet);
    if (original.msg_name) {
        void *length=nr==SYS_recvmsg ? (char *)a[1]+offsetof(struct msghdr,msg_namelen) : (void *)a[5];
        error=address(original.msg_name,original.msg_namelen,length,&packet,options&MD_NETWORK_PACKET_ETHERNET);
    }
    if (!error && nr==SYS_recvmsg) {
        original.msg_flags=native.msg_flags;
        size_t used=0;
        if (options&MD_NETWORK_PACKET_INFO) {
            struct nl_pktinfo info={.group=packet.group};
            error=control_item(&original,&used,SOL_NETLINK,NETLINK_PKTINFO,&info,sizeof(info));
        }
        if (!error && (options&MD_NETWORK_PACKET_CREDENTIALS)) {
            error=receive_credentials(&packet);
            if (!error) {
                const struct ucred sender={packet.pid,packet.uid,packet.gid};
                error=control_item(&original,&used,SOL_SOCKET,SCM_CREDENTIALS,&sender,sizeof(sender));
            }
        }
        original.msg_controllen=used;
        if (!error) error=md_write_memory((char *)a[1]+offsetof(struct msghdr,msg_controllen),
            &original.msg_controllen,sizeof(original.msg_controllen));
        if (!error) error=md_write_memory((char *)a[1]+offsetof(struct msghdr,msg_flags),
            &original.msg_flags,sizeof(original.msg_flags));
    }
    return error ? error : result;
}
