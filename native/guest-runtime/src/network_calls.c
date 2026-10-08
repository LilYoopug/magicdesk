#define _GNU_SOURCE
#include "network_calls.h"
#include "adapter_buffer.h"
#include "fs_buffer.h"
#include "fd_filter.h"
#include "interception.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <sys/socket.h>
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
long md_network_call(long nr, const unsigned long *a) {
    if (nr==SYS_read || nr==SYS_readv || nr==SYS_recvfrom || nr==SYS_recvmsg || nr==SYS_recvmmsg) {
        if (nr==SYS_recvfrom && a[4]) {
            long result=RAW6(recvfrom,a[0],a[1],a[2],a[3],0,0);
            struct sockaddr_nl source={.nl_family=AF_NETLINK};
            long error=result<0 ? 0 : output((void *)a[4],(void *)a[5],&source,sizeof(source));
            return error ? error : result;
        }
        if (nr==SYS_recvmsg || nr==SYS_recvmmsg) return -EOPNOTSUPP;
        return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
    }
    size_t size=0; const void *input=NULL;
    if (nr==SYS_ioctl) { size=sizeof(struct ifreq); input=(void *)a[2]; }
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
    } else if (nr!=SYS_getsockname && nr!=SYS_getsockopt) return -EOPNOTSUPP;
    if (size>BUFFER_SIZE) return -EMSGSIZE;
    long memory=md_adapter_buffer_take(); if (memory<0) return memory;
    long result=size ? md_read_memory((void *)memory,input,size) : 0;
    if (!result) result=md_guest_buffer_control(MD_BUFFER_NETWORK_CALL,size,0);
    if (!result && nr==SYS_ioctl) result=md_write_memory((void *)a[2],(void *)memory,size);
    else if (result>=0 && (nr==SYS_getsockname || nr==SYS_getsockopt))
        result=output((void *)a[nr==SYS_getsockname ? 1 : 3],(void *)a[nr==SYS_getsockname ? 2 : 4],(void *)memory,result);
    long released=md_adapter_buffer_release(); return result ? result : released;
}
