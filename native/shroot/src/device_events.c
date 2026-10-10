#define _GNU_SOURCE
#include "device_events.h"
#include "fd_selector.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

struct subscription {
    struct md_fd_object object;
    struct md_device_events *bus;
    struct subscription *next;
    int peer,type,bound,error;
    uint32_t port,groups;
};
struct md_device_events {
    atomic_uint references;
    pthread_mutex_t lock;
    struct subscription *subscribers;
    uint64_t sequence;
    uint32_t next_port;
    int stopped;
};
struct udev_header {
    char prefix[8];
    uint32_t magic,header_size,offset,size,subsystem,devtype,tags_hi,tags_lo;
};
struct md_device_events *md_device_events_new(void) {
    struct md_device_events *b=calloc(1,sizeof(*b)); if (!b) return NULL;
    atomic_init(&b->references,1); b->next_port=UINT32_MAX;
    int error=pthread_mutex_init(&b->lock,NULL);
    if (error) { free(b); errno=error; return NULL; }
    return b;
}
struct md_device_events *md_device_events_retain(struct md_device_events *b) {
    if (b) atomic_fetch_add_explicit(&b->references,1,memory_order_relaxed);
    return b;
}
void md_device_events_release(struct md_device_events *b) {
    if (!b || atomic_fetch_sub_explicit(&b->references,1,memory_order_acq_rel)!=1) return;
    pthread_mutex_destroy(&b->lock); free(b);
}
void md_device_events_stop(struct md_device_events *b) {
    if (!b) return;
    pthread_mutex_lock(&b->lock); b->stopped=1;
    for (struct subscription *s=b->subscribers;s;s=s->next) shutdown(s->peer,SHUT_RDWR);
    pthread_mutex_unlock(&b->lock);
}
static void destroy(struct md_fd_object *object) {
    struct subscription *s=(void *)object;
    pthread_mutex_lock(&s->bus->lock);
    struct subscription **p=&s->bus->subscribers;
    while (*p && *p!=s) p=&(*p)->next;
    if (*p) *p=s->next;
    pthread_mutex_unlock(&s->bus->lock);
    close(s->peer); md_device_events_release(s->bus); free(s);
}
static const struct md_fd_object_type type={.destroy=destroy,.selectors=1U<<MD_FD_SELECTOR_PROC};
int md_device_events_is(const struct md_fd_object *object) { return object && object->type==&type; }
int md_device_events_socket(struct md_device_events *b,int flags,struct md_fd_object **out,int *fd) {
    if (!b) return -EPROTONOSUPPORT;
    if (flags&~(SOCK_NONBLOCK|SOCK_CLOEXEC|15)) return -EINVAL;
    int base=flags&15;
    if (base!=SOCK_DGRAM && base!=SOCK_RAW) return -ESOCKTNOSUPPORT;
    struct subscription *s=calloc(1,sizeof(*s)); if (!s) return -ENOMEM;
    int pair[2];
    if (socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,pair)) { int e=-errno; free(s); return e; }
    if (fcntl(pair[1],F_SETFL,O_NONBLOCK) || ((flags&SOCK_NONBLOCK) && fcntl(pair[0],F_SETFL,O_NONBLOCK))) {
        int e=-errno; close(pair[0]); close(pair[1]); free(s); return e;
    }
    md_fd_object_init(&s->object,&type); s->bus=md_device_events_retain(b); s->peer=pair[1]; s->type=base;
    pthread_mutex_lock(&b->lock); s->next=b->subscribers; b->subscribers=s;
    if (b->stopped) shutdown(s->peer,SHUT_RDWR);
    pthread_mutex_unlock(&b->lock);
    *fd=pair[0]; *out=&s->object; return 0;
}
static uint32_t hash(const char *text) {
    /* udev's wire filter is MurmurHash2 with seed zero, not a host ABI hash. */
    size_t n=strlen(text); uint32_t h=(uint32_t)n;
    while (n>=4) {
        uint32_t k; memcpy(&k,text,4); k*=0x5bd1e995U; k^=k>>24; k*=0x5bd1e995U;
        h=(h*0x5bd1e995U)^k; text+=4; n-=4;
    }
    uint32_t tail=0; for (size_t i=0;i<n;++i) tail|=(uint32_t)(unsigned char)text[i]<<(8*i);
    if (n) { h^=tail; h*=0x5bd1e995U; }
    h^=h>>13; h*=0x5bd1e995U; return h^(h>>15);
}
int md_device_events_publish(struct md_device_events *b,const char *action,const char *path,
        const char *subsystem,const char *properties,size_t size) {
    if (!b || !action || !path || !subsystem || (size && properties[size-1])) return -EINVAL;
    char packet[8192],kernel[8192];
    struct udev_header h={.prefix="libudev",.magic=htonl(0xfeedcafe),.header_size=sizeof(h),
        .offset=sizeof(h),.subsystem=htonl(hash(subsystem)),.tags_hi=UINT32_MAX,.tags_lo=UINT32_MAX};
    pthread_mutex_lock(&b->lock);
    uint64_t sequence=++b->sequence;
    int n=snprintf(packet+sizeof(h),sizeof(packet)-sizeof(h),"ACTION=%s%cDEVPATH=%s%cSUBSYSTEM=%s%cSEQNUM=%llu%c",
        action,0,path,0,subsystem,0,(unsigned long long)sequence,0);
    int prefix=snprintf(kernel,sizeof(kernel),"%s@%s",action,path);
    if (n<0 || prefix<0 || sizeof(h)+(size_t)n+size>sizeof(packet) || (size_t)prefix+1+n+size>sizeof(kernel)) {
        pthread_mutex_unlock(&b->lock); return -EMSGSIZE;
    }
    h.size=(uint32_t)n+(uint32_t)size; memcpy(packet,&h,sizeof(h));
    if (size) memcpy(packet+sizeof(h)+n,properties,size);
    memcpy(kernel+prefix+1,packet+sizeof(h),h.size);
    for (struct subscription *s=b->subscribers;s && !b->stopped;s=s->next) {
        for (unsigned group=1;group<=2;group<<=1) if (s->bound && (s->groups&group)) {
            const void *data=group==1 ? (void *)kernel : (void *)packet;
            size_t length=group==1 ? (size_t)prefix+1+h.size : sizeof(h)+h.size;
            if (send(s->peer,data,length,MSG_DONTWAIT|MSG_NOSIGNAL)<0)
                s->error=errno==EAGAIN ? ENOBUFS : errno;
        }
    }
    pthread_mutex_unlock(&b->lock); return 0;
}
static int port_used(struct md_device_events *b,uint32_t port) {
    for (struct subscription *s=b->subscribers;s;s=s->next) if (s->bound && s->port==port) return 1;
    return 0;
}
long md_device_events_call(struct md_fd_object *object,long nr,const unsigned long *a,
        void *data,size_t capacity,size_t size,pid_t pid) {
    if (!md_device_events_is(object)) return -EBADF;
    struct subscription *s=(void *)object; struct md_device_events *b=s->bus;
    long result=-EOPNOTSUPP;
    pthread_mutex_lock(&b->lock);
    if (nr==SYS_bind) {
        result=-EINVAL;
        if (size==sizeof(struct sockaddr_nl)) {
            const struct sockaddr_nl *address=data;
            if (address->nl_family!=AF_NETLINK) result=-EAFNOSUPPORT;
            else if (address->nl_groups&~3U) result=-EPERM;
            else if (!s->bound) {
                uint32_t port=address->nl_pid ? address->nl_pid : (uint32_t)pid;
                if (!address->nl_pid) while (port_used(b,port)) port=b->next_port--;
                if (port_used(b,port)) result=-EADDRINUSE;
                else { s->port=port; s->groups=address->nl_groups; s->bound=1; result=0; }
            }
        }
    } else if (nr==SYS_getsockname && capacity>=sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl address={.nl_family=AF_NETLINK,.nl_pid=s->port,.nl_groups=s->groups};
        memcpy(data,&address,sizeof(address)); result=sizeof(address);
    } else if (nr==SYS_getsockopt && capacity>=4) {
        int value=0; result=sizeof(value);
        if (a[1]==SOL_NETLINK && a[2]==NETLINK_LIST_MEMBERSHIPS) value=(int)s->groups;
        else if (a[1]!=SOL_SOCKET) result=-ENOPROTOOPT;
        else switch (a[2]) {
        case SO_DOMAIN: value=AF_NETLINK; break;
        case SO_TYPE: value=s->type; break;
        case SO_PROTOCOL: value=NETLINK_KOBJECT_UEVENT; break;
        case SO_ERROR: value=s->error; s->error=0; break;
        default: result=-ENOPROTOOPT; break;
        }
        if (result>0) memcpy(data,&value,4);
    } else if (nr==SYS_setsockopt && a[1]==SOL_NETLINK && size==4) {
        int group; memcpy(&group,data,4);
        if (a[2]==NETLINK_ADD_MEMBERSHIP || a[2]==NETLINK_DROP_MEMBERSHIP) {
            if (group<1 || group>2) result=-EPERM;
            else { if (a[2]==NETLINK_ADD_MEMBERSHIP) s->groups|=1U<<(group-1); else s->groups&=~(1U<<(group-1)); result=0; }
        } else result=-ENOPROTOOPT;
    } else if (nr==SYS_read || nr==SYS_readv || nr==SYS_recvfrom || nr==SYS_recvmsg) {
        result=-s->error; s->error=0;
    } else if (nr==SYS_write || nr==SYS_sendmsg || nr==SYS_sendto) result=-EPERM;
    pthread_mutex_unlock(&b->lock); return result;
}
