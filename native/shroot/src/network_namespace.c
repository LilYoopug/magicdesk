#define _GNU_SOURCE
#include "network_internal.h"
#include "network_route.h"
#include "network_endpoint.h"
#include "guest_identity.h"
#include "fd_selector.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <pthread.h>

int md_network_parameter_get(struct md_network_namespace *n,enum md_network_parameter kind,uint32_t out[2]) {
    if (!md_network_namespace_managed(n)) return -EXDEV;
    pthread_mutex_lock(&n->fabric->lock);
    int error=0;
    switch (kind) {
    case MD_NET_UNPRIVILEGED_PORT: out[0]=n->unprivileged_port; out[1]=0; break;
    case MD_NET_PING_GROUPS: memcpy(out,n->ping_groups,sizeof(n->ping_groups)); break;
    case MD_NET_LOCAL_PORTS: memcpy(out,n->local_ports,sizeof(n->local_ports)); break;
    default: error=-EINVAL;
    }
    pthread_mutex_unlock(&n->fabric->lock); return error;
}
int md_network_parameter_set(struct md_network_namespace *n,enum md_network_parameter kind,const uint32_t in[2]) {
    if (!md_network_namespace_managed(n)) return -EXDEV;
    pthread_mutex_lock(&n->fabric->lock);
    int error=0;
    switch (kind) {
    case MD_NET_UNPRIVILEGED_PORT:
        if (in[0]>65535 || in[0]>n->local_ports[0]) error=-EINVAL;
        else n->unprivileged_port=in[0];
        break;
    case MD_NET_PING_GROUPS:
        if (in[0]==UINT32_MAX || in[1]==UINT32_MAX) error=-EINVAL;
        else if (in[0]>in[1]) { n->ping_groups[0]=1; n->ping_groups[1]=0; }
        else memcpy(n->ping_groups,in,sizeof(n->ping_groups));
        break;
    case MD_NET_LOCAL_PORTS:
        if (!in[0] || in[0]>in[1] || in[1]>65535 || in[0]<n->unprivileged_port) error=-EINVAL;
        else memcpy(n->local_ports,in,sizeof(n->local_ports));
        break;
    default: error=-EINVAL;
    }
    pthread_mutex_unlock(&n->fabric->lock); return error;
}
struct network_socket {
    struct md_fd_object object;
    struct md_network_namespace *space;
    int peer, family, type, protocol, bound;
    uint32_t port;
    int capped_ack;
};
static void socket_destroy(struct md_fd_object *object) {
    struct network_socket *socket=(void *)object;
    if (socket->peer>=0) close(socket->peer);
    md_network_namespace_release(socket->space); free(socket);
}
static const struct md_fd_object_type socket_type={.destroy=socket_destroy};
static const struct md_fd_object_type control_type={.destroy=socket_destroy,
    .selectors=1U<<MD_FD_SELECTOR_PROC};
struct md_fd_object *md_network_socket_new(struct md_network_namespace *n) {
    if (!md_network_namespace_managed(n)) { errno=EINVAL; return NULL; }
    struct network_socket *s=calloc(1,sizeof(*s)); if (!s) return NULL;
    md_fd_object_init(&s->object,&socket_type); s->space=md_network_namespace_retain(n); s->peer=-1;
    return &s->object;
}
int md_network_socket_offline(const struct md_fd_object *object) {
    return object && (object->type==&socket_type || object->type==&control_type);
}
int md_network_socket_control(const struct md_fd_object *object) {
    return object && object->type==&control_type;
}
int md_network_socket_open(struct md_network_namespace *n, int family, int type, int protocol,
        struct md_fd_object **out, int *fd) {
    if (!md_network_namespace_managed(n)) return -EINVAL;
    if (type&~(SOCK_CLOEXEC|SOCK_NONBLOCK|15)) return -EINVAL;
    if (family==AF_UNIX && md_network_endpoint_enabled(n)) {
        int native=socket(family,type|SOCK_CLOEXEC,protocol);
        if (native<0) return -errno;
        *out=NULL; *fd=native; return 0;
    }
    if ((family==AF_INET || family==AF_INET6) && md_network_endpoint_enabled(n))
        return md_network_endpoint_open(n,family,type,protocol,out,fd);
    int base=type&15;
    if (family==AF_NETLINK) {
        if (protocol!=NETLINK_ROUTE) return -EPROTONOSUPPORT;
        if (base!=SOCK_RAW && base!=SOCK_DGRAM) return -ESOCKTNOSUPPORT;
    } else if (family==AF_UNIX || family==AF_INET || family==AF_INET6) {
        if (base!=SOCK_DGRAM || protocol) return -EPROTONOSUPPORT;
    } else return -EAFNOSUPPORT;
    struct network_socket *s=calloc(1,sizeof(*s)); if (!s) return -ENOMEM;
    int pair[2];
    if (socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,pair)) { int e=-errno; free(s); return e; }
    if (fcntl(pair[1],F_SETFL,O_NONBLOCK) || ((type&SOCK_NONBLOCK) && fcntl(pair[0],F_SETFL,O_NONBLOCK))) {
        int e=-errno; close(pair[0]); close(pair[1]); free(s); return e;
    }
    md_fd_object_init(&s->object,&control_type); s->space=md_network_namespace_retain(n);
    s->peer=pair[1]; s->family=family; s->type=base; s->protocol=protocol;
    *out=&s->object; *fd=pair[0]; return 0;
}
static unsigned link_flags(const struct md_network_link *link) {
    return link->flags | ((link->flags&IFF_UP) ? IFF_RUNNING|IFF_LOWER_UP : 0);
}
static int publish_response(void *context,const void *data,size_t size) {
    struct network_socket *s=context;
    return send(s->peer,data,size,MSG_DONTWAIT|MSG_NOSIGNAL)<0 ? -errno : 0;
}
long md_network_socket_call(struct md_fd_object *object, const struct md_identity *identity,
        long nr, const unsigned long *a, void *data, size_t capacity, size_t size, pid_t pid,
        const struct md_network_target *resolver) {
    if (!md_network_socket_control(object)) return -EBADF;
    struct network_socket *s=(void *)object;
    if (nr==SYS_ioctl) {
        if (size!=sizeof(struct ifreq)) return -EINVAL;
        struct ifreq *r=data;
        if (a[1]!=SIOCGIFNAME && !memchr(r->ifr_name,0,IFNAMSIZ)) return -ENODEV;
        struct md_network_link info;
        pthread_mutex_lock(&s->space->fabric->lock);
        struct md_network_interface *link=md_network_interface_find(s->space,
            a[1]==SIOCGIFNAME ? (unsigned)r->ifr_ifindex : 0,
            a[1]==SIOCGIFNAME ? NULL : r->ifr_name);
        if (link) info=link->info;
        pthread_mutex_unlock(&s->space->fabric->lock);
        if (!link) return -ENODEV;
        if (a[1]==SIOCGIFNAME) {
            memcpy(r->ifr_name,info.name,IFNAMSIZ); return 0;
        }
        if (a[1]==SIOCGIFINDEX) r->ifr_ifindex=info.index;
        else if (a[1]==SIOCGIFFLAGS) r->ifr_flags=(short)link_flags(&info);
        else if (a[1]==SIOCGIFMTU) r->ifr_mtu=info.mtu;
        else return -EOPNOTSUPP;
        return 0;
    }
    if (nr==SYS_getsockopt) {
        if (a[1]!=SOL_SOCKET || capacity<sizeof(int)) return -EOPNOTSUPP;
        int value;
        switch (a[2]) {
        case SO_DOMAIN: value=s->family; break;
        case SO_TYPE: value=s->type; break;
        case SO_PROTOCOL: value=s->protocol; break;
        case SO_ERROR: value=0; break;
        default: return -EOPNOTSUPP;
        }
        memcpy(data,&value,sizeof(value)); return sizeof(value);
    }
    if (s->family!=AF_NETLINK) return -EOPNOTSUPP;
    if (nr==SYS_setsockopt && a[1]==SOL_NETLINK) {
        if (size!=sizeof(int)) return -EINVAL;
        int value; memcpy(&value,data,sizeof(value));
        if (value!=0 && value!=1) return -EINVAL;
        if (a[2]==NETLINK_EXT_ACK) return 0;
        if (a[2]==NETLINK_CAP_ACK) { s->capped_ack=value; return 0; }
        return -ENOPROTOOPT;
    }
    if (nr==SYS_bind) {
        if (size!=sizeof(struct sockaddr_nl)) return -EINVAL;
        const struct sockaddr_nl *address=data;
        if (address->nl_family!=AF_NETLINK) return -EAFNOSUPPORT;
        if (address->nl_groups) return -EOPNOTSUPP;
        if (s->bound) return -EINVAL;
        s->port=address->nl_pid ? address->nl_pid : (uint32_t)pid; s->bound=1; return 0;
    }
    if (nr==SYS_getsockname) {
        if (capacity<sizeof(struct sockaddr_nl)) return -EINVAL;
        struct sockaddr_nl address={.nl_family=AF_NETLINK,.nl_pid=s->port};
        memcpy(data,&address,sizeof(address)); return sizeof(address);
    }
    if (nr==SYS_sendto || nr==SYS_sendmsg || nr==SYS_write) {
        if (size<sizeof(struct nlmsghdr)) return -EINVAL;
        const struct nlmsghdr *h=data;
        /* Kernel-backed response queue supplies poll/epoll readiness; no
         * request or interface mutation is submitted to Android netlink. */
        long remaining=(long)size;
        if (!NLMSG_OK(h,remaining)) return -EINVAL;
        for (;NLMSG_OK(h,remaining);h=NLMSG_NEXT(h,remaining)) {
            union { struct nlmsghdr align; unsigned char bytes[MD_NETWORK_BUFFER_SIZE+sizeof(struct nlmsgerr)]; } small;
            int query=h->nlmsg_type==RTM_GETLINK || h->nlmsg_type==RTM_GETADDR || h->nlmsg_type==RTM_GETROUTE;
            size_t limit=query ? 65536 : sizeof(small);
            unsigned char *reply=query ? malloc(limit) : small.bytes; if (!reply) return -ENOMEM;
            struct md_network_publication publication={.context=s,.publish=publish_response};
            long result=md_network_route(s->space,identity,h,h->nlmsg_len,s->port ? s->port : (uint32_t)pid,
                s->capped_ack,resolver,reply,limit,&publication);
            if (query) free(reply);
            if (result<0) return result;
        }
        return (long)size;
    }
    return -EOPNOTSUPP;
}
