#define _GNU_SOURCE
#include "network_namespace.h"
#include "namespace_identity.h"
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

struct md_network_namespace {
    atomic_uint references;
    uint64_t inode;
    struct md_user_namespace *owner;
    int offline;
    unsigned loopback_flags;
    uint32_t loopback_address;
};
struct md_network_namespace *md_network_namespace_new(struct md_user_namespace *owner, int offline) {
    struct md_network_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    int error=md_namespace_identity_new(&n->inode);
    if (error) { free(n); errno=-error; return NULL; }
    atomic_init(&n->references,1); n->owner=md_user_namespace_retain(owner); n->offline=!!offline;
    n->loopback_flags=IFF_LOOPBACK;
    return n;
}
struct md_network_namespace *md_network_namespace_retain(struct md_network_namespace *n) {
    if (n) atomic_fetch_add_explicit(&n->references,1,memory_order_relaxed);
    return n;
}
void md_network_namespace_release(struct md_network_namespace *n) {
    if (!n || atomic_fetch_sub_explicit(&n->references,1,memory_order_acq_rel)!=1) return;
    md_user_namespace_release(n->owner); free(n);
}
uint64_t md_network_namespace_inode(const struct md_network_namespace *n) { return n->inode; }
const struct md_user_namespace *md_network_namespace_owner(const struct md_network_namespace *n) { return n->owner; }
int md_network_namespace_offline(const struct md_network_namespace *n) { return n && n->offline; }
struct network_socket {
    struct md_fd_object object;
    struct md_network_namespace *space;
    int peer, family, type, protocol, bound;
    uint32_t port;
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
    if (!md_network_namespace_offline(n)) { errno=EINVAL; return NULL; }
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
    if (!md_network_namespace_offline(n)) return -EINVAL;
    if (type&~(SOCK_CLOEXEC|SOCK_NONBLOCK|15)) return -EINVAL;
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
static int route_change(struct network_socket *s, const struct md_identity *identity,
        const struct nlmsghdr *h, size_t size,unsigned *flags,uint32_t *loopback) {
    if (!(h->nlmsg_flags&NLM_F_REQUEST)) return -EINVAL;
    if (!md_identity_capable_in(identity,s->space->owner,CAP_NET_ADMIN)) return -EPERM;
    if (h->nlmsg_type==RTM_NEWLINK) {
        if (size<NLMSG_LENGTH(sizeof(struct ifinfomsg))) return -EINVAL;
        const struct ifinfomsg *m=NLMSG_DATA(h);
        if (m->ifi_index!=1) return -ENODEV;
        if (size!=NLMSG_LENGTH(sizeof(*m)) || m->ifi_change&~IFF_UP) return -EOPNOTSUPP;
        *flags=(*flags&~m->ifi_change)|(m->ifi_flags&m->ifi_change);
        return 0;
    }
    if (h->nlmsg_type==RTM_NEWADDR) {
        if (size<NLMSG_LENGTH(sizeof(struct ifaddrmsg))) return -EINVAL;
        const struct ifaddrmsg *m=NLMSG_DATA(h);
        if (m->ifa_index!=1) return -ENODEV;
        if (m->ifa_family!=AF_INET || m->ifa_prefixlen!=8 || m->ifa_scope!=RT_SCOPE_HOST) return -EOPNOTSUPP;
        uint32_t address=0;
        int remaining=(int)size-(int)NLMSG_LENGTH(sizeof(*m));
        for (const struct rtattr *a=IFA_RTA(m); RTA_OK(a,remaining); a=RTA_NEXT(a,remaining)) {
            if (a->rta_type!=IFA_LOCAL && a->rta_type!=IFA_ADDRESS) return -EOPNOTSUPP;
            if (RTA_PAYLOAD(a)!=sizeof(address)) return -EINVAL;
            uint32_t value; memcpy(&value,RTA_DATA(a),sizeof(value));
            if (ntohl(value)!=INADDR_LOOPBACK || (address && address!=value)) return -EOPNOTSUPP;
            address=value;
        }
        if (remaining || !address) return -EINVAL;
        if (*loopback && (h->nlmsg_flags&NLM_F_EXCL)) return -EEXIST;
        *loopback=address; return 0;
    }
    return -EOPNOTSUPP;
}
static unsigned loopback_flags(const struct md_network_namespace *space) {
    return space->loopback_flags | ((space->loopback_flags&IFF_UP) ? IFF_RUNNING|IFF_LOWER_UP : 0);
}
static size_t attribute(void *out,unsigned type,const void *data,size_t size) {
    struct rtattr *a=out;
    a->rta_type=type; a->rta_len=RTA_LENGTH(size);
    memcpy(RTA_DATA(a),data,size); return RTA_SPACE(size);
}
static int route_query(const struct network_socket *s,const struct nlmsghdr *h,size_t size,
        void *out) {
    if (size<NLMSG_LENGTH(sizeof(struct ifinfomsg))) return -EINVAL;
    if (h->nlmsg_flags&~(NLM_F_REQUEST|NLM_F_ACK|NLM_F_DUMP)) return -EOPNOTSUPP;
    const struct ifinfomsg *m=NLMSG_DATA(h);
    if (m->ifi_family!=AF_UNSPEC && m->ifi_family!=AF_PACKET) return -EAFNOSUPPORT;
    int dump=(h->nlmsg_flags&NLM_F_DUMP)==NLM_F_DUMP, named=0;
    if (!dump && m->ifi_index && m->ifi_index!=1) return -ENODEV;
    int remaining=(int)size-(int)NLMSG_LENGTH(sizeof(*m));
    for (const struct rtattr *a=IFLA_RTA(m); RTA_OK(a,remaining); a=RTA_NEXT(a,remaining)) {
        if (a->rta_type==IFLA_IFNAME) {
            if (named || RTA_PAYLOAD(a)<1 || RTA_PAYLOAD(a)>IFNAMSIZ
                    || ((const char *)RTA_DATA(a))[RTA_PAYLOAD(a)-1]) return -EINVAL;
            if (RTA_PAYLOAD(a)!=3 || memcmp(RTA_DATA(a),"lo",3)) return -ENODEV;
            named=1;
        } else if (a->rta_type==IFLA_EXT_MASK) {
            uint32_t mask;
            if (RTA_PAYLOAD(a)!=sizeof(mask)) return -EINVAL;
            memcpy(&mask,RTA_DATA(a),sizeof(mask));
            if (mask&~(RTEXT_FILTER_VF|RTEXT_FILTER_SKIP_STATS)) return -EOPNOTSUPP;
        } else return -EOPNOTSUPP;
    }
    if (remaining) return -EINVAL;
    if (!dump && !named && !m->ifi_index) return -EINVAL;
    struct nlmsghdr *reply=out;
    *reply=(struct nlmsghdr){.nlmsg_len=NLMSG_LENGTH(sizeof(*m)),.nlmsg_type=RTM_NEWLINK,
        .nlmsg_flags=dump ? NLM_F_MULTI : 0,.nlmsg_seq=h->nlmsg_seq,.nlmsg_pid=s->port};
    struct ifinfomsg *link=NLMSG_DATA(reply);
    *link=(struct ifinfomsg){.ifi_family=AF_UNSPEC,.ifi_type=ARPHRD_LOOPBACK,
        .ifi_index=1,.ifi_flags=loopback_flags(s->space)};
    char *at=(char *)out+reply->nlmsg_len;
    at+=attribute(at,IFLA_IFNAME,"lo",3);
    uint32_t mtu=65536; at+=attribute(at,IFLA_MTU,&mtu,sizeof(mtu));
    unsigned char address[6]={0}; at+=attribute(at,IFLA_ADDRESS,address,sizeof(address));
    unsigned char state=(s->space->loopback_flags&IFF_UP) ? IF_OPER_UNKNOWN : IF_OPER_DOWN;
    at+=attribute(at,IFLA_OPERSTATE,&state,sizeof(state));
    reply->nlmsg_len=(uint32_t)(at-(char *)out);
    if (dump) {
        struct nlmsghdr *done=(void *)at;
        *done=(struct nlmsghdr){.nlmsg_len=NLMSG_LENGTH(sizeof(int)),.nlmsg_type=NLMSG_DONE,
            .nlmsg_flags=NLM_F_MULTI,.nlmsg_seq=h->nlmsg_seq,.nlmsg_pid=s->port};
        at+=NLMSG_ALIGN(done->nlmsg_len);
    } else if (h->nlmsg_flags&NLM_F_ACK) {
        struct nlmsghdr *ack=(void *)at;
        *ack=(struct nlmsghdr){.nlmsg_len=NLMSG_LENGTH(sizeof(struct nlmsgerr)),.nlmsg_type=NLMSG_ERROR,
            .nlmsg_seq=h->nlmsg_seq,.nlmsg_pid=s->port};
        ((struct nlmsgerr *)NLMSG_DATA(ack))->msg=*h;
        at+=NLMSG_ALIGN(ack->nlmsg_len);
    }
    return (int)(at-(char *)out);
}
long md_network_socket_call(struct md_fd_object *object, const struct md_identity *identity,
        long nr, const unsigned long *a, void *data, size_t capacity, size_t size, pid_t pid) {
    if (!md_network_socket_control(object)) return -EBADF;
    struct network_socket *s=(void *)object;
    if (nr==SYS_ioctl) {
        if (size!=sizeof(struct ifreq)) return -EINVAL;
        struct ifreq *r=data;
        if (a[1]==SIOCGIFNAME) {
            if (r->ifr_ifindex!=1) return -ENODEV;
            memset(r->ifr_name,0,IFNAMSIZ); memcpy(r->ifr_name,"lo",3); return 0;
        }
        if (memcmp(r->ifr_name,"lo",3)) return -ENODEV;
        if (a[1]==SIOCGIFINDEX) r->ifr_ifindex=1;
        else if (a[1]==SIOCGIFFLAGS) r->ifr_flags=(short)loopback_flags(s->space);
        else if (a[1]==SIOCGIFMTU) r->ifr_mtu=65536;
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
        if (h->nlmsg_len!=size) return -EOPNOTSUPP;
        struct { struct nlmsghdr header; struct nlmsgerr error; } reply={
            .header={.nlmsg_len=NLMSG_LENGTH(sizeof(struct nlmsgerr)),.nlmsg_type=NLMSG_ERROR,
                .nlmsg_seq=h->nlmsg_seq,.nlmsg_pid=s->port ? s->port : (uint32_t)pid},
            .error={.msg=*h}};
        unsigned flags=s->space->loopback_flags; uint32_t address=s->space->loopback_address;
        union { struct nlmsghdr align; unsigned char bytes[256]; } query={0};
        int queried=0;
        if (h->nlmsg_type==RTM_GETLINK && (h->nlmsg_flags&NLM_F_REQUEST)) {
            queried=route_query(s,h,size,query.bytes);
            reply.error.error=queried<0 ? queried : 0;
        } else reply.error.error=route_change(s,identity,h,size,&flags,&address);
        /* Kernel-backed response queue supplies poll/epoll readiness; no
         * request or interface mutation is submitted to Android netlink. */
        ssize_t written=send(s->peer,queried>0 ? (void *)query.bytes : (void *)&reply,
            queried>0 ? (size_t)queried : sizeof(reply),MSG_DONTWAIT|MSG_NOSIGNAL);
        if (written>=0 && !reply.error.error) {
            s->space->loopback_flags=flags; s->space->loopback_address=address;
        }
        return written<0 ? -errno : (long)size;
    }
    return -EOPNOTSUPP;
}
