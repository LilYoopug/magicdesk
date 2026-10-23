#define _GNU_SOURCE
#include "network_icmp6.h"
#include "network_internal.h"
#include "network_ethernet.h"
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>

struct md_icmp6_membership {
    struct md_icmp6_membership *next;
    struct ipv6_mreq request;
    uint64_t policy;
};
void md_network_icmp6_attach(struct md_network_icmp6 *s,struct md_network_namespace *n,int peer) {
    *s=(struct md_network_icmp6){.space=n,.peer=peer,.unicast_hops=-1,.multicast_hops=1,
        .multicast_loop=1,.next=n->icmp6};
    n->icmp6=s;
}
void md_network_icmp6_detach(struct md_network_icmp6 *s) {
    struct md_network_icmp6 **at=&s->space->icmp6;
    while (*at && *at!=s) at=&(*at)->next;
    if (*at) *at=s->next;
    while (s->memberships) { struct md_icmp6_membership *m=s->memberships; s->memberships=m->next; free(m); }
}
int md_network_icmp6_options(const struct md_network_icmp6 *s) {
    return MD_NETWORK_PACKET_IPV6 | (s->receive_info ? MD_NETWORK_PACKET_IPV6_INFO : 0)
        | (s->receive_hops ? MD_NETWORK_PACKET_IPV6_HOPS : 0) | (s->timestamp ? MD_NETWORK_PACKET_TIMESTAMP : 0);
}
static struct md_ip_address ip(const void *a) { return md_ip_load(AF_INET6,a); }
static uint32_t sum_bytes(const void *data,size_t size,uint32_t sum) {
    const unsigned char *p=data;
    while (size>=2) { sum+=(unsigned)p[0]*256+p[1]; p+=2; size-=2; }
    if (size) sum+=(unsigned)*p*256;
    return sum;
}
static uint16_t checksum(const struct ip6_hdr *h,const void *data,size_t size) {
    uint32_t sum=sum_bytes(&h->ip6_src,16,0);
    sum=sum_bytes(&h->ip6_dst,16,sum);
    sum=sum_bytes(data,size,sum+(uint32_t)size+IPPROTO_ICMPV6);
    while (sum>>16) sum=(sum&65535)+(sum>>16);
    return htons((uint16_t)~sum);
}
static int all_nodes(struct md_ip_address a) {
    static const unsigned char bytes[16]={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return !memcmp(a.bytes,bytes,16);
}
static int multicast_member(const struct md_network_namespace *n,const struct md_network_interface *link,
        struct md_ip_address address) {
    if (all_nodes(address)) return 1;
    for (const struct md_network_icmp6 *s=n->icmp6;s;s=s->next)
        for (const struct md_icmp6_membership *m=s->memberships;m;m=m->next)
            if ((unsigned)m->request.ipv6mr_interface==link->info.index && m->policy==link->policy_id
                    && md_ip_equal(ip(&m->request.ipv6mr_multiaddr),address)) return 1;
    /* Solicited-node groups belong to configured addresses, not raw sockets. */
    static const unsigned char prefix[13]={0xff,2,0,0,0,0,0,0,0,0,0,1,0xff};
    if (!memcmp(address.bytes,prefix,sizeof(prefix)))
        for (unsigned i=0;i<link->address_count;++i)
            if (link->addresses[i].address.family==AF_INET6
                    && !memcmp(link->addresses[i].address.bytes+13,address.bytes+13,3)) return 1;
    return 0;
}
static void reply(struct md_network_namespace *n,struct md_network_interface *link,const struct ethhdr *ether,
        const struct ip6_hdr *input,const void *payload,size_t size,struct md_ip_address source) {
    size_t length=sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+size;
    unsigned char *frame=malloc(length);
    if (!frame) return;
    struct ethhdr e={.h_proto=htons(ETH_P_IPV6)};
    memcpy(e.h_source,link->info.address,6); memcpy(e.h_dest,ether->h_source,6);
    struct ip6_hdr h={.ip6_flow=htonl(6U<<28),.ip6_plen=htons((uint16_t)size),
        .ip6_nxt=IPPROTO_ICMPV6,.ip6_hlim=255,.ip6_src=source.v6,.ip6_dst=input->ip6_src};
    if (md_ip_unspecified(ip(&h.ip6_dst))) {
        h.ip6_dst=(struct in6_addr){{{0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}};
        memcpy(e.h_dest,(unsigned char[]){0x33,0x33,0,0,0,1},6);
    }
    memcpy(frame,&e,sizeof(e)); memcpy(frame+sizeof(e),&h,sizeof(h));
    unsigned char *body=frame+sizeof(e)+sizeof(h);
    memcpy(body,payload,size); body[2]=body[3]=0;
    uint16_t check=checksum(&h,body,size); memcpy(body+2,&check,2);
    /* Only echo replies and neighbor advertisements enter here. Neither can
     * generate another automatic reply, so bridge traversal cannot recurse. */
    if (link->kind!=MD_LINK_LOOPBACK && md_network_interface_has(link,ip(&h.ip6_dst)))
        md_network_icmp6_receive(n,link,frame,length);
    else md_network_ethernet_transmit(n,link,NULL,frame,length);
    free(frame);
}
void md_network_icmp6_receive(struct md_network_namespace *n,struct md_network_interface *link,
        const void *frame,size_t length) {
    if (link->ipv6.disabled || length<sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+8) return;
    const struct ethhdr *ether=frame;
    struct ip6_hdr h; memcpy(&h,(const char *)frame+sizeof(*ether),sizeof(h));
    size_t size=ntohs(h.ip6_plen);
    if ((h.ip6_vfc>>4)!=6 || h.ip6_nxt!=IPPROTO_ICMPV6 || size<8
            || size>length-sizeof(*ether)-sizeof(h)) return;
    const unsigned char *data=(const void *)((const char *)frame+sizeof(*ether)+sizeof(h));
    if (checksum(&h,data,size) || IN6_IS_ADDR_MULTICAST(&h.ip6_src)) return;
    struct md_ip_address source=ip(&h.ip6_src),destination=ip(&h.ip6_dst);
    int local=md_network_interface_has(link,destination);
    if (!local && !(md_ip_multicast(destination) && multicast_member(n,link,destination))) return;
    struct md_network_packet envelope={.ipv6={.interface=link->info.index,.hops=h.ip6_hlim}};
    memcpy(envelope.ipv6.source,&h.ip6_src,16); memcpy(envelope.ipv6.destination,&h.ip6_dst,16);
    struct timeval now; gettimeofday(&now,NULL);
    envelope.ipv6.seconds=now.tv_sec; envelope.ipv6.microseconds=now.tv_usec;
    struct iovec vectors[]={{&envelope,sizeof(envelope)},{(void *)data,size}};
    struct msghdr message={.msg_iov=vectors,.msg_iovlen=2};
    for (struct md_network_icmp6 *s=n->icmp6;s;s=s->next) {
        if ((s->device && (s->device!=link->info.index || s->device_policy!=link->policy_id))
                || (s->local_scope && (s->local_scope!=link->info.index || s->local_policy!=link->policy_id))
                || (!IN6_IS_ADDR_UNSPECIFIED(&s->local) && !md_ip_equal(ip(&s->local),destination))
                || (s->connected && !md_ip_equal(ip(&s->remote),source))
                || ICMP6_FILTER_WILLBLOCK(data[0],&s->filter)) continue;
        if (sendmsg(s->peer,&message,MSG_DONTWAIT|MSG_NOSIGNAL)<0 && errno!=ECONNREFUSED) s->overflow=1;
    }
    if (data[0]==ICMP6_ECHO_REQUEST && !data[1] && local && !md_ip_unspecified(source)) {
        unsigned char *body=malloc(size);
        if (!body) return;
        memcpy(body,data,size); body[0]=ICMP6_ECHO_REPLY;
        reply(n,link,ether,&h,body,size,destination); free(body);
    } else if (data[0]==ND_NEIGHBOR_SOLICIT && !data[1] && h.ip6_hlim==255 && size>=24) {
        struct md_ip_address target=md_ip_load(AF_INET6,data+8);
        if (md_ip_multicast(target) || !md_network_interface_has(link,target)) return;
        for (size_t at=24;at<size;) {
            if (size-at<2 || !data[at+1] || (size_t)data[at+1]*8>size-at) return;
            if (md_ip_unspecified(source) && data[at]==ND_OPT_SOURCE_LINKADDR) return;
            at+=(size_t)data[at+1]*8;
        }
        unsigned char body[32]={ND_NEIGHBOR_ADVERT};
        body[4]=(md_network_forwarding(n,AF_INET6,link->info.index) ? 0x80 : 0)
            | (md_ip_unspecified(source) ? 0 : 0x40) | 0x20;
        memcpy(body+8,target.bytes,16); body[24]=ND_OPT_TARGET_LINKADDR; body[25]=1;
        memcpy(body+26,link->info.address,6);
        reply(n,link,ether,&h,body,sizeof(body),target);
    }
}
static long send_packet(struct md_network_icmp6 *s,const void *data,size_t size,const struct md_network_address *to) {
    if (size<sizeof(struct icmp6_hdr)) return -EINVAL;
    if (size>65535) return -EMSGSIZE;
    struct sockaddr_in6 address={.sin6_family=AF_INET6,.sin6_addr=s->remote,.sin6_scope_id=s->remote_scope};
    if (to && to->size) {
        if (to->size<sizeof(address) || to->size>sizeof(to->value)) return -EINVAL;
        memcpy(&address,to->value,sizeof(address));
        if (address.sin6_family!=AF_INET6) return -EAFNOSUPPORT;
    } else if (!s->connected) return -EDESTADDRREQ;
    struct md_ip_address destination=ip(&address.sin6_addr);
    if (md_ip_unspecified(destination)) destination=md_ip_loopback(AF_INET6);
    unsigned index=address.sin6_scope_id ? address.sin6_scope_id : s->device ? s->device
        : md_ip_multicast(destination) ? s->multicast_device : s->local_scope;
    if (index && s->device && index!=s->device) return -EINVAL;
    struct md_network_interface *link=index ? md_network_interface_find(s->space,index,NULL)
        : md_network_route_find(s->space,destination,NULL);
    if (!link) return index ? -ENODEV : -ENETUNREACH;
    if ((s->device && s->device_policy!=link->policy_id)
            || (s->local_scope && (s->local_scope!=link->info.index || s->local_policy!=link->policy_id))
            || (md_ip_multicast(destination) && !address.sin6_scope_id && !s->device && s->multicast_device
                && s->multicast_policy!=link->policy_id)) return -ENODEV;
    if (!(link->info.flags&IFF_UP)) return -ENETDOWN;
    if (link->ipv6.disabled) return -EADDRNOTAVAIL;
    if (size+sizeof(struct ip6_hdr)>link->info.mtu || size+sizeof(struct ip6_hdr)>link->ipv6.mtu) return -EMSGSIZE;
    struct md_ip_address source=ip(&s->local);
    if (md_ip_unspecified(source)) {
        struct md_ip_address selection=destination;
        if (md_ip_multicast(destination) && (destination.bytes[1]&15)<=2) {
            selection=md_ip_any(AF_INET6); selection.bytes[0]=0xfe; selection.bytes[1]=0x80;
        }
        source=md_network_interface_source(link,selection);
    }
    if (md_ip_unspecified(source)) return -EADDRNOTAVAIL;
    if (!md_network_interface_has(link,source)) return -EADDRNOTAVAIL;
    size_t length=sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+size;
    unsigned char *frame=malloc(length);
    if (!frame) return -ENOMEM;
    struct ethhdr ether={.h_proto=htons(ETH_P_IPV6)};
    memcpy(ether.h_source,link->info.address,6);
    int found=md_ip_multicast(destination);
    if (found) { ether.h_dest[0]=ether.h_dest[1]=0x33; memcpy(ether.h_dest+2,destination.bytes+12,4); }
    else {
        struct md_network_interface *neighbor=md_network_interface_has(link,destination) ? link
            : md_network_neighbor(s->space,link,destination);
        if (neighbor) { memcpy(ether.h_dest,neighbor->info.address,6); found=1; }
    }
    int error=found ? 0 : -ENETUNREACH;
    if (!error) {
        struct ip6_hdr h={.ip6_flow=htonl((6U<<28)|((unsigned)s->traffic_class<<20)),.ip6_plen=htons((uint16_t)size),
            .ip6_nxt=IPPROTO_ICMPV6,.ip6_hlim=md_ip_multicast(destination) ? (unsigned)s->multicast_hops
                : s->unicast_hops<0 ? link->ipv6.hop_limit : (unsigned)s->unicast_hops,
            .ip6_src=source.v6,.ip6_dst=destination.v6};
        memcpy(frame,&ether,sizeof(ether)); memcpy(frame+sizeof(ether),&h,sizeof(h));
        unsigned char *body=frame+sizeof(ether)+sizeof(h);
        memcpy(body,data,size); body[2]=body[3]=0;
        uint16_t check=checksum(&h,body,size); memcpy(body+2,&check,2);
        if (link->kind!=MD_LINK_LOOPBACK && (md_network_interface_has(link,destination)
                || (md_ip_multicast(destination) && s->multicast_loop)))
            md_network_icmp6_receive(s->space,link,frame,length);
        if (!md_network_interface_has(link,destination) || link->kind==MD_LINK_LOOPBACK)
            error=md_network_ethernet_transmit(s->space,link,NULL,frame,length);
    }
    free(frame); return error ? error : (long)size;
}
static int membership(struct md_network_icmp6 *s,int option,const void *data,size_t size) {
    if (size<sizeof(struct ipv6_mreq)) return -EINVAL;
    struct ipv6_mreq request; memcpy(&request,data,sizeof(request));
    if (!IN6_IS_ADDR_MULTICAST(&request.ipv6mr_multiaddr)) return -EINVAL;
    unsigned index=request.ipv6mr_interface ? request.ipv6mr_interface : s->device ? s->device : s->multicast_device;
    struct md_network_interface *link=md_network_interface_find(s->space,index,NULL);
    if (!link) return -ENODEV;
    request.ipv6mr_interface=index;
    struct md_icmp6_membership **at=&s->memberships;
    while (*at && ((*at)->policy!=link->policy_id || (unsigned)(*at)->request.ipv6mr_interface!=index
            || memcmp(&(*at)->request.ipv6mr_multiaddr,&request.ipv6mr_multiaddr,16))) at=&(*at)->next;
    if (option==IPV6_DROP_MEMBERSHIP) {
        if (!*at) return -EADDRNOTAVAIL;
        struct md_icmp6_membership *old=*at; *at=old->next; free(old);
    } else {
        if (*at) return -EADDRINUSE;
        *at=calloc(1,sizeof(**at)); if (!*at) return -ENOMEM;
        (*at)->request=request; (*at)->policy=link->policy_id;
    }
    return 0;
}
long md_network_icmp6_call(struct md_network_icmp6 *s,long nr,const unsigned long *a,void *data,size_t capacity,size_t size,
        const struct md_network_address *destination) {
    if (nr==SYS_sendto || nr==SYS_sendmsg || nr==SYS_write) return send_packet(s,data,size,destination);
    if (nr==SYS_bind || nr==SYS_connect) {
        if (size<sizeof(sa_family_t)) return -EINVAL;
        struct sockaddr_in6 address={0};
        memcpy(&address,data,size<sizeof(address) ? size : sizeof(address));
        if (nr==SYS_connect && address.sin6_family==AF_UNSPEC) { s->connected=0; return 0; }
        if (size<sizeof(address)) return -EINVAL;
        if (address.sin6_family!=AF_INET6) return -EAFNOSUPPORT;
        if (nr==SYS_connect) {
            s->remote=address.sin6_addr; s->remote_scope=address.sin6_scope_id; s->connected=1; return 0;
        }
        if (s->bound) return -EINVAL;
        struct md_network_interface *scoped=address.sin6_scope_id
            ? md_network_interface_find(s->space,address.sin6_scope_id,NULL) : NULL;
        if (address.sin6_scope_id && !scoped) return -ENODEV;
        if (IN6_IS_ADDR_LINKLOCAL(&address.sin6_addr) && !scoped && !s->device) return -EINVAL;
        if (!IN6_IS_ADDR_UNSPECIFIED(&address.sin6_addr)) {
            int found=0;
            for (unsigned i=0;i<s->space->count;++i) if ((!address.sin6_scope_id
                    || address.sin6_scope_id==s->space->links[i].info.index)
                    && md_network_interface_has(&s->space->links[i],ip(&address.sin6_addr))) found=1;
            if (!found) return -EADDRNOTAVAIL;
        }
        s->local=address.sin6_addr; s->local_scope=address.sin6_scope_id;
        s->local_policy=scoped ? scoped->policy_id : 0; s->bound=1; return 0;
    }
    if (nr==SYS_getsockname || nr==SYS_getpeername) {
        if (capacity<sizeof(struct sockaddr_in6)) return -EINVAL;
        if (nr==SYS_getpeername && !s->connected) return -ENOTCONN;
        struct sockaddr_in6 address={.sin6_family=AF_INET6,.sin6_port=htons(IPPROTO_ICMPV6),
            .sin6_addr=nr==SYS_getsockname ? s->local : s->remote,
            .sin6_scope_id=nr==SYS_getsockname ? s->local_scope : s->remote_scope};
        memcpy(data,&address,sizeof(address)); return sizeof(address);
    }
    int set=nr==SYS_setsockopt;
    if (!set && nr!=SYS_getsockopt) return -EOPNOTSUPP;
    if (a[1]==IPPROTO_ICMPV6 && a[2]==ICMP6_FILTER) {
        if (set) { if (size<sizeof(s->filter)) return -EINVAL; memcpy(&s->filter,data,sizeof(s->filter)); return 0; }
        if (capacity<sizeof(s->filter)) return -EINVAL;
        memcpy(data,&s->filter,sizeof(s->filter)); return sizeof(s->filter);
    }
    if (a[1]==SOL_SOCKET && a[2]==SO_BINDTODEVICE) {
        if (!set) {
            struct md_network_interface *link=md_network_interface_find(s->space,s->device,NULL);
            size_t length=link && link->policy_id==s->device_policy ? strlen(link->info.name)+1 : 0;
            if (capacity<length) return -EINVAL;
            if (length) memcpy(data,link->info.name,length);
            return length;
        }
        if (!size || !*(char *)data) { s->device=0; s->device_policy=0; return 0; }
        if (size>IFNAMSIZ || !memchr(data,0,size)) return -EINVAL;
        struct md_network_interface *link=md_network_interface_find(s->space,0,data);
        if (!link) return -ENODEV;
        s->device=link->info.index; s->device_policy=link->policy_id; return 0;
    }
    if (set && a[1]==IPPROTO_IPV6 && (a[2]==IPV6_ADD_MEMBERSHIP || a[2]==IPV6_DROP_MEMBERSHIP))
        return membership(s,(int)a[2],data,size);
    int *field=NULL,low=0,high=1;
    if (a[1]==IPPROTO_IPV6) {
        switch (a[2]) {
        case IPV6_UNICAST_HOPS: field=&s->unicast_hops; low=-1; high=255; break;
        case IPV6_MULTICAST_HOPS: field=&s->multicast_hops; low=-1; high=255; break;
        case IPV6_MULTICAST_LOOP: field=&s->multicast_loop; break;
        case IPV6_RECVHOPLIMIT: field=&s->receive_hops; break;
        case IPV6_RECVPKTINFO: field=&s->receive_info; break;
        case IPV6_TCLASS: field=&s->traffic_class; low=-1; high=255; break;
        case IPV6_MULTICAST_IF: {
            if (!set) { if (capacity<sizeof(int)) return -EINVAL; memcpy(data,&s->multicast_device,4); return 4; }
            int index; if (size<sizeof(index)) return -EINVAL; memcpy(&index,data,sizeof(index));
            struct md_network_interface *link=index ? md_network_interface_find(s->space,(unsigned)index,NULL) : NULL;
            if (index && !link) return -ENODEV;
            s->multicast_device=(unsigned)index; s->multicast_policy=link ? link->policy_id : 0; return 0;
        }
        default: return -ENOPROTOOPT;
        }
    } else if (a[1]==SOL_SOCKET && a[2]==SO_TIMESTAMP) field=&s->timestamp;
#ifdef SO_BINDTOIFINDEX
    else if (a[1]==SOL_SOCKET && a[2]==SO_BINDTOIFINDEX) {
        if (!set) { if (capacity<sizeof(int)) return -EINVAL; memcpy(data,&s->device,4); return 4; }
        int index; if (size<sizeof(index)) return -EINVAL; memcpy(&index,data,sizeof(index));
        struct md_network_interface *link=index ? md_network_interface_find(s->space,(unsigned)index,NULL) : NULL;
        if (index && !link) return -ENODEV;
        s->device=(unsigned)index; s->device_policy=link ? link->policy_id : 0; return 0;
    }
#endif
    if (!field) return -ENOPROTOOPT;
    if (!set) { if (capacity<sizeof(int)) return -EINVAL; memcpy(data,field,sizeof(int)); return sizeof(int); }
    int value; if (size<sizeof(value)) return -EINVAL; memcpy(&value,data,sizeof(value));
    if (value<low || value>high) return -EINVAL;
    if (value==-1 && a[2]==IPV6_MULTICAST_HOPS) value=1;
    if (value==-1 && a[2]==IPV6_TCLASS) value=0;
    *field=value; return 0;
}
