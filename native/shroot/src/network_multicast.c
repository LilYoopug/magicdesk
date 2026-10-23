#include "network_multicast.h"
#include "network_internal.h"
#include "network_flow.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct md_multicast_group {
    struct md_multicast_group *next;
    struct md_ip_address address;
    uint64_t policy;
    unsigned interface;
};
void md_network_multicast_attach(struct md_network_multicast *m,struct md_network_namespace *n) {
    *m=(struct md_network_multicast)MD_NETWORK_MULTICAST_INITIALIZER;
    m->space=n; m->next=n->multicast; n->multicast=m;
}
void md_network_multicast_destroy(struct md_network_multicast *m) {
    struct md_network_multicast **at=&m->space->multicast;
    while (*at && *at!=m) at=&(*at)->next;
    if (*at) *at=m->next;
    while (m->groups) { struct md_multicast_group *g=m->groups; m->groups=g->next; free(g); }
    m->count=0;
}
int md_network_multicast_subscribed(const struct md_network_namespace *n,const struct md_network_interface *link,
        struct md_ip_address address) {
    if (address.family==AF_INET && address.v4==htonl(0xe0000001)) return 1;
    if (address.family==AF_INET6) {
        static const unsigned char all_nodes[16]={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (!memcmp(address.bytes,all_nodes,16)) return 1;
        static const unsigned char solicited[13]={0xff,2,0,0,0,0,0,0,0,0,0,1,0xff};
        if (!memcmp(address.bytes,solicited,13))
            for (unsigned i=0;i<link->address_count;++i)
                if (link->addresses[i].address.family==AF_INET6
                        && !memcmp(link->addresses[i].address.bytes+13,address.bytes+13,3)) return 1;
    }
    for (const struct md_network_multicast *m=n->multicast;m;m=m->next)
        if (md_network_multicast_joined(m,link,address)) return 1;
    return 0;
}
int md_network_multicast_joined(const struct md_network_multicast *m,const struct md_network_interface *link,
        struct md_ip_address address) {
    for (const struct md_multicast_group *g=m->groups;g;g=g->next)
        if (g->policy==link->policy_id && md_ip_equal(g->address,address)) return 1;
    return 0;
}
int md_network_multicast_output(struct md_network_namespace *n,const struct md_network_multicast *m,unsigned *out) {
    if (!m->output) return 0;
    struct md_network_interface *link=md_network_interface_find(n,m->output,NULL);
    if (!link || link->policy_id!=m->output_policy) return -ENODEV;
    *out=m->output; return 0;
}
static int membership(struct md_network_namespace *n,struct md_network_multicast *m,int join,
        struct md_ip_address address,unsigned index,struct md_ip_address local) {
    if (!md_ip_multicast(address)) return -EINVAL;
    struct md_network_interface *link=index ? md_network_interface_find(n,index,NULL)
        : !md_ip_unspecified(local) ? md_network_local_interface(n,local,0)
        : join ? md_network_route_find(n,address,NULL) : NULL;
    if ((index || !md_ip_unspecified(local) || join) && !link) return -ENODEV;
    struct md_multicast_group **at=&m->groups;
    while (*at && (!md_ip_equal((*at)->address,address) || (link && (*at)->policy!=link->policy_id))) at=&(*at)->next;
    if (!join) {
        if (!*at) return -EADDRNOTAVAIL;
        struct md_multicast_group *old=*at; *at=old->next; free(old); --m->count;
    } else {
        if (*at) return -EADDRINUSE;
        if (m->count==64) return -ENOBUFS;
        struct md_multicast_group *g=malloc(sizeof(*g));
        if (!g) return -ENOMEM;
        *g=(struct md_multicast_group){.next=m->groups,.address=address,.policy=link->policy_id,.interface=link->info.index};
        m->groups=g; ++m->count;
    }
    return 0;
}
int md_network_multicast_option_io(struct md_network_namespace *n,struct md_network_multicast *m,
        unsigned family,unsigned device,int writing,unsigned level,unsigned option,void *buffer,socklen_t *size) {
    int ipv4=level==IPPROTO_IP;
    if ((int)*size<0) return -EINVAL;
    if (!ipv4 && family!=AF_INET6) return -ENOPROTOOPT;
    int *setting=NULL,maximum=1,byte=0;
    if (ipv4 && option==IP_MULTICAST_TTL) { setting=&m->hops; maximum=255; byte=1; }
    else if (!ipv4 && option==IPV6_MULTICAST_HOPS) { setting=&m->hops; maximum=255; }
    else if (ipv4 && option==IP_MULTICAST_LOOP) { setting=&m->loop; byte=1; }
    else if (!ipv4 && option==IPV6_MULTICAST_LOOP) setting=&m->loop;
    else if ((ipv4 && option==IP_MULTICAST_ALL) || (!ipv4 && option==IPV6_MULTICAST_ALL)) setting=&m->all;
    if (setting) {
        if (writing) {
            int value=0;
            if (*size>=sizeof(value)) memcpy(&value,buffer,sizeof(value));
            else if (byte && *size) value=*(unsigned char *)buffer;
            else return -EINVAL;
            if (value==-1 && setting==&m->hops) value=1;
            if (value<0 || value>maximum) return -EINVAL;
            *setting=value;
        } else {
            if (byte && *size && *size<sizeof(int)) { *(unsigned char *)buffer=(unsigned char)*setting; *size=1; }
            else { if (*size>sizeof(int)) *size=sizeof(int); memcpy(buffer,setting,*size); }
        }
        return 0;
    }
    int output=(ipv4 && option==IP_MULTICAST_IF) || (!ipv4 && option==IPV6_MULTICAST_IF);
    if (output && !writing) {
        unsigned value=ipv4 ? m->address.v4 : m->output;
        if (*size>sizeof(value)) *size=sizeof(value);
        memcpy(buffer,&value,*size); return 0;
    }
    if (!writing) return -ENOPROTOOPT;
    struct md_ip_address group=md_ip_any(ipv4 ? AF_INET : AF_INET6),local=md_ip_any(AF_INET);
    unsigned index=0;
    int join=0;
    if (ipv4 && (output || option==IP_ADD_MEMBERSHIP || option==IP_DROP_MEMBERSHIP)) {
        struct ip_mreqn req={0};
        if (output && *size==sizeof(struct in_addr)) memcpy(&req.imr_address,buffer,sizeof(struct in_addr));
        else if (*size>=sizeof(struct ip_mreq)) memcpy(&req,buffer,*size<sizeof(req) ? sizeof(struct ip_mreq) : sizeof(req));
        else return -EINVAL;
        if (req.imr_ifindex<0) return -EINVAL;
        group=md_ip_v4(req.imr_multiaddr.s_addr); local=md_ip_v4(req.imr_address.s_addr); index=(unsigned)req.imr_ifindex;
        join=option==IP_ADD_MEMBERSHIP;
    } else if (!ipv4 && output) {
        if (*size<sizeof(index)) return -EINVAL;
        memcpy(&index,buffer,sizeof(index));
    } else if (!ipv4 && (option==IPV6_ADD_MEMBERSHIP || option==IPV6_DROP_MEMBERSHIP)) {
        struct ipv6_mreq req;
        if (*size<sizeof(req)) return -EINVAL;
        memcpy(&req,buffer,sizeof(req)); group=md_ip_load(AF_INET6,&req.ipv6mr_multiaddr); index=req.ipv6mr_interface;
        join=option==IPV6_ADD_MEMBERSHIP;
    } else if (option==MCAST_JOIN_GROUP || option==MCAST_LEAVE_GROUP) {
        struct group_req req;
        if (*size<sizeof(req)) return -EINVAL;
        memcpy(&req,buffer,sizeof(req));
        struct md_inet_address a;
        int error=md_inet_decode((void *)&req.gr_group,sizeof(req.gr_group),&a);
        if (error || a.ip.family!=(ipv4 ? AF_INET : AF_INET6)) return -EINVAL;
        group=a.ip; index=req.gr_interface; join=option==MCAST_JOIN_GROUP;
    } else return -EOPNOTSUPP;
    if (!output) return membership(n,m,join,group,index ? index : !ipv4 && join ? device : 0,local);
    struct md_network_interface *link=index ? md_network_interface_find(n,index,NULL)
        : !md_ip_unspecified(local) ? md_network_local_interface(n,local,0) : NULL;
    if ((index || !md_ip_unspecified(local)) && !link) return -EADDRNOTAVAIL;
    m->output=link ? link->info.index : 0; m->output_policy=link ? link->policy_id : 0; m->address=local;
    return 0;
}
