#define _GNU_SOURCE
#include "network_route.h"
#include "network_internal.h"
#include "guest_identity.h"
#include <errno.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

struct attrs { const struct rtattr *v[IFLA_MAX+1]; };
static int attributes(const void *data,size_t size,struct attrs *out,unsigned max) {
    memset(out,0,sizeof(*out));
    while (size) {
        if (size<sizeof(struct rtattr)) return -EINVAL;
        const struct rtattr *a=data;
        unsigned type=a->rta_type&NLA_TYPE_MASK;
        if (a->rta_len<sizeof(*a) || a->rta_len>size || RTA_ALIGN(a->rta_len)>size) return -EINVAL;
        if (type>max || !type) return -EOPNOTSUPP;
        if (out->v[type]) return -EINVAL;
        out->v[type]=a; size-=RTA_ALIGN(a->rta_len); data=(const char *)data+RTA_ALIGN(a->rta_len);
    }
    return 0;
}
static int number(const struct rtattr *a,uint32_t *out) {
    if (RTA_PAYLOAD(a)!=sizeof(*out)) return -EINVAL;
    memcpy(out,RTA_DATA(a),sizeof(*out)); return 0;
}
static int string(const struct rtattr *a,char *out,size_t maximum) {
    size_t size=RTA_PAYLOAD(a);
    if (!size || size>maximum) return -EINVAL;
    size_t length=strnlen(RTA_DATA(a),size);
    if (!length || length>=maximum) return -EINVAL;
    memcpy(out,RTA_DATA(a),length); out[length]=0; return 0;
}
static int kind_is(const struct rtattr *a,const char *name) {
    size_t size=RTA_PAYLOAD(a),length=strlen(name);
    return (size==length || (size==length+1 && !((const char *)RTA_DATA(a))[length]))
        && !memcmp(RTA_DATA(a),name,length);
}
struct output { unsigned char *data; size_t size,capacity; struct nlmsghdr *message; };
static int append(struct output *o,const void *data,size_t length) {
    size_t size=NLMSG_ALIGN(length);
    if (size>o->capacity-o->size) return -EMSGSIZE;
    if (length) memcpy(o->data+o->size,data,length);
    memset(o->data+o->size+length,0,size-length); o->size+=size; return 0;
}
static int begin(struct output *o,const struct nlmsghdr *request,uint32_t port,unsigned type,int multi,
        const void *payload,size_t size) {
    if (NLMSG_SPACE(size)>o->capacity-o->size) return -EMSGSIZE;
    struct nlmsghdr h={.nlmsg_len=NLMSG_LENGTH(size),.nlmsg_type=type,.nlmsg_flags=multi ? NLM_F_MULTI : 0,
        .nlmsg_seq=request->nlmsg_seq,.nlmsg_pid=port};
    o->message=(void *)(o->data+o->size);
    append(o,&h,sizeof(h)); return append(o,payload,size);
}
static int attribute(struct output *o,unsigned type,const void *data,size_t size) {
    if (RTA_SPACE(size)>o->capacity-o->size) return -EMSGSIZE;
    struct rtattr h={.rta_type=type,.rta_len=RTA_LENGTH(size)};
    append(o,&h,sizeof(h)); append(o,data,size);
    o->message->nlmsg_len+=RTA_SPACE(size); return 0;
}
static int done(struct output *o,const struct nlmsghdr *request,uint32_t port,int error,int dump,int capped) {
    if (dump && !error) { int zero=0; return begin(o,request,port,NLMSG_DONE,1,&zero,sizeof(zero)); }
    if (error || (request->nlmsg_flags&NLM_F_ACK)) {
        struct nlmsgerr e={.error=error,.msg=*request};
        int result=begin(o,request,port,NLMSG_ERROR,0,&e,sizeof(e));
        if (result) return result;
        if (!error || capped) o->message->nlmsg_flags|=NLM_F_CAPPED;
        else {
            size_t payload=request->nlmsg_len-sizeof(*request);
            result=append(o,NLMSG_DATA(request),payload);
            if (!result) o->message->nlmsg_len+=payload;
        }
        return result;
    }
    return 0;
}
static unsigned flags(const struct md_network_interface *link) {
    return link->info.flags | ((link->info.flags&IFF_UP) ? IFF_RUNNING|IFF_LOWER_UP : 0);
}
static int link_reply(struct output *out,const struct nlmsghdr *h,uint32_t port,int dump,
        const struct md_network_interface *link) {
    struct ifinfomsg m={.ifi_family=AF_UNSPEC,.ifi_type=link->info.type,
        .ifi_index=link->info.index,.ifi_flags=flags(link)};
    int error=begin(out,h,port,RTM_NEWLINK,dump,&m,sizeof(m));
    if (!error) error=attribute(out,IFLA_IFNAME,link->info.name,strlen(link->info.name)+1);
    if (!error) error=attribute(out,IFLA_MTU,&link->info.mtu,sizeof(link->info.mtu));
    if (!error) error=attribute(out,IFLA_TXQLEN,&link->info.tx_queue_length,sizeof(link->info.tx_queue_length));
    if (!error) error=attribute(out,IFLA_ADDRESS,link->info.address,6);
    unsigned char state=(link->info.flags&IFF_UP) ? IF_OPER_UNKNOWN : IF_OPER_DOWN;
    if (!error) error=attribute(out,IFLA_OPERSTATE,&state,1);
    if (!error && link->master) error=attribute(out,IFLA_MASTER,&link->master,sizeof(link->master));
    if (!error && link->peer) error=attribute(out,IFLA_LINK,&link->peer,sizeof(link->peer));
    if (!error && (link->kind==MD_LINK_VETH || link->kind==MD_LINK_BRIDGE)) {
        const char *kind=link->kind==MD_LINK_VETH ? "veth" : "bridge";
        unsigned char data[RTA_SPACE(7)]={0};
        struct rtattr *a=(void *)data; a->rta_type=IFLA_INFO_KIND; a->rta_len=RTA_LENGTH(strlen(kind)+1);
        memcpy(RTA_DATA(a),kind,strlen(kind)+1);
        /* rtnl_link_fill uses nla_nest_start_noflag for this legacy nest. */
        error=attribute(out,IFLA_LINKINFO,data,RTA_ALIGN(a->rta_len));
    }
    return error;
}
struct link_change {
    const char *name,*peer_name;
    char name_storage[IFNAMSIZ],peer_storage[IFNAMSIZ];
    enum md_network_link_kind kind;
    unsigned index,master,mtu,change,flags,tx_queue_length,peer_tx_queue_length;
    int has_master,has_mtu,has_address,namespace_fd,has_tx_queue_length,has_peer_tx_queue_length;
    unsigned char address[6];
};
static int parse_link(const struct nlmsghdr *h,struct link_change *change,struct attrs *a) {
    if (h->nlmsg_len<NLMSG_LENGTH(sizeof(struct ifinfomsg))) return -EINVAL;
    const struct ifinfomsg *m=NLMSG_DATA(h);
    if (m->ifi_index<0 || (m->ifi_family!=AF_UNSPEC && m->ifi_family!=AF_PACKET)) return -EINVAL;
    *change=(struct link_change){.index=(unsigned)m->ifi_index,.change=m->ifi_change,.flags=m->ifi_flags,
        .namespace_fd=-1};
    int error=attributes(IFLA_RTA(m),h->nlmsg_len-NLMSG_LENGTH(sizeof(*m)),a,IFLA_MAX);
    for (unsigned i=1;!error && i<=IFLA_MAX;++i) {
        const struct rtattr *v=a->v[i]; if (!v) continue;
        switch (i) {
        case IFLA_IFNAME:
            error=string(v,change->name_storage,IFNAMSIZ); change->name=change->name_storage; break;
        case IFLA_MTU: error=number(v,&change->mtu); change->has_mtu=1; break;
        case IFLA_TXQLEN: error=number(v,&change->tx_queue_length); change->has_tx_queue_length=1; break;
        case IFLA_MASTER: error=number(v,&change->master); change->has_master=1; break;
        case IFLA_ADDRESS:
            if (RTA_PAYLOAD(v)!=6) error=-EINVAL;
            else { memcpy(change->address,RTA_DATA(v),6); change->has_address=1; } break;
        case IFLA_NET_NS_FD: {
            uint32_t fd=0; error=number(v,&fd); change->namespace_fd=(int)fd;
            if (!error && (int)fd<0) error=-EBADF; break;
        }
        case IFLA_EXT_MASK: {
            uint32_t mask; error=number(v,&mask);
            if (!error && (mask&~(RTEXT_FILTER_VF|RTEXT_FILTER_SKIP_STATS))) error=-EOPNOTSUPP;
            break;
        }
        case IFLA_LINKINFO: break;
        default: error=-EOPNOTSUPP;
        }
    }
    if (error || !a->v[IFLA_LINKINFO]) return error;
    struct attrs info;
    error=attributes(RTA_DATA(a->v[IFLA_LINKINFO]),RTA_PAYLOAD(a->v[IFLA_LINKINFO]),&info,IFLA_INFO_MAX);
    if (error || !info.v[IFLA_INFO_KIND]) return error ? error : -EINVAL;
    for (unsigned i=1;i<=IFLA_INFO_MAX;++i)
        if (info.v[i] && i!=IFLA_INFO_KIND && i!=IFLA_INFO_DATA) return -EOPNOTSUPP;
    if (kind_is(info.v[IFLA_INFO_KIND],"bridge")) {
        change->kind=MD_LINK_BRIDGE;
        if (info.v[IFLA_INFO_DATA] && RTA_PAYLOAD(info.v[IFLA_INFO_DATA])) return -EOPNOTSUPP;
        return 0;
    }
    if (!kind_is(info.v[IFLA_INFO_KIND],"veth")) return -EOPNOTSUPP;
    change->kind=MD_LINK_VETH;
    if (!info.v[IFLA_INFO_DATA]) return -EINVAL;
    struct attrs data;
    error=attributes(RTA_DATA(info.v[IFLA_INFO_DATA]),RTA_PAYLOAD(info.v[IFLA_INFO_DATA]),&data,VETH_INFO_MAX);
    if (error || !data.v[VETH_INFO_PEER]) return error ? error : -EINVAL;
    const struct rtattr *peer=data.v[VETH_INFO_PEER];
    if (RTA_PAYLOAD(peer)<sizeof(struct ifinfomsg)) return -EINVAL;
    const struct ifinfomsg *p=RTA_DATA(peer);
    if (p->ifi_index || p->ifi_flags || p->ifi_change) return -EOPNOTSUPP;
    struct attrs peer_attrs;
    error=attributes(p+1,RTA_PAYLOAD(peer)-sizeof(*p),&peer_attrs,IFLA_MAX);
    if (error) return error;
    for (unsigned i=1;i<=IFLA_MAX;++i) if (peer_attrs.v[i]) {
        if (i==IFLA_TXQLEN) {
            error=number(peer_attrs.v[i],&change->peer_tx_queue_length);
            if (error) return error;
            change->has_peer_tx_queue_length=1;
        } else if (i!=IFLA_IFNAME) return -EOPNOTSUPP;
    }
    if (!peer_attrs.v[IFLA_IFNAME]) return -EINVAL;
    change->peer_name=change->peer_storage;
    return string(peer_attrs.v[IFLA_IFNAME],change->peer_storage,IFNAMSIZ);
}
static int change_link(struct md_network_namespace *n,const struct nlmsghdr *h,const struct link_change *c,
        struct md_network_namespace *target) {
    struct md_network_interface *link=md_network_interface_find(n,c->index,c->name);
    if (h->nlmsg_type==RTM_DELLINK) return link ? md_network_interface_remove(n,link->info.index) : -ENODEV;
    if (c->change&~IFF_UP || (c->has_mtu && (c->mtu<68 || c->mtu>65535))) return -EOPNOTSUPP;
    if (c->has_master && c->master) {
        struct md_network_interface *master=md_network_interface_find(n,c->master,NULL);
        if (!master || master->kind!=MD_LINK_BRIDGE) return -EINVAL;
    }
    if (link && (h->nlmsg_flags&NLM_F_EXCL) && (h->nlmsg_flags&NLM_F_CREATE)) return -EEXIST;
    if (!link) {
        if (!(h->nlmsg_flags&NLM_F_CREATE)) return -ENODEV;
        if (!c->name || !c->kind || c->index || target) return -EOPNOTSUPP;
        if (c->kind==MD_LINK_VETH && (!c->peer_name || !strcmp(c->peer_name,c->name))) return -EINVAL;
        if (c->peer_name && md_network_interface_find(n,0,c->peer_name)) return -EEXIST;
        int error=md_network_interface_reserve(n,c->kind==MD_LINK_VETH ? 2 : 1);
        unsigned index=0,peer=0;
        if (!error) error=md_network_interface_add(n,c->kind,c->name,&index);
        if (error) return error;
        if (c->kind==MD_LINK_VETH) {
            error=md_network_interface_add(n,MD_LINK_VETH,c->peer_name,&peer);
            if (error) { md_network_interface_remove(n,index); return error; }
            md_network_interface_find(n,peer,NULL)->peer=index;
            if (c->has_peer_tx_queue_length)
                md_network_interface_find(n,peer,NULL)->info.tx_queue_length=c->peer_tx_queue_length;
        }
        link=md_network_interface_find(n,index,NULL); link->peer=peer;
    } else if (c->kind && c->kind!=link->kind) return -EOPNOTSUPP;
    if ((target && target!=n) || (c->name && strcmp(c->name,link->info.name))) {
        unsigned index=link->info.index;
        int error=md_network_interface_move(n,index,target ? target : n,c->name);
        if (error) return error;
        link=md_network_interface_find(target ? target : n,index,NULL);
    }
    if (target && c->has_master) return -EOPNOTSUPP;
    link->info.flags=(link->info.flags&~c->change)|(c->flags&c->change);
    if (c->has_master) link->master=c->master;
    if (c->has_mtu) link->info.mtu=c->mtu;
    if (c->has_tx_queue_length) link->info.tx_queue_length=c->tx_queue_length;
    if (c->has_address) memcpy(link->info.address,c->address,6);
    return 0;
}
static int address_reply(struct output *o,const struct nlmsghdr *h,uint32_t port,int dump,const struct md_network_interface *link) {
    struct ifaddrmsg m={.ifa_family=AF_INET,.ifa_prefixlen=link->prefix,.ifa_flags=IFA_F_PERMANENT,
        .ifa_scope=link->kind==MD_LINK_LOOPBACK ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE,.ifa_index=link->info.index};
    int error=begin(o,h,port,RTM_NEWADDR,dump,&m,sizeof(m));
    if (!error) error=attribute(o,IFA_ADDRESS,&link->ipv4,sizeof(link->ipv4));
    if (!error) error=attribute(o,IFA_LOCAL,&link->ipv4,sizeof(link->ipv4));
    if (!error) error=attribute(o,IFA_LABEL,link->info.name,strlen(link->info.name)+1);
    return error;
}
static int addresses(struct md_network_namespace *n,const struct nlmsghdr *h,uint32_t port,int dump,struct output *o) {
    if (h->nlmsg_len<NLMSG_LENGTH(sizeof(struct ifaddrmsg))) return -EINVAL;
    const struct ifaddrmsg *m=NLMSG_DATA(h);
    if (m->ifa_family!=AF_UNSPEC && m->ifa_family!=AF_INET) return h->nlmsg_type==RTM_GETADDR && dump ? 0 : -EAFNOSUPPORT;
    if (h->nlmsg_type==RTM_GETADDR) {
        int found=0;
        for (unsigned i=0;i<n->count;++i) if (n->links[i].ipv4 && (!m->ifa_index || n->links[i].info.index==m->ifa_index)) {
            int error=address_reply(o,h,port,dump,&n->links[i]); if (error) return error; found=1;
        }
        return dump || found ? 0 : -EADDRNOTAVAIL;
    }
    struct md_network_interface *link=md_network_interface_find(n,m->ifa_index,NULL);
    if (!link) return -ENODEV;
    if (m->ifa_family!=AF_INET || m->ifa_prefixlen>32) return -EINVAL;
    if (m->ifa_scope!=(link->kind==MD_LINK_LOOPBACK ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE)) return -EOPNOTSUPP;
    struct attrs a;
    int error=attributes(IFA_RTA(m),h->nlmsg_len-NLMSG_LENGTH(sizeof(*m)),&a,IFA_MAX);
    uint32_t address=0;
    for (unsigned i=1;!error && i<=IFA_MAX;++i) if (a.v[i]) {
        if (i==IFA_ADDRESS || i==IFA_LOCAL) {
            uint32_t value=0; error=number(a.v[i],&value);
            if (!error && address && value!=address) error=-EOPNOTSUPP;
            address=value;
        } else if (i==IFA_LABEL) {
            char label[IFNAMSIZ]; error=string(a.v[i],label,IFNAMSIZ);
            if (!error && strcmp(label,link->info.name)) error=-EOPNOTSUPP;
        } else if (i==IFA_BROADCAST || i==IFA_FLAGS) { uint32_t ignored; error=number(a.v[i],&ignored); }
        else error=-EOPNOTSUPP;
    }
    if (error) return error;
    if (!address) return -EINVAL;
    if (h->nlmsg_type==RTM_DELADDR) {
        if (link->ipv4!=address || link->prefix!=m->ifa_prefixlen) return -EADDRNOTAVAIL;
        link->ipv4=0; link->prefix=0; return 0;
    }
    if (link->ipv4 && ((h->nlmsg_flags&NLM_F_EXCL) || link->ipv4!=address)) return -EEXIST;
    link->ipv4=address; link->prefix=m->ifa_prefixlen; return 0;
}
static int route_reply(struct output *o,const struct nlmsghdr *h,uint32_t port,int dump,
        const struct md_network_interface *link,uint32_t gateway,const uint32_t *lookup) {
    struct rtmsg m={.rtm_family=AF_INET,.rtm_dst_len=lookup ? 32 : gateway ? 0 : link->prefix,.rtm_table=RT_TABLE_MAIN,
        .rtm_protocol=gateway ? RTPROT_BOOT : RTPROT_KERNEL,.rtm_scope=gateway ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK,
        .rtm_type=RTN_UNICAST};
    int error=begin(o,h,port,RTM_NEWROUTE,dump,&m,sizeof(m));
    if (!error) error=attribute(o,RTA_OIF,&link->info.index,sizeof(link->info.index));
    if (!error && gateway) error=attribute(o,RTA_GATEWAY,&gateway,sizeof(gateway));
    if (!error && (!gateway || lookup)) {
        uint32_t mask=link->prefix ? htonl(UINT32_MAX<<(32-link->prefix)) : 0;
        uint32_t destination=lookup ? *lookup : link->ipv4&mask;
        error=attribute(o,RTA_DST,&destination,sizeof(destination));
        if (!error) error=attribute(o,RTA_PREFSRC,&link->ipv4,sizeof(link->ipv4));
    }
    return error;
}
static int route_lookup(struct md_network_namespace *n,const struct nlmsghdr *h,uint32_t port,struct output *o) {
    const struct rtmsg *m=NLMSG_DATA(h);
    if (m->rtm_family!=AF_INET || m->rtm_dst_len!=32 || m->rtm_src_len || m->rtm_tos
            || (m->rtm_flags&~RTM_F_LOOKUP_TABLE) || (m->rtm_table && m->rtm_table!=RT_TABLE_MAIN)) return -EOPNOTSUPP;
    struct attrs a; int error=attributes(RTM_RTA(m),h->nlmsg_len-NLMSG_LENGTH(sizeof(*m)),&a,RTA_MAX);
    uint32_t destination=0,index=0;
    for (unsigned i=1;!error && i<=RTA_MAX;++i) if (a.v[i]) {
        if (i==RTA_DST) error=number(a.v[i],&destination);
        else if (i==RTA_OIF) error=number(a.v[i],&index);
        else if (i==RTA_UID) { uint32_t uid; error=number(a.v[i],&uid); }
        else error=-EOPNOTSUPP;
    }
    if (error) return error;
    if (!a.v[RTA_DST]) return -EINVAL;
    uint32_t gateway=0;
    struct md_network_interface *link=md_network_route_find(n,destination,&gateway);
    if (!link || (index && index!=link->info.index)) return -ENETUNREACH;
    return route_reply(o,h,port,0,link,gateway,&destination);
}
static int routes(struct md_network_namespace *n,const struct nlmsghdr *h,uint32_t port,int dump,struct output *o) {
    if (h->nlmsg_len<NLMSG_LENGTH(sizeof(struct rtmsg))) return -EINVAL;
    const struct rtmsg *m=NLMSG_DATA(h);
    if (m->rtm_family!=AF_UNSPEC && m->rtm_family!=AF_INET) return h->nlmsg_type==RTM_GETROUTE && dump ? 0 : -EAFNOSUPPORT;
    if (h->nlmsg_type==RTM_GETROUTE) {
        if (!dump) return route_lookup(n,h,port,o);
        if (m->rtm_table && m->rtm_table!=RT_TABLE_MAIN) return 0;
        for (unsigned i=0;i<n->count;++i) if (n->links[i].ipv4) {
            int error=route_reply(o,h,port,1,&n->links[i],0,NULL); if (error) return error;
            if (n->links[i].info.index==n->default_interface) {
                error=route_reply(o,h,port,1,&n->links[i],n->default_gateway,NULL); if (error) return error;
            }
        }
        return 0;
    }
    if (m->rtm_family!=AF_INET || m->rtm_table!=RT_TABLE_MAIN || m->rtm_dst_len || m->rtm_src_len
            || m->rtm_tos || m->rtm_type!=RTN_UNICAST || m->rtm_flags) return -EOPNOTSUPP;
    struct attrs a; int error=attributes(RTM_RTA(m),h->nlmsg_len-NLMSG_LENGTH(sizeof(*m)),&a,RTA_MAX);
    unsigned index=0; uint32_t gateway=0;
    for (unsigned i=1;!error && i<=RTA_MAX;++i) if (a.v[i]) {
        if (i==RTA_OIF) error=number(a.v[i],&index);
        else if (i==RTA_GATEWAY) error=number(a.v[i],&gateway);
        else error=-EOPNOTSUPP;
    }
    if (error) return error;
    struct md_network_interface *link=md_network_interface_find(n,index,NULL);
    if (!link || !link->ipv4 || !gateway) return -ENETUNREACH;
    if (h->nlmsg_type==RTM_DELROUTE) {
        if (n->default_interface!=index || n->default_gateway!=gateway) return -ESRCH;
        n->default_interface=0; n->default_gateway=0; return 0;
    }
    if (n->default_interface && !(h->nlmsg_flags&NLM_F_REPLACE)) return -EEXIST;
    n->default_interface=index; n->default_gateway=gateway; return 0;
}
struct topology_checkpoint {
    struct md_network_namespace *space;
    struct md_network_interface *links;
    unsigned count,default_interface;
    uint32_t default_gateway;
};
static int checkpoint(struct topology_checkpoint *saved,struct md_network_namespace *n) {
    if (!n) return 0;
    struct md_network_interface *links=n->count ? malloc(n->count*sizeof(*links)) : NULL;
    if (n->count && !links) return -ENOMEM;
    if (n->count) memcpy(links,n->links,n->count*sizeof(*links));
    *saved=(struct topology_checkpoint){.space=n,.links=links,.count=n->count,
        .default_interface=n->default_interface,.default_gateway=n->default_gateway};
    return 0;
}
static void checkpoint_finish(struct topology_checkpoint *saved,int commit) {
    struct md_network_namespace *n=saved->space;
    if (!n) return;
    if (!commit) {
        free(n->links); n->links=saved->links; saved->links=NULL;
        n->count=n->capacity=saved->count;
        n->default_interface=saved->default_interface; n->default_gateway=saved->default_gateway;
    }
    free(saved->links);
}
long md_network_route(struct md_network_namespace *n,const struct md_identity *identity,
        const struct nlmsghdr *h,size_t size,uint32_t port,int capped,const struct md_network_target *resolver,
        void *data,size_t capacity,const struct md_network_publication *publication) {
    if (size<sizeof(*h) || h->nlmsg_len!=size || !(h->nlmsg_flags&NLM_F_REQUEST)) return -EINVAL;
    int query=h->nlmsg_type==RTM_GETLINK || h->nlmsg_type==RTM_GETADDR || h->nlmsg_type==RTM_GETROUTE;
    int dump=query && (h->nlmsg_flags&NLM_F_DUMP)==NLM_F_DUMP;
    const struct nlmsghdr *original=h;
    struct { struct nlmsghdr header; struct ifinfomsg body; } expanded={0};
    if (dump) {
        size_t payload=h->nlmsg_type==RTM_GETLINK ? sizeof(struct ifinfomsg)
            : h->nlmsg_type==RTM_GETADDR ? sizeof(struct ifaddrmsg) : sizeof(struct rtmsg);
        /* Legacy rtnetlink dumps carry only rtgenmsg's family (glibc pads it
         * to four bytes). Mutation and lookup requests retain strict parsing. */
        if (size>=NLMSG_LENGTH(sizeof(struct rtgenmsg)) && size<NLMSG_LENGTH(payload)) {
            expanded.header=*h;
            expanded.header.nlmsg_len=NLMSG_LENGTH(payload);
            expanded.body.ifi_family=((const struct rtgenmsg *)NLMSG_DATA(h))->rtgen_family;
            h=&expanded.header;
        }
    }
    int error=!query && !md_identity_capable_in(identity,n->owner,CAP_NET_ADMIN) ? -EPERM : 0;
    struct output out={.data=data,.capacity=capacity};
    struct link_change change={0}; struct attrs attrs={0}; struct md_network_namespace *target=NULL;
    int link=h->nlmsg_type==RTM_GETLINK || h->nlmsg_type==RTM_NEWLINK || h->nlmsg_type==RTM_SETLINK || h->nlmsg_type==RTM_DELLINK;
    if (!error && link) error=parse_link(h,&change,&attrs);
    if (!error && link && change.namespace_fd>=0) {
        error=resolver && resolver->resolve ? resolver->resolve(resolver->context,change.namespace_fd,&target) : -EOPNOTSUPP;
        if (!error && (!md_identity_capable_in(identity,target->owner,CAP_NET_ADMIN))) error=-EPERM;
        if (!error && target->fabric!=n->fabric) error=-EXDEV;
        if (!error && (query || change.has_master)) error=-EOPNOTSUPP;
    }
    pthread_mutex_lock(&n->fabric->lock);
    /* A link mutation touches its owner and at most one peer/move target.
     * Queries and socket data IO allocate no topology journal. The lock keeps
     * tentative edits invisible until their response enters the native queue. */
    struct topology_checkpoint saved[2]={0};
    unsigned next_index=n->fabric->next_index;
    if (!error && !query) {
        struct md_network_namespace *other=target;
        if (h->nlmsg_type==RTM_DELLINK) {
            struct md_network_interface *found=md_network_interface_find(n,change.index,change.name);
            if (found) other=md_network_interface_owner(n->fabric,found->peer);
        }
        error=checkpoint(&saved[0],n);
        if (!error && other && other!=n) error=checkpoint(&saved[1],other);
    }
    if (!error) {
        if (h->nlmsg_type==RTM_GETLINK) {
            if (dump) {
                for (unsigned i=0;!error && i<n->count;++i) error=link_reply(&out,h,port,1,&n->links[i]);
            } else {
                struct md_network_interface *found=md_network_interface_find(n,change.index,change.name);
                error=found ? link_reply(&out,h,port,0,found) : -ENODEV;
            }
        } else if (link) error=change_link(n,h,&change,target);
        else if (h->nlmsg_type==RTM_GETADDR || h->nlmsg_type==RTM_NEWADDR || h->nlmsg_type==RTM_DELADDR)
            error=addresses(n,h,port,dump,&out);
        else if (h->nlmsg_type==RTM_GETROUTE || h->nlmsg_type==RTM_NEWROUTE || h->nlmsg_type==RTM_DELROUTE)
            error=routes(n,h,port,dump,&out);
        else error=-EOPNOTSUPP;
    }
    if (error) out.size=0;
    int encoded=done(&out,original,port,error,dump,capped);
    if (!encoded && out.size && publication)
        encoded=publication->publish(publication->context,out.data,out.size);
    int commit=!error && !encoded;
    for (unsigned i=0;i<2;++i) checkpoint_finish(&saved[i],commit);
    if (!query && !commit) n->fabric->next_index=next_index;
    pthread_mutex_unlock(&n->fabric->lock);
    md_network_namespace_release(target);
    return encoded ? encoded : (long)out.size;
}
