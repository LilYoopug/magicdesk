#define _GNU_SOURCE
#include "network_ethernet.h"
#include "network_internal.h"
#include "network_icmp6.h"
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

struct md_ethernet_membership {
    struct md_ethernet_membership *next;
    struct packet_mreq request;
    uint64_t policy;
    unsigned count;
};
void md_network_ethernet_attach(struct md_network_ethernet *s,struct md_network_namespace *n,int peer,int type,int protocol) {
    *s=(struct md_network_ethernet){.space=n,.peer=peer,.type=type,.protocol=(uint16_t)protocol,.next=n->ethernet};
    n->ethernet=s;
}
void md_network_ethernet_detach(struct md_network_ethernet *s) {
    struct md_network_ethernet **at=&s->space->ethernet;
    while (*at && *at!=s) at=&(*at)->next;
    if (*at) *at=s->next;
    while (s->memberships) {
        struct md_ethernet_membership *m=s->memberships;
        s->memberships=m->next; free(m);
    }
}
static int membership(struct md_network_ethernet *s,int option,const void *data,size_t size) {
    if (size<sizeof(struct packet_mreq)) return -EINVAL;
    struct packet_mreq request; memcpy(&request,data,sizeof(request));
    if (request.mr_ifindex<=0 || request.mr_alen>ETH_ALEN) return -EINVAL;
    if (request.mr_type!=PACKET_MR_MULTICAST && request.mr_type!=PACKET_MR_UNICAST
            && request.mr_type!=PACKET_MR_PROMISC && request.mr_type!=PACKET_MR_ALLMULTI) return -EOPNOTSUPP;
    if ((request.mr_type==PACKET_MR_MULTICAST || request.mr_type==PACKET_MR_UNICAST)
            && request.mr_alen!=ETH_ALEN) return -EINVAL;
    struct md_network_interface *link=md_network_interface_find(s->space,(unsigned)request.mr_ifindex,NULL);
    if (!link) return option==PACKET_DROP_MEMBERSHIP ? 0 : -ENODEV;
    struct md_ethernet_membership **at=&s->memberships;
    while (*at && ((*at)->policy!=link->policy_id || (*at)->request.mr_type!=request.mr_type
            || (*at)->request.mr_alen!=request.mr_alen
            || memcmp((*at)->request.mr_address,request.mr_address,request.mr_alen))) at=&(*at)->next;
    if (option==PACKET_DROP_MEMBERSHIP) {
        if (*at && !--(*at)->count) { struct md_ethernet_membership *old=*at; *at=old->next; free(old); }
    } else if (*at) {
        if ((*at)->count==UINT_MAX) return -ENOBUFS;
        ++(*at)->count;
    } else {
        *at=calloc(1,sizeof(**at));
        if (!*at) return -ENOMEM;
        (*at)->request=request; (*at)->policy=link->policy_id; (*at)->count=1;
    }
    return 0;
}
static unsigned packet_type(const struct md_network_interface *link,const struct ethhdr *frame) {
    static const unsigned char broadcast[ETH_ALEN]={255,255,255,255,255,255};
    if (!memcmp(frame->h_dest,broadcast,ETH_ALEN)) return PACKET_BROADCAST;
    if (frame->h_dest[0]&1) return PACKET_MULTICAST;
    return memcmp(frame->h_dest,link->info.address,ETH_ALEN) ? PACKET_OTHERHOST : PACKET_HOST;
}
static void deliver(struct md_network_namespace *n,const struct md_network_interface *link,
        const struct md_network_ethernet *sender,const struct ethhdr *frame,size_t size,int outgoing) {
    struct md_network_packet header={.ethernet={.sll_family=AF_PACKET,.sll_ifindex=(int)link->info.index,
        .sll_protocol=frame->h_proto,.sll_hatype=link->info.type,.sll_halen=ETH_ALEN,
        .sll_pkttype=outgoing ? PACKET_OUTGOING : packet_type(link,frame)}};
    memcpy(header.ethernet.sll_addr,frame->h_source,ETH_ALEN);
    for (struct md_network_ethernet *s=n->ethernet;s;s=s->next) {
        if ((outgoing && s==sender) || !s->protocol || (s->index && (s->index!=link->info.index || s->policy!=link->policy_id))) continue;
        if (outgoing ? s->ignore_outgoing || s->protocol!=htons(ETH_P_ALL)
                : s->protocol!=htons(ETH_P_ALL) && s->protocol!=frame->h_proto) continue;
        size_t skip=s->type==SOCK_DGRAM ? sizeof(*frame) : 0;
        struct iovec vectors[]={{&header,sizeof(header)},{(char *)frame+skip,size-skip}};
        struct msghdr message={.msg_iov=vectors,.msg_iovlen=2};
        if (sendmsg(s->peer,&message,MSG_DONTWAIT|MSG_NOSIGNAL)<0 && errno!=ECONNREFUSED) s->overflow=1;
    }
}
struct hop { struct md_network_namespace *space; struct md_network_interface *link; int outgoing; };
static void enqueue(struct hop *queue,size_t *count,struct md_network_namespace *n,struct md_network_interface *link,int outgoing) {
    if (!link || !(link->info.flags&IFF_UP)) return;
    for (size_t i=0;i<*count;++i) if (queue[i].space==n && queue[i].link==link && queue[i].outgoing==outgoing) return;
    queue[(*count)++]=(struct hop){n,link,outgoing};
}
int md_network_ethernet_transmit(struct md_network_namespace *space,struct md_network_interface *source,
        const struct md_network_ethernet *s,const void *data,size_t size) {
    const struct ethhdr *frame=data;
    /* Every interface can be visited once in each direction. Allocate before
     * publication, then walk iteratively so bridge/veth cycles cannot recurse. */
    size_t capacity=0;
    for (struct md_network_namespace *n=space->fabric->spaces;n;n=n->next) {
        if (n->count>(SIZE_MAX/sizeof(struct hop)-capacity)/2) return -EOVERFLOW;
        capacity+=2*n->count;
    }
    struct hop *queue=calloc(capacity,sizeof(*queue));
    if (!queue) return -ENOMEM;
    size_t count=0;
    enqueue(queue,&count,space,source,1);
    static const unsigned char reserved[5]={1,0x80,0xc2,0,0};
    int link_local=!memcmp(frame->h_dest,reserved,sizeof(reserved)) && frame->h_dest[5]<=15;
    for (size_t at=0;at<count;++at) {
        struct hop hop=queue[at];
        struct md_network_interface *link=hop.link;
        deliver(hop.space,link,s,frame,size,hop.outgoing);
        if (!hop.outgoing && frame->h_proto==htons(ETH_P_IPV6))
            md_network_icmp6_receive(hop.space,link,frame,size);
        if (hop.outgoing && link->kind==MD_LINK_LOOPBACK) enqueue(queue,&count,hop.space,link,0);
        else if (hop.outgoing && link->kind==MD_LINK_VETH) {
            struct md_network_namespace *peer=md_network_interface_owner(hop.space->fabric,link->peer);
            if (peer) enqueue(queue,&count,peer,md_network_interface_find(peer,link->peer,NULL),0);
        } else if (link->kind==MD_LINK_BRIDGE || (!hop.outgoing && link->master)) {
            unsigned bridge=link->kind==MD_LINK_BRIDGE ? link->info.index : link->master;
            if (link->master) {
                struct md_network_interface *master=md_network_interface_find(hop.space,bridge,NULL);
                if (master && (master->info.flags&IFF_UP)) {
                    deliver(hop.space,master,s,frame,size,0);
                    if (frame->h_proto==htons(ETH_P_IPV6)) md_network_icmp6_receive(hop.space,master,frame,size);
                }
            }
            if (!link_local || hop.outgoing) for (unsigned i=0;i<hop.space->count;++i) {
                struct md_network_interface *port=&hop.space->links[i];
                if (port->master==bridge && md_network_bridge_forward(link->kind==MD_LINK_BRIDGE ? NULL : link,port))
                    enqueue(queue,&count,hop.space,port,1);
            }
        }
    }
    free(queue); return 0;
}
static long send_frame(struct md_network_ethernet *s,const void *data,size_t size,const struct md_network_address *destination) {
    struct sockaddr_ll address={.sll_ifindex=(int)s->index,.sll_protocol=s->protocol};
    if (destination && destination->size) {
        if (destination->size<sizeof(address) || destination->size>sizeof(destination->value)) return -EINVAL;
        memcpy(&address,&destination->value,sizeof(address));
        if (address.sll_family!=AF_PACKET || address.sll_ifindex<0) return -EINVAL;
    }
    struct md_network_interface *link=md_network_interface_find(s->space,(unsigned)address.sll_ifindex,NULL);
    if (!link || ((!destination || !destination->size) && s->index && s->policy!=link->policy_id)) return -ENXIO;
    if (!(link->info.flags&IFF_UP)) return -ENETDOWN;
    if (size>(size_t)link->info.mtu+(s->type==SOCK_RAW ? ETH_HLEN : 0)) return -EMSGSIZE;
    if (s->type==SOCK_RAW && size<ETH_HLEN) return -EINVAL;
    void *allocation=NULL;
    const struct ethhdr *frame=data;
    size_t length=size;
    if (s->type==SOCK_DGRAM) {
        if (!destination || !destination->size || address.sll_halen!=ETH_ALEN) return -EINVAL;
        allocation=malloc(size+ETH_HLEN);
        if (!allocation) return -ENOMEM;
        struct ethhdr header={.h_proto=address.sll_protocol};
        memcpy(header.h_dest,address.sll_addr,ETH_ALEN);
        memcpy(header.h_source,link->info.address,ETH_ALEN);
        memcpy(allocation,&header,sizeof(header)); memcpy((char *)allocation+ETH_HLEN,data,size);
        frame=allocation; length+=ETH_HLEN;
    }
    int error=md_network_ethernet_transmit(s->space,link,s,frame,length);
    free(allocation); return error ? error : (long)size;
}
long md_network_ethernet_call(struct md_network_ethernet *s,long nr,const unsigned long *a,void *data,size_t capacity,size_t size,
        const struct md_network_address *destination) {
    if (nr==SYS_sendto || nr==SYS_sendmsg || nr==SYS_write) return send_frame(s,data,size,destination);
    if (nr==SYS_connect) return -EOPNOTSUPP;
    if (nr==SYS_getpeername) return -EOPNOTSUPP;
    if (nr==SYS_bind) {
        if (size<sizeof(struct sockaddr_ll)) return -EINVAL;
        const struct sockaddr_ll *address=data;
        if (address->sll_family!=AF_PACKET || address->sll_ifindex<0) return -EINVAL;
        struct md_network_interface *link=md_network_interface_find(s->space,(unsigned)address->sll_ifindex,NULL);
        if (address->sll_ifindex && !link) return -ENODEV;
        s->index=(unsigned)address->sll_ifindex; s->policy=link ? link->policy_id : 0;
        if (address->sll_protocol) s->protocol=address->sll_protocol;
        return 0;
    }
    if (nr==SYS_getsockname) {
        if (capacity<sizeof(struct sockaddr_ll)) return -EINVAL;
        struct sockaddr_ll address={.sll_family=AF_PACKET,.sll_protocol=s->protocol,.sll_ifindex=(int)s->index};
        struct md_network_interface *link=md_network_interface_find(s->space,s->index,NULL);
        if (link && link->policy_id==s->policy) {
            address.sll_hatype=link->info.type; address.sll_halen=ETH_ALEN;
            memcpy(address.sll_addr,link->info.address,ETH_ALEN);
        }
        memcpy(data,&address,sizeof(address)); return sizeof(address);
    }
    if (nr==SYS_setsockopt && a[1]==SOL_PACKET) {
        if (a[2]==PACKET_ADD_MEMBERSHIP || a[2]==PACKET_DROP_MEMBERSHIP) return membership(s,(int)a[2],data,size);
        if (a[2]==PACKET_IGNORE_OUTGOING) {
            if (size!=sizeof(int)) return -EINVAL;
            int value; memcpy(&value,data,sizeof(value));
            if (value!=0 && value!=1) return -EINVAL;
            s->ignore_outgoing=value; return 0;
        }
    }
    if (nr==SYS_getsockopt && a[1]==SOL_PACKET && a[2]==PACKET_IGNORE_OUTGOING) {
        if (capacity<sizeof(int)) return -EINVAL;
        memcpy(data,&s->ignore_outgoing,sizeof(int)); return sizeof(int);
    }
    return -EOPNOTSUPP;
}
