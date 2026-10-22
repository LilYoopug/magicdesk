#ifndef MD_NETWORK_ETHERNET_H
#define MD_NETWORK_ETHERNET_H
#include "network_packet.h"
struct md_network_namespace;
struct md_ethernet_membership;
/* Weak namespace list, protected by the fabric lock. The control socket owns
 * the queue and lifetime; no raw socket is opened on Android. */
struct md_network_ethernet {
    struct md_network_ethernet *next;
    struct md_network_namespace *space;
    struct md_ethernet_membership *memberships;
    int peer, type, ignore_outgoing, overflow;
    unsigned index;
    uint64_t policy;
    uint16_t protocol;
};
void md_network_ethernet_attach(struct md_network_ethernet *,struct md_network_namespace *,int,int,int);
void md_network_ethernet_detach(struct md_network_ethernet *);
long md_network_ethernet_call(struct md_network_ethernet *,long,const unsigned long *,void *,size_t,size_t,
    const struct md_network_address *);
#endif
