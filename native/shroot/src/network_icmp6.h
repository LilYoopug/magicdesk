#ifndef MD_NETWORK_ICMP6_H
#define MD_NETWORK_ICMP6_H
#include "network_packet.h"
#include <netinet/icmp6.h>
struct md_network_namespace;
struct md_network_interface;
struct md_icmp6_membership;
/* Control-plane sockets share Ethernet delivery and the existing datagram
 * envelope. They never open privileged host sockets or intercept TCP/UDP IO. */
struct md_network_icmp6 {
    struct md_network_icmp6 *next;
    struct md_network_namespace *space;
    struct md_icmp6_membership *memberships;
    struct icmp6_filter filter;
    struct in6_addr local, remote;
    int peer, bound, connected, overflow, multicast_loop;
    int unicast_hops, multicast_hops, receive_hops, receive_info, timestamp, traffic_class;
    unsigned device, multicast_device, local_scope, remote_scope;
    uint64_t device_policy, multicast_policy, local_policy;
};
void md_network_icmp6_attach(struct md_network_icmp6 *,struct md_network_namespace *,int);
void md_network_icmp6_detach(struct md_network_icmp6 *);
long md_network_icmp6_call(struct md_network_icmp6 *,long,const unsigned long *,void *,size_t,size_t,
    const struct md_network_address *);
void md_network_icmp6_receive(struct md_network_namespace *,struct md_network_interface *,const void *,size_t);
int md_network_icmp6_options(const struct md_network_icmp6 *);
#endif
