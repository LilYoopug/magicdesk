#ifndef MD_NETWORK_MULTICAST_H
#define MD_NETWORK_MULTICAST_H
#include "network_ip.h"

struct md_network_namespace;
struct md_network_interface;
struct md_multicast_group;
struct md_network_multicast {
    struct md_network_multicast *next;
    struct md_network_namespace *space;
    struct md_multicast_group *groups;
    unsigned count, output;
    uint64_t output_policy;
    struct md_ip_address address;
    int hops, loop, all;
};
#define MD_NETWORK_MULTICAST_INITIALIZER { .hops=1, .loop=1, .all=1 }
static inline int md_network_multicast_option(unsigned level,unsigned option) {
    if (level==IPPROTO_IP) switch (option) {
    case IP_MULTICAST_IF: case IP_MULTICAST_TTL: case IP_MULTICAST_LOOP:
    case IP_MULTICAST_ALL: case IP_ADD_MEMBERSHIP: case IP_DROP_MEMBERSHIP:
    case IP_ADD_SOURCE_MEMBERSHIP: case IP_DROP_SOURCE_MEMBERSHIP:
    case IP_BLOCK_SOURCE: case IP_UNBLOCK_SOURCE: case IP_MSFILTER: return 1;
    }
    if (level==IPPROTO_IPV6) switch (option) {
    case IPV6_MULTICAST_IF: case IPV6_MULTICAST_HOPS: case IPV6_MULTICAST_LOOP:
    case IPV6_MULTICAST_ALL: case IPV6_ADD_MEMBERSHIP: case IPV6_DROP_MEMBERSHIP: return 1;
    }
    if (level==IPPROTO_IP || level==IPPROTO_IPV6) switch (option) {
    case MCAST_JOIN_GROUP: case MCAST_LEAVE_GROUP: case MCAST_JOIN_SOURCE_GROUP:
    case MCAST_LEAVE_SOURCE_GROUP: case MCAST_BLOCK_SOURCE: case MCAST_UNBLOCK_SOURCE:
    case MCAST_MSFILTER: return 1;
    }
    return 0;
}
/* Caller owns the fabric turn. Unsupported source filters never reach Android. */
int md_network_multicast_option_io(struct md_network_namespace *,struct md_network_multicast *,
    unsigned,unsigned,int,unsigned,unsigned,void *,socklen_t *);
int md_network_multicast_joined(const struct md_network_multicast *,const struct md_network_interface *,struct md_ip_address);
int md_network_multicast_subscribed(const struct md_network_namespace *,const struct md_network_interface *,struct md_ip_address);
int md_network_multicast_output(struct md_network_namespace *,const struct md_network_multicast *,unsigned *);
void md_network_multicast_attach(struct md_network_multicast *,struct md_network_namespace *);
void md_network_multicast_destroy(struct md_network_multicast *);
#endif
