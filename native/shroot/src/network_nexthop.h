#ifndef MD_NETWORK_NEXTHOP_H
#define MD_NETWORK_NEXTHOP_H
#include "network_internal.h"
#include "network_message.h"
const struct md_network_nexthop *md_network_nexthop_find(const struct md_network_namespace *,uint32_t);
int md_network_nexthop_reply(struct md_network_message *,const struct nlmsghdr *,uint32_t,int,
    const struct md_network_nexthop *);
int md_network_nexthops(struct md_network_namespace *,const struct nlmsghdr *,uint32_t,int,struct md_network_message *);
#endif
