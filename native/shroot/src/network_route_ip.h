#ifndef MD_NETWORK_ROUTE_IP_H
#define MD_NETWORK_ROUTE_IP_H
#include "network_internal.h"
#include "network_message.h"
int64_t md_network_lifetime_now(void);
uint32_t md_network_lifetime_remaining(int64_t,int64_t);

struct md_network_route_entry md_network_connected_route(const struct md_network_interface *,const struct md_network_ip_assignment *);
int md_network_address_has_route(const struct md_network_ip_assignment *);
int md_network_connected_index(const struct md_network_interface *,const struct md_network_ip_assignment *);
int md_network_address_reply(struct md_network_message *,const struct nlmsghdr *,uint32_t,int,
    const struct md_network_interface *,const struct md_network_ip_assignment *);
int md_network_route_reply(struct md_network_message *,const struct nlmsghdr *,uint32_t,int,
    const struct md_network_interface *,const struct md_network_route_entry *,const struct md_ip_address *);
int md_network_addresses(struct md_network_namespace *,const struct nlmsghdr *,uint32_t,int,struct md_network_message *);
int md_network_routes(struct md_network_namespace *,const struct nlmsghdr *,uint32_t,int,int,struct md_network_message *);
#endif
