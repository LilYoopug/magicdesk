#ifndef MD_NETWORK_ROUTE_H
#define MD_NETWORK_ROUTE_H
#include "network_namespace.h"
#include "network_message.h"
#include <linux/netlink.h>
enum md_network_target_kind { MD_NETWORK_TARGET_NONE, MD_NETWORK_TARGET_FD, MD_NETWORK_TARGET_PID };
struct md_network_target_reference { enum md_network_target_kind kind; int value; };
/* Resolves guest descriptors or guest-visible PIDs, never host PID/path input. */
struct md_network_target {
    void *context;
    int (*resolve)(void *,struct md_network_target_reference,struct md_network_namespace **);
};
int md_network_route_query(unsigned);
/* Legacy ioctl admission uses the same transaction, policy and notifications. */
int md_network_route_set_address(struct md_network_namespace *,const struct md_identity *,const char *,const unsigned char [6]);
int md_network_route_set_flags(struct md_network_namespace *,const struct md_identity *,const char *,unsigned);
int md_network_route_set_mtu(struct md_network_namespace *,const struct md_identity *,const char *,unsigned);
int md_network_route_attach_bridge(struct md_network_namespace *,const struct md_identity *,const char *,unsigned);
enum { MD_NETWORK_ROUTE_CAPPED_ACK=1, MD_NETWORK_ROUTE_STRICT=2 };
long md_network_route(struct md_network_namespace *,const struct md_identity *,
    const struct nlmsghdr *,size_t,uint32_t,unsigned options,const struct md_network_target *,void *,size_t,
    const struct md_network_publication *);
#endif
