#ifndef MD_NETWORK_ROUTE_H
#define MD_NETWORK_ROUTE_H
#include "network_namespace.h"
#include <linux/netlink.h>
/* Resolves a captured guest namespace handle, never a host PID/path. */
struct md_network_target {
    void *context;
    int (*resolve)(void *,int,struct md_network_namespace **);
};
/* Called under the fabric lock. Must not block or access guest memory.
 * A failed publication leaves the topology unchanged. */
struct md_network_publication {
    void *context;
    int (*publish)(void *,const void *,size_t);
};
int md_network_route_query(unsigned);
enum { MD_NETWORK_ROUTE_CAPPED_ACK=1, MD_NETWORK_ROUTE_STRICT=2 };
long md_network_route(struct md_network_namespace *,const struct md_identity *,
    const struct nlmsghdr *,size_t,uint32_t,unsigned options,const struct md_network_target *,void *,size_t,
    const struct md_network_publication *);
#endif
