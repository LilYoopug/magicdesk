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
long md_network_route(struct md_network_namespace *,const struct md_identity *,
    const struct nlmsghdr *,size_t,uint32_t,int capped_ack,const struct md_network_target *,void *,size_t,
    const struct md_network_publication *);
#endif
