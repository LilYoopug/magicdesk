#ifndef MD_NETWORK_TRANSPORT_H
#define MD_NETWORK_TRANSPORT_H
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

struct md_network_route_metrics { uint32_t mtu, hops, present; };
struct md_network_transport_policy { uint32_t mtu, hops; };
struct md_network_transport {
    struct md_network_transport_policy route;
    int user_mtu, user_hops, user_mss;
    int applied_mtu, applied_hops, applied_mss;
};
#define MD_NETWORK_TRANSPORT_INITIALIZER { .user_hops=-1, .applied_hops=-1 }
static inline int md_network_transport_option(unsigned level,unsigned option) {
    return (level==IPPROTO_IPV6 && (option==IPV6_MTU || option==IPV6_UNICAST_HOPS))
        || (level==IPPROTO_TCP && option==TCP_MAXSEG);
}
/* Native socket policy is installed at connection/address preparation, never
 * on ordinary stream IO. Application options remain the stricter/explicit input. */
int md_network_transport_apply(struct md_network_transport *,int,int,struct md_network_transport_policy);
int md_network_transport_set(struct md_network_transport *,int,int,unsigned,unsigned,int);
#endif
