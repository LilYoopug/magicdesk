#ifndef MD_NETWORK_INTERNAL_H
#define MD_NETWORK_INTERNAL_H
#include "network_namespace.h"
#include <pthread.h>

struct md_network_ipv4_policy { uint32_t route_localnet, rp_filter, arp_notify; };
struct md_network_interface {
    struct md_network_link info;
    enum md_network_link_kind kind;
    unsigned master, peer, prefix, hairpin, isolated;
    uint32_t ipv4;
    uint64_t policy_id;
    struct md_network_ipv4_policy policy;
};
struct md_network_fabric {
    atomic_uint references;
    pthread_mutex_t lock;
    unsigned next_index;
    struct md_network_namespace *spaces;
    struct md_network_endpoint *endpoints;
    int endpoints_enabled;
    uint64_t policy_generation;
    struct md_network_forward *forward;
};
struct md_network_namespace {
    atomic_uint references;
    uint64_t inode, next_policy;
    struct md_user_namespace *owner;
    enum md_network_mode mode;
    struct md_network_fabric *fabric;
    struct md_network_namespace *next;
    struct md_network_interface *links;
    unsigned count, capacity;
    unsigned default_interface;
    uint32_t default_gateway, default_metric;
    uint32_t unprivileged_port, ping_groups[2], local_ports[2];
    uint32_t next_port, ipv4_forward;
    uint32_t tcp_keepalive[3];
    struct md_network_ipv4_policy all, defaults;
    struct md_network_listener *listeners;
    struct md_network_ethernet *ethernet;
    struct md_network_filter *filter;
};
/* Weak listeners are removed under the fabric lock before final FD release.
 * Only committed topology changes are broadcast. Delivery never blocks. */
struct md_network_listener {
    struct md_network_listener *next;
    int peer, protocol;
    uint32_t groups, port;
    int overflow;
};
void md_network_broadcast(struct md_network_namespace *,unsigned,const void *,size_t);
/* Mutators below run under the fabric lock. No guest IO or blocking syscall
 * may span that lock. Namespaces are weakly listed and unlink before release. */
struct md_network_interface *md_network_interface_find(struct md_network_namespace *,unsigned,const char *);
/* Caller holds the fabric lock; all link observers share this projection. */
struct md_network_link md_network_interface_snapshot(struct md_network_namespace *,const struct md_network_interface *);
int md_network_interface_reserve(struct md_network_namespace *,unsigned);
int md_network_interface_add(struct md_network_namespace *,enum md_network_link_kind,const char *,unsigned *);
int md_network_interface_remove(struct md_network_namespace *,unsigned);
int md_network_interface_move(struct md_network_namespace *,unsigned,struct md_network_namespace *,const char *);
/* NULL ingress denotes locally generated bridge traffic. */
int md_network_bridge_forward(const struct md_network_interface *ingress,const struct md_network_interface *egress);
struct md_network_namespace *md_network_interface_owner(struct md_network_fabric *,unsigned);
struct md_network_interface *md_network_route_find(struct md_network_namespace *,uint32_t,uint32_t *gateway);
int md_network_ingress(struct md_network_namespace *,const struct md_network_interface *,uint32_t source,uint32_t destination);
#endif
