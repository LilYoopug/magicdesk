#ifndef MD_NETWORK_INTERNAL_H
#define MD_NETWORK_INTERNAL_H
#include "network_namespace.h"
#include <pthread.h>

enum md_network_link_kind { MD_LINK_LOOPBACK, MD_LINK_UPLINK, MD_LINK_BRIDGE, MD_LINK_VETH };
struct md_network_interface {
    struct md_network_link info;
    enum md_network_link_kind kind;
    unsigned master, peer, prefix;
    uint32_t ipv4;
};
struct md_network_fabric {
    atomic_uint references;
    pthread_mutex_t lock;
    unsigned next_index;
    struct md_network_namespace *spaces;
    struct md_network_endpoint *endpoints;
    int routed;
};
struct md_network_namespace {
    atomic_uint references;
    uint64_t inode;
    struct md_user_namespace *owner;
    enum md_network_mode mode;
    struct md_network_fabric *fabric;
    struct md_network_namespace *next;
    struct md_network_interface *links;
    unsigned count, capacity;
    unsigned default_interface;
    uint32_t default_gateway;
    uint32_t unprivileged_port, ping_groups[2], local_ports[2];
    uint32_t next_port;
    struct md_network_listener *listeners;
};
/* Weak listeners are removed under the fabric lock before final FD release.
 * Only committed topology changes are broadcast. Delivery never blocks. */
struct md_network_listener {
    struct md_network_listener *next;
    int peer, protocol;
    uint32_t groups;
    int overflow;
};
void md_network_broadcast(struct md_network_namespace *,unsigned,const void *,size_t);
/* Mutators below run under the fabric lock. No guest IO or blocking syscall
 * may span that lock. Namespaces are weakly listed and unlink before release. */
struct md_network_interface *md_network_interface_find(struct md_network_namespace *,unsigned,const char *);
int md_network_interface_reserve(struct md_network_namespace *,unsigned);
int md_network_interface_add(struct md_network_namespace *,enum md_network_link_kind,const char *,unsigned *);
int md_network_interface_remove(struct md_network_namespace *,unsigned);
int md_network_interface_move(struct md_network_namespace *,unsigned,struct md_network_namespace *,const char *);
struct md_network_namespace *md_network_interface_owner(struct md_network_fabric *,unsigned);
struct md_network_interface *md_network_route_find(struct md_network_namespace *,uint32_t,uint32_t *gateway);
#endif
