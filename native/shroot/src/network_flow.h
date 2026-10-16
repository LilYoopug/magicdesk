#ifndef MD_NETWORK_FLOW_H
#define MD_NETWORK_FLOW_H
#include "network_filter.h"
#include "network_internal.h"

struct md_network_flow_step {
    uint64_t space;
    unsigned hook, hairpin_port;
    struct md_filter_packet packet;
    struct md_filter_rewrite after;
};
struct md_network_flow_path {
    struct md_filter_packet original, translated;
    struct md_network_flow_step steps[16];
    unsigned count, mediated;
    uint64_t destination, generation;
};
/* Routing, policy and retained conntrack coordinates share the fabric lock. */
struct md_network_interface *md_network_local_interface(struct md_network_namespace *,uint32_t,int);
struct md_network_namespace *md_network_space_find(struct md_network_fabric *,uint64_t);
int md_network_flow_route(struct md_network_namespace *,struct md_filter_packet *,int,struct md_network_flow_path *);
int md_network_flow_check(struct md_network_fabric *,struct md_network_flow_path *,int);
int md_network_flow_accounting(struct md_network_fabric *,struct md_network_flow_path *,int,int,struct md_filter_accounting *);
int md_network_flow_admits(struct md_network_namespace *,struct md_network_filter *,const struct md_network_flow_path *);
#endif
