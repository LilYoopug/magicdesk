#ifndef MD_NETWORK_FORWARD_H
#define MD_NETWORK_FORWARD_H
#include "network_flow.h"
#include <netinet/in.h>

struct md_network_forward_update;
struct md_network_port_reservation;
/* All methods except final fabric shutdown run under the fabric lock. New
 * listeners are prepared before ACK and become visible only with the ruleset. */
int md_network_forward_prepare(struct md_network_namespace *,struct md_network_filter *,struct md_network_forward_update **);
void md_network_forward_commit(struct md_network_forward_update *);
void md_network_forward_abort(struct md_network_forward_update *);
void md_network_forward_changed(struct md_network_fabric *);
void md_network_forward_retire(struct md_network_namespace *);
void md_network_forward_shutdown(struct md_network_fabric *);
int md_network_forward_route(struct md_network_namespace *,const void *,int,const struct sockaddr_in *,
    const struct sockaddr_in *,struct md_network_flow_path *,struct sockaddr_in *);
int md_network_forward_source(struct md_network_namespace *,int,struct sockaddr_in *,uint32_t *);
int md_network_forward_destination(struct md_network_namespace *,const void *,int,const struct sockaddr_in *,
    const struct sockaddr_in *,struct sockaddr_in *);
void md_network_forward_endpoint_closed(struct md_network_namespace *,const void *);
int md_network_forward_bind(struct md_network_namespace *,const void *,int,const struct sockaddr_in *,
    struct md_network_port_reservation **);
void md_network_forward_bound(struct md_network_port_reservation *,int);
int md_network_forward_listen(struct md_network_namespace *,const void *,int);
/* Resolve a logical destination to its current socket, without retaining it. */
int md_network_endpoint_resolve(struct md_network_fabric *,uint64_t,int,const struct sockaddr_in *,struct sockaddr_in *,const void **);
#endif
