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
int md_network_forward_timer(struct md_network_fabric *);
void md_network_forward_retire(struct md_network_namespace *);
void md_network_forward_shutdown(struct md_network_fabric *);
int md_network_forward_route(struct md_network_namespace *,const void *,int,const struct md_inet_address *,
    const struct md_inet_address *,struct md_network_flow_path *,struct md_inet_address *);
int md_network_forward_source(struct md_network_namespace *,int,struct md_inet_address *,struct md_ip_address *);
int md_network_forward_destination(struct md_network_namespace *,const void *,int,const struct md_inet_address *,
    const struct md_inet_address *,struct md_inet_address *);
void md_network_forward_endpoint_closed(struct md_network_namespace *,const void *);
void md_network_forward_endpoint_disconnected(struct md_network_namespace *,const void *,int);
int md_network_forward_endpoint_active(struct md_network_namespace *,const void *);
int md_network_forward_bind(struct md_network_namespace *,const void *,int,const struct md_inet_address *,int,
    struct md_network_port_reservation **);
void md_network_forward_bound(struct md_network_port_reservation *,int);
int md_network_forward_listen(struct md_network_namespace *,const void *,int);
#endif
