#ifndef MD_NETWORK_ENDPOINT_H
#define MD_NETWORK_ENDPOINT_H
#include "network_namespace.h"
#include <netinet/in.h>

/* Endpoint metadata never retains a native socket. The caller captures its
 * actual description under the file-table turn for each operation. */
int md_network_endpoint_is(const struct md_fd_object *);
int md_network_endpoint_enabled(const struct md_network_namespace *);
int md_network_endpoint_open(struct md_network_namespace *,int,int,int,struct md_fd_object **,int *);
int md_network_endpoint_bind(struct md_fd_object *,int,const struct md_identity *,const struct sockaddr *,socklen_t);
int md_network_endpoint_listen(struct md_fd_object *,int,int);
int md_network_endpoint_destination(struct md_fd_object *,const struct sockaddr *,socklen_t,
    struct sockaddr_storage *,socklen_t *);
int md_network_endpoint_name(struct md_fd_object *,int,int,struct sockaddr_storage *,socklen_t *);
int md_network_endpoint_connected(struct md_fd_object *,int,const struct sockaddr *,socklen_t);
int md_network_endpoint_autobind(struct md_fd_object *,int,const struct md_identity *,const struct sockaddr *,socklen_t);
int md_network_endpoint_source(struct md_fd_object *,struct sockaddr_storage *,socklen_t *);
int md_network_endpoint_accept(struct md_fd_object *,int,struct md_fd_object **);
struct md_network_filter;
int md_network_endpoint_filter_update(struct md_network_namespace *,struct md_network_filter *);
#endif
