#ifndef MD_NETWORK_ENDPOINT_H
#define MD_NETWORK_ENDPOINT_H
#include "network_namespace.h"
#include <netinet/in.h>

/* Endpoint metadata never retains a native socket. The caller captures its
 * actual description under the file-table turn for each operation. */
int md_network_endpoint_is(const struct md_fd_object *);
struct md_network_namespace *md_network_endpoint_namespace(const struct md_fd_object *);
int md_network_endpoint_enabled(const struct md_network_namespace *);
int md_network_endpoint_open(struct md_network_namespace *,uint32_t,int,int,int,struct md_fd_object **,int *);
int md_network_endpoint_bind(struct md_fd_object *,int,const struct md_identity *,const struct sockaddr *,socklen_t);
int md_network_endpoint_listen(struct md_fd_object *,int,int);
int md_network_endpoint_device_set(struct md_fd_object *,const struct md_identity *,const char *);
int md_network_endpoint_device_get(struct md_fd_object *,char *,socklen_t *);
int md_network_endpoint_destination(struct md_fd_object *,const struct sockaddr *,socklen_t,
    struct sockaddr_storage *,socklen_t *);
int md_network_endpoint_destination_info(struct md_fd_object *,const struct sockaddr *,socklen_t,
    struct in_pktinfo *,struct sockaddr_storage *,socklen_t *);
int md_network_endpoint_name(struct md_fd_object *,int,int,struct sockaddr_storage *,socklen_t *);
int md_network_endpoint_connected(struct md_fd_object *,int,const struct sockaddr *,socklen_t);
int md_network_endpoint_autobind(struct md_fd_object *,int,const struct md_identity *,const struct sockaddr *,socklen_t);
int md_network_endpoint_source(struct md_fd_object *,struct sockaddr_storage *,socklen_t *);
int md_network_endpoint_source_info(struct md_fd_object *,struct sockaddr_storage *,socklen_t *,struct in_pktinfo *);
int md_network_endpoint_accept(struct md_fd_object *,int,struct md_fd_object **);
struct md_network_endpoint_info {
    uint64_t inode;
    uint32_t uid;
    struct sockaddr_in local, peer;
};
/* An owned, namespace-scoped snapshot, sorted by native socket inode. */
int md_network_endpoint_snapshot(struct md_network_namespace *,int,
    struct md_network_endpoint_info **,size_t *);
struct md_network_filter;
int md_network_endpoint_policy_update(struct md_network_namespace *,struct md_network_filter *);
/* Called under the fabric lock before changing TCP namespace defaults. */
int md_network_endpoint_tcp_idle(const struct md_network_namespace *);
#endif
