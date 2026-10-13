#ifndef MD_NETWORK_NAMESPACE_H
#define MD_NETWORK_NAMESPACE_H
#include "fd_object.h"
#include "user_namespace.h"
#include "control_file.h"
struct md_identity;
struct md_network_target;

/* Native launches retain Android networking. A routed launch owns a logical
 * fabric and socket-address translation. New namespaces start private, with
 * no route until explicitly attached; none of these modes alters Android links. */
struct md_network_namespace;
enum md_network_mode { MD_NETWORK_NATIVE, MD_NETWORK_PRIVATE, MD_NETWORK_ROUTED };
struct md_network_namespace *md_network_namespace_new(struct md_user_namespace *, enum md_network_mode);
struct md_network_namespace *md_network_namespace_copy(struct md_network_namespace *,struct md_user_namespace *);
struct md_network_namespace *md_network_namespace_retain(struct md_network_namespace *);
void md_network_namespace_release(struct md_network_namespace *);
uint64_t md_network_namespace_inode(const struct md_network_namespace *);
const struct md_user_namespace *md_network_namespace_owner(const struct md_network_namespace *);
int md_network_namespace_managed(const struct md_network_namespace *);
enum md_network_parameter { MD_NET_UNPRIVILEGED_PORT, MD_NET_PING_GROUPS, MD_NET_LOCAL_PORTS,
    MD_NET_IPV4_FORWARD };
/* Policy state belongs to the selected managed namespace, never Android. */
int md_network_parameter_get(struct md_network_namespace *,enum md_network_parameter,uint32_t values[2]);
int md_network_parameter_set(struct md_network_namespace *,enum md_network_parameter,const uint32_t values[2]);
struct md_control_file md_network_sysctl_new(struct md_network_namespace *,enum md_network_parameter,struct md_fs_anchor *);
struct md_network_link {
    unsigned index, flags, mtu, type, state, tx_queue_length;
    char name[16];
    unsigned char address[6];
};
/* One control-plane snapshot for ioctl, netlink and namespace-mounted sysfs. */
int md_network_link_info(const struct md_network_namespace *, unsigned, struct md_network_link *);
struct md_fd_object *md_network_socket_new(struct md_network_namespace *);
int md_network_socket_offline(const struct md_fd_object *);
int md_network_socket_control(const struct md_fd_object *);
int md_network_socket_open(struct md_network_namespace *, int family, int type, int protocol,
    struct md_fd_object **, int *fd);
long md_network_socket_call(struct md_fd_object *, const struct md_identity *, long nr,
    const unsigned long *, void *data, size_t capacity, size_t size, pid_t pid,const struct md_network_target *);
#define MD_NETWORK_BUFFER_SIZE 4096
#endif
