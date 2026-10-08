#ifndef MD_NETWORK_NAMESPACE_H
#define MD_NETWORK_NAMESPACE_H
#include "fd_object.h"
#include "user_namespace.h"
struct md_identity;

/* An offline view permits inherited descriptions and anonymous local IPC.
 * It exposes a logical loopback control interface, but no addressed data
 * sockets or host routing authority. */
struct md_network_namespace;
struct md_network_namespace *md_network_namespace_new(struct md_user_namespace *, int offline);
struct md_network_namespace *md_network_namespace_retain(struct md_network_namespace *);
void md_network_namespace_release(struct md_network_namespace *);
uint64_t md_network_namespace_inode(const struct md_network_namespace *);
const struct md_user_namespace *md_network_namespace_owner(const struct md_network_namespace *);
int md_network_namespace_offline(const struct md_network_namespace *);
struct md_fd_object *md_network_socket_new(struct md_network_namespace *);
int md_network_socket_offline(const struct md_fd_object *);
int md_network_socket_control(const struct md_fd_object *);
int md_network_socket_open(struct md_network_namespace *, int family, int type, int protocol,
    struct md_fd_object **, int *fd);
long md_network_socket_call(struct md_fd_object *, const struct md_identity *, long nr,
    const unsigned long *, void *data, size_t capacity, size_t size, pid_t pid);
#define MD_NETWORK_BUFFER_SIZE 4096
#endif
