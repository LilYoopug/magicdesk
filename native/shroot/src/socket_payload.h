#ifndef MD_SOCKET_PAYLOAD_H
#define MD_SOCKET_PAYLOAD_H
#include "ipc_io.h"
#include <sys/uio.h>
struct md_socket_vectors { struct iovec local[8], *items; size_t bytes; };
long md_socket_vectors_open(struct md_socket_vectors *,struct msghdr *);
void md_socket_vectors_close(struct md_socket_vectors *);
long md_socket_payload_prepare(struct md_ipc_io_message *,const struct msghdr *,int sending);
long md_socket_payload_scatter(struct md_ipc_io_message *,struct msghdr *,long,int batch);
#endif
