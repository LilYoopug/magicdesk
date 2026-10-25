#ifndef MD_SOCKET_PAYLOAD_H
#define MD_SOCKET_PAYLOAD_H
#include "ipc_io.h"
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
struct md_socket_vectors { struct iovec local[8], *items; size_t bytes; };
long md_socket_vectors_open(struct md_socket_vectors *,struct msghdr *);
void md_socket_vectors_close(struct md_socket_vectors *);
long md_socket_payload_prepare(struct md_ipc_io_message *,const struct msghdr *,int sending);
long md_socket_payload_scatter(struct md_ipc_io_message *,struct msghdr *,long,int batch);
static inline long md_socket_payload_layout(struct md_ipc_io_message *io,const struct msghdr *m) {
    if (m->msg_iovlen>1024) return -EMSGSIZE;
    if (m->msg_namelen>sizeof(io->address)) return -EINVAL;
    io->size=0; io->control_size=m->msg_controllen;
    io->address_size=m->msg_name ? m->msg_namelen : 0; io->flags=0;
    for (size_t i=0;i<m->msg_iovlen;++i) {
        struct iovec v=m->msg_iov[i];
        if (v.iov_len>INT_MAX-io->size) return -EMSGSIZE;
        io->size+=v.iov_len;
    }
    return 0;
}
#endif
