#ifndef MD_SOCKET_CALLS_H
#define MD_SOCKET_CALLS_H
#include "fs.h"

/* Address and identity metadata are adapted; payload and FD transport is native. */
#define MD_SOCKET_CALLS(X) X(bind) X(connect) X(sendto) X(sendmsg) X(sendmmsg) \
    X(getsockname) X(getpeername) X(accept) X(accept4) X(recvfrom) X(recvmsg) \
    X(listen) X(socketpair) X(getsockopt)
long md_socket_call(const struct md_fs *, const char *, long, const unsigned long *);
long md_socket_pair(const struct md_fs *, const unsigned long *, int offline);
long md_socket_offline_error(long nr, const unsigned long *);
#endif
