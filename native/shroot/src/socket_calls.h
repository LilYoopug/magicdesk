#ifndef MD_SOCKET_CALLS_H
#define MD_SOCKET_CALLS_H
#include "fs.h"
#include <sys/syscall.h>

/* Address and identity metadata are adapted; payload and FD transport is native. */
#include "syscall_catalog.h"
static inline int md_socket_payload_native(long nr, unsigned long address) {
    return !address && (nr==SYS_sendto || nr==SYS_recvfrom);
}
long md_socket_call(const struct md_fs *, const char *, long, const unsigned long *,unsigned long);
long md_socket_pair(const struct md_fs *, const unsigned long *, int offline);
long md_socket_offline_error(long nr, const unsigned long *);
#endif
