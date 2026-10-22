#pragma once
#include <linux/filter.h>
#include <stddef.h>

struct md_socket_filter {
    struct sock_filter *code;
    unsigned count;
};
/* The kernel owns execution and locking. The original program remains the
 * userspace ABI; the carrier-only prefix must never be visible to its loads. */
int md_socket_filter_attach(struct md_socket_filter *,int,const void *,size_t,unsigned);
int md_socket_filter_detach(struct md_socket_filter *,int);
void md_socket_filter_clear(struct md_socket_filter *);
