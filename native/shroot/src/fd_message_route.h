#ifndef MD_FD_MESSAGE_ROUTE_H
#define MD_FD_MESSAGE_ROUTE_H
#include <stdint.h>
#define MD_FD_ROUTE_MAGIC 0x4d444652U
#define MD_FD_ROUTE_VERSION 1U
/* Pointer-free hint in a negotiated carrier's first packet, beside its rights.
 * This is not authentication by itself and never appears in application bytes. */
struct md_fd_message_route {
    uint32_t magic, version, count, side;
    uint64_t cookie;
    unsigned char link[16], nonce[16];
    char launch[32];
};
_Static_assert(sizeof(struct md_fd_message_route)==88, "message route wire size");
#endif
