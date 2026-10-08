#ifndef MD_FD_DELIVERY_H
#define MD_FD_DELIVERY_H
#include "fd_origins.h"
#include "fd_receipt.h"
#include "fd_table_observation.h"

/* Zero-initialized, caller-owned operation. The caller serializes access and
 * retains capacity entries in both scratch arrays through dispose. Preparation
 * pins the destination table and origins, not the source task or data OFDs. */
struct md_fd_delivery {
    struct md_fd_origin_update *updates;
    int *numbers;
    struct md_fd_receipt *receipt;
    const struct md_fd_table_observation *observation;
    unsigned capacity, published;
    int receipt_fd;
};
int md_fd_delivery_prepare(struct md_fd_delivery *, struct md_fd_origins *,
        struct md_fd_object *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers);
/* The caller owns this mapped receipt through dispose. No memfd, mmap or
 * destination scratch descriptor is allocated. Kernel output uses this same
 * storage; a terminal event can publish it without a guest acknowledgement. */
int md_fd_delivery_prepare_mapped(struct md_fd_delivery *, struct md_fd_origins *,
        struct md_fd_object *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers, struct md_fd_receipt *);
/* Alternate kernel evidence when recvmsg must write directly to arbitrary app
 * memory. The caller arms observation after admission under the same table
 * turn, and retains it and its directory until publication/dispose. */
int md_fd_delivery_prepare_observed(struct md_fd_delivery *, struct md_fd_origins *,
        struct md_fd_object *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers, const struct md_fd_table_observation *);
/* Borrowed receipt FD; pass through the selected authenticated transport. */
int md_fd_delivery_receipt(const struct md_fd_delivery *);
/* Kernel completion/terminal event only, under the destination's table turn.
 * Returns the installed count or a negative error; numbers contains that prefix.
 * Zero leaves preparation live for an EAGAIN retry. The owner disposes a final
 * zero delivery. Successful nonempty publication is allocation-free and once-only. */
int md_fd_delivery_publish(struct md_fd_delivery *);
/* Releases preparation and receipt, never installed caller-owned descriptors. */
void md_fd_delivery_dispose(struct md_fd_delivery *);
#endif
