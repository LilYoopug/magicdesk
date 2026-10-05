#ifndef MD_FD_EXCHANGE_H
#define MD_FD_EXCHANGE_H
#include "fd_origins.h"
#include <stdint.h>

/* Launch-local capabilities joining an authenticated RPC to its original file
 * table. Wire IDs are never pointers. The owner and the worker retain separate
 * references; disconnect does not invalidate an in-progress publication. */
struct md_fd_exchanges;
struct md_fd_exchange;
struct md_fd_exchanges *md_fd_exchanges_create(void);
void md_fd_exchanges_destroy(struct md_fd_exchanges *);
int md_fd_exchange_begin(struct md_fd_exchanges *, int actor, struct md_fd_origins *,
        const int bases[2], struct md_fd_exchange **);
uint64_t md_fd_exchange_id(const struct md_fd_exchange *);
struct md_fd_exchange *md_fd_exchange_acquire(struct md_fd_exchanges *, uint64_t,
        int actor, struct md_fd_origins *);
void md_fd_exchange_close(struct md_fd_exchanges *, struct md_fd_exchange *);
void md_fd_exchange_release(struct md_fd_exchange *);
/* Borrowed immutable inputs, captured under the sender's table turn. */
const struct md_fs_anchor *md_fd_exchange_input(const struct md_fd_exchange *, unsigned);
/* Prepare before sending any rights. Publish once after kernel receive, while
 * the receiver owns the table turn; no allocation occurs after installation. */
int md_fd_exchange_offer(struct md_fd_exchange *, struct md_fs_anchor *, unsigned count);
/* Borrowed transport FD. Only payload-producing exchanges allocate a receipt.
 * Completion reads the kernel's shared output, not a post-receive guest ACK. */
int md_fd_exchange_receipt(const struct md_fd_exchange *);
int md_fd_exchange_received(struct md_fd_exchange *);
#endif
