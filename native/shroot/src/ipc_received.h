#ifndef MD_IPC_RECEIVED_H
#define MD_IPC_RECEIVED_H
#include "received_info.h"
#include "received_fds.h"
struct md_ipc_capsules;
struct md_fs_context;
/* Worker-only, one message from captured [socket, rights...] custody. Native
 * messages borrow their original indices without duplicating FDs. ORIGINS_V1
 * returns a separate immutable data vector and indices into that vector.
 * Outputs remain unchanged on error. Cache is lazy; free after worker join. */
int md_ipc_received_message(struct md_ipc_capsules **, struct md_fs_context *,
    const struct md_received_fds *, const int *, unsigned,
    struct md_received_message *, struct md_received_fds **);
#endif
