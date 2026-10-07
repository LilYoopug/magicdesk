#ifndef MD_IPC_PEER_H
#define MD_IPC_PEER_H
#include "ipc_credentials.h"

enum { MD_IPC_PEER_ORIGINS=1 };
/* An explicit private control channel between trusted runtime owners, never
 * an application socket. Does not discover peers, transfer origins or enable
 * carrier framing in the application adapter. One event-loop owner. */
struct md_ipc_peer;
/* Worker-side admission resolves the captured application socket once, then
 * releases the database gate before any control IO. The caller owns control
 * until success; admission transfers it without dup or changing its flags.
 * The captured application socket itself is not retained. */
int md_ipc_peer_open(struct md_ipc_credentials *, int application, int control,
    uint64_t supported, uint64_t required, struct md_ipc_peer **);
void md_ipc_peer_close(struct md_ipc_peer *);
/* Borrowed control FD and poll interests. The owner supplies the event wait
 * and cancellation deadline; expiry closes the peer, never means agreement.
 * No wait, polling timer, SQL or allocation inside step. At most four packets. */
int md_ipc_peer_fd(const struct md_ipc_peer *);
short md_ipc_peer_events(const struct md_ipc_peer *);
int md_ipc_peer_step(struct md_ipc_peer *); /* 1 agreed, 0 pending, negative error */
/* Success after sending our confirmation and receiving the peer's; this is
 * not proof of continued peer liveness. The binding stays borrowed until
 * peer close, and retains the IPC epoch without retaining SQLite. Application
 * operations must still capture their actual socket/table resources. Features
 * do not change binding->transport: an ordinary application connection cannot
 * be upgraded by negotiating a private control exchange. */
int md_ipc_peer_agreement(const struct md_ipc_peer *, const struct md_ipc_binding **,
    uint64_t *features);
#endif
