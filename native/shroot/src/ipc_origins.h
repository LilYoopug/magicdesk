#ifndef MD_IPC_ORIGINS_H
#define MD_IPC_ORIGINS_H
#include "fd_messages.h"
#include "received_fds.h"
#include "ipc_credentials.h"
#include "ipc_outgoing.h"

struct md_fs_worker;
struct md_ipc_origins;
struct md_ipc_origin_request;
struct md_fs_context;
/* One event-loop owner and its existing filesystem worker, no live-peer RPC.
 * The launch ID is copied as a diagnostic hint, not an authentication proof.
 * Capsule/key/import state is lazy and worker-owned. At most 16 requests. */
int md_ipc_origins_new(struct md_fs_worker *, const char *launch_id, struct md_ipc_origins **);
/* Stop/join worker first, then reclaim undelivered completions and cached state. */
void md_ipc_origins_destroy(struct md_ipc_origins *);
/* Both operations borrow immutable, already captured custody. Slot zero is the
 * actual application socket, never a reusable caller FD number. Admission pins
 * all inputs. The sender retains its message through actual send completion
 * and calls md_fd_message_export_end with the observed/uncertain outcome;
 * cancellation before send releases it without committing a native escape.
 * Other input references may be released immediately after admission.
 * Preparation requires the matching source-table snapshot and slots [1,count)
 * as its actual data rights. Each snapshot is single-use, including failure.
 * Receive expects exactly [socket, carrier], from one selected message. */
int md_ipc_origins_prepare(struct md_ipc_origins *, struct md_fd_message *,
    struct md_received_fds *, void (*complete)(struct md_ipc_origin_request *, int, void *),
    void *, struct md_ipc_origin_request **);
/* Transfers the captured task context only on successful admission. Address
 * resolution and credential validation use that snapshot, not a later task. */
int md_ipc_origins_send(struct md_ipc_origins *, struct md_fd_message *,
    struct md_received_fds *, struct md_fs_context *, const struct md_ipc_send_options *,
    void (*complete)(struct md_ipc_origin_request *, int, void *), void *,
    struct md_ipc_origin_request **);
int md_ipc_origins_receive(struct md_ipc_origins *, struct md_received_fds *,
    void (*complete)(struct md_ipc_origin_request *, int, void *),
    void *, struct md_ipc_origin_request **);
/* Event-loop completion only. Preparation selects the captured connection's
 * format: ORIGINS_V1 returns [socket, capsule]; NATIVE (also unregistered peers)
 * returns the original captured owner without duplicating any descriptions.
 * receive returns the actual annotated data vector, without its socket.
 * Pending take returns EAGAIN; a completed error consumes the request. Invalid
 * output leaves it intact. Optional transport is written only on success.
 * Completion may take/cancel its own request. */
int md_ipc_origins_take(struct md_ipc_origin_request **, struct md_received_fds **,
    enum md_ipc_ancillary_transport *);
/* Addressed/credential sends require destination output, including any owned
 * anchor. They cannot be taken through the descriptor-only interface. */
int md_ipc_origins_take_send(struct md_ipc_origin_request **, struct md_received_fds **,
    enum md_ipc_ancillary_transport *, struct md_ipc_send_address *);
/* Clears handle immediately, suppresses callback, pins worker inputs through
 * completion or join. Never closes a caller slot or retries a send/receive. */
void md_ipc_origins_cancel(struct md_ipc_origin_request **);
#endif
