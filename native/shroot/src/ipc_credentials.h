#ifndef MD_IPC_CREDENTIALS_H
#define MD_IPC_CREDENTIALS_H
#include "ipc_identity.h"
#include "fs_operation.h"
#include "pid_namespace.h"

/* Store-scoped, live IPC metadata. Kernel sockets own data and descriptor
 * lifetimes; this authority owns connection-time identity/format snapshots. */
struct md_ipc_credentials;
/* Immutable application ancillary format, selected at socketpair/connect from
 * runtime-owner declarations, never from application bytes or a received FD.
 * NATIVE is also the explicit agreement when either endpoint offers none. */
enum md_ipc_ancillary_transport { MD_IPC_TRANSPORT_NATIVE, MD_IPC_TRANSPORT_ORIGINS_V1 };
/* Connection association, not protocol negotiation or proof that a peer is
 * alive. Opposite sides share a link, including before accept is published.
 * Meaningful only in the same live store authority. Caller holds the captured
 * socket through lookup; failure leaves output unchanged. No FD is retained. */
struct md_ipc_connection { unsigned char link[16]; unsigned side; };
int md_ipc_credentials_connection(struct md_ipc_credentials *, int socket,
    struct md_ipc_connection *);
/* Host-only connection snapshot with an owned live-epoch/store-maintenance pin.
 * No socket or SQLite connection is retained. Zero-initialize, never copy by assignment;
 * release after the last protocol operation using the connection identity. */
struct md_ipc_scope;
struct md_ipc_binding {
    struct md_ipc_connection connection;
    struct md_ipc_scope *scope;
    enum md_ipc_ancillary_transport transport;
};
int md_ipc_credentials_bind(struct md_ipc_credentials *, int socket, struct md_ipc_binding *);
/* Crossing an unadapted boundary latches actual UNIX socket cookies native-only.
 * Already adapted connections/listeners fail EXDEV before any send. A failed
 * or cancelled send cannot undo exposure. No descriptors are retained. */
int md_ipc_credentials_native(struct md_ipc_credentials *, const int *fds, unsigned count);
/* Capture before forking the initial guest. It retains these sockets until
 * admission completes; known runtime agreements survive internal exec/launch.
 * Unknown inherited sockets can never acquire an adapted protocol later. */
struct md_ipc_inherited { uint64_t *cookies; unsigned count; };
int md_ipc_inherited_capture(struct md_ipc_inherited *);
int md_ipc_credentials_inherit(struct md_ipc_credentials *, const struct md_ipc_inherited *);
void md_ipc_inherited_release(struct md_ipc_inherited *);
/* No allocation, FD duplication or SQL. Both bindings pin the live epoch;
 * matching retained store identities therefore refer to that same epoch. */
int md_ipc_binding_copy(struct md_ipc_binding *, const struct md_ipc_binding *);
int md_ipc_binding_same_scope(const struct md_ipc_binding *, const struct md_ipc_binding *);
void md_ipc_binding_release(struct md_ipc_binding *);
enum md_ipc_operation {
    MD_IPC_LISTEN_BEGIN = 1, MD_IPC_LISTEN_END, MD_IPC_CONNECT_BEGIN,
    MD_IPC_CONNECT_END, MD_IPC_ACCEPT, MD_IPC_PAIR, MD_IPC_NAME,
    MD_IPC_MESSAGE_CREATE, MD_IPC_MESSAGE_READ, MD_IPC_MESSAGE_SENDER
};
/* Offer applies only to new listeners/connections/pairs; opening another owner
 * cannot upgrade an existing connection. NATIVE adds no data-path work.
 * A transport agreement does not authenticate a message's custodian. */
int md_ipc_credentials_open(const char *store, enum md_ipc_ancillary_transport offer,
    struct md_ipc_credentials **);
void md_ipc_credentials_close(struct md_ipc_credentials *);
/* Worker-owned, event-driven retirement of process-local typed FD custody. */
int md_ipc_credentials_pollfd(const struct md_ipc_credentials *);
int md_ipc_credentials_dispatch(struct md_ipc_credentials *);
void md_ipc_credentials_execute(struct md_ipc_credentials *, const struct md_identity *, const struct md_pid_identity *,
    const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
#endif
