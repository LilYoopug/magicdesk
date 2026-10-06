#ifndef MD_IPC_CREDENTIALS_H
#define MD_IPC_CREDENTIALS_H
#include "ipc_identity.h"
#include "fs_operation.h"

/* Store-scoped, live IPC metadata. Kernel sockets own data and descriptor
 * lifetimes; this authority owns only connection-time identity snapshots. */
struct md_ipc_credentials;
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
struct md_ipc_binding { struct md_ipc_connection connection; struct md_ipc_scope *scope; };
int md_ipc_credentials_bind(struct md_ipc_credentials *, int socket, struct md_ipc_binding *);
/* No allocation, FD duplication or SQL. Both bindings pin the live epoch;
 * matching retained store identities therefore refer to that same epoch. */
int md_ipc_binding_copy(struct md_ipc_binding *, const struct md_ipc_binding *);
int md_ipc_binding_same_scope(const struct md_ipc_binding *, const struct md_ipc_binding *);
void md_ipc_binding_release(struct md_ipc_binding *);
enum md_ipc_operation {
    MD_IPC_LISTEN_BEGIN = 1, MD_IPC_LISTEN_END, MD_IPC_CONNECT_BEGIN,
    MD_IPC_CONNECT_END, MD_IPC_ACCEPT, MD_IPC_PAIR, MD_IPC_NAME,
    MD_IPC_MESSAGE_CREATE, MD_IPC_MESSAGE_READ
};
int md_ipc_credentials_open(const char *store, struct md_ipc_credentials **);
void md_ipc_credentials_close(struct md_ipc_credentials *);
void md_ipc_credentials_execute(struct md_ipc_credentials *, const struct md_identity *,
    const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
#endif
