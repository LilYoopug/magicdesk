#ifndef MD_FD_MESSAGES_H
#define MD_FD_MESSAGES_H
#include "ipc_credentials.h"
#include "fd_origins.h"
#include "fd_message_route.h"

/* One owner's message-origin authority, not a transport negotiation.
 * No data OFD or carrier is retained. Registry mutations belong to its event
 * loop; immutable vectors may be retained across supervisor/worker handoff. */
struct md_fd_messages;
struct md_fd_message;
int md_fd_messages_new(struct md_fd_messages **);
void md_fd_messages_free(struct md_fd_messages *);
/* Lazily created epoll descriptor, or -1 before first admission. Borrowed for
 * the owner's event wait; no periodic scan. Each dispatch processes at most 16
 * events. Failure leaves uncertain records owned, never claims their expiry. */
int md_fd_messages_fd(const struct md_fd_messages *);
unsigned md_fd_messages_count(const struct md_fd_messages *);
int md_fd_messages_dispatch(struct md_fd_messages *);

/* Capture under the source table turn, kept through the actual kernel capture.
 * One allocation sized to count; pins origins, not the source descriptor table.
 * Failure leaves output unchanged. This does not capture the data OFDs. */
int md_fd_message_capture(struct md_fd_origins *, const int *, unsigned,
    struct md_fd_message **);
struct md_fd_message *md_fd_message_retain(struct md_fd_message *);
void md_fd_message_release(struct md_fd_message *);
unsigned md_fd_message_count(const struct md_fd_message *);
struct md_fd_object *const *md_fd_message_origins(const struct md_fd_message *);

/* Reserve optional native exports before serializing a message. Other typed
 * authorities keep their existing local/portable policy. EOPNOTSUPP leaves
 * that entry local; other failures roll back the whole reservation set.
 * Preparation belongs to one worker, completion to the sending owner after
 * worker handoff. No allocation. End is idempotent; final release aborts.
 * escaped includes an unobserved terminal send, not just confirmed success. */
int md_fd_message_export_begin(struct md_fd_message *);
int md_fd_message_exports_native(const struct md_fd_message *, unsigned index);
void md_fd_message_export_end(struct md_fd_message *, int escaped);

/* Bind an unpublished vector to its captured ORIGINS_V1 sending connection. The trusted
 * owner supplies its registered launch ID, not an application-supplied label.
 * Pins epoch/store, not socket/SQLite; one random nonce per message, no allocation.
 * Failure leaves the vector unchanged. May only bind once. */
int md_fd_message_bind(struct md_fd_message *, const struct md_ipc_binding *, const char *launch_id);
/* Freeze a bound message for self-contained kernel custody. No registry entry,
 * lifetime monitor or retained carrier. Serialization uses the same route. */
int md_fd_message_issue(struct md_fd_message *, int carrier);
/* Published route hint; no in-memory origin pointer crosses a process boundary. */
int md_fd_message_route(const struct md_fd_message *, struct md_fd_message_route *);
/* Borrowed retained store directory from the bound source authority, or -1.
 * Worker serialization may inspect it while the immutable message is pinned. */
int md_fd_message_store_root(const struct md_fd_message *);
/* Only for a carrier selected by an agreed transport, never arbitrary received
 * application FDs. Non-consuming peek installs no rights. Checks actual kernel
 * cookie and captured receiving connection; launch is still an untrusted hint.
 * NATIVE bindings fail before accessing the supplied carrier. */
int md_fd_message_route_read(int carrier, const struct md_ipc_binding *, struct md_fd_message_route *);
/* On the verified source owner: actual carrier, actual destination binding and
 * the offered hint must all match this registry. Pins the existing vector, with
 * no allocation or SQL. Does not transfer origins across processes. */
int md_fd_messages_claim(struct md_fd_messages *, const struct md_ipc_binding *,
    int carrier, const struct md_fd_message_route *, struct md_fd_message **);

/* Trusted caller supplies the expected receiving connection side and a private
 * nonblocking CLOEXEC pipe reader. Its writer must follow the carrier's kernel
 * lifetime. Only successful admission transfers the reader and adds a registry
 * reference. No application slot is closed. Each message is published once. */
int md_fd_messages_publish(struct md_fd_messages *, struct md_fd_message *,
    const struct md_ipc_connection *, int carrier, int lifetime_reader);
/* Only withdraw a carrier proven not to have escaped, or destroy the whole
 * authority. An ambiguous send instead retains its record until actual EOF. */
int md_fd_messages_withdraw(struct md_fd_messages *, struct md_fd_message *);
/* Caller retains the actual received carrier and resolves its socket's key
 * through the same live IPC authority. Success pins the immutable vector;
 * lookup/retain/retirement allocate and duplicate no descriptors. */
int md_fd_messages_find(struct md_fd_messages *, const struct md_ipc_connection *,
    int carrier, struct md_fd_message **);
#endif
