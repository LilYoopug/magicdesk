#ifndef MD_IPC_CAPSULE_H
#define MD_IPC_CAPSULE_H
#include "fd_messages.h"
#include "received_fds.h"

/* Filesystem-worker-owned authenticated custody. Portable filesystem origins
 * survive sender-supervisor exit; local typed objects retain that worker's
 * registry and reject import by another authority.
 * Only explicitly ORIGINS_V1 connections may use this format. The owner caches
 * one epoch key and common origin importer; no per-message database records. */
struct md_ipc_capsules;
int md_ipc_capsules_new(const struct md_ipc_binding *, struct md_ipc_capsules **);
void md_ipc_capsules_free(struct md_ipc_capsules *);
/* Borrows an unbound captured message and its exact data descriptions. A failed
 * attempt may consume its single-use route, but never the borrowed data FDs.
 * Success returns one CLOEXEC carrier. Portable bundle writers are closed;
 * a local carrier owns the pipe writer that bounds its registry entry. */
int md_ipc_capsules_publish(struct md_ipc_capsules *, const struct md_ipc_binding *,
    const char *launch, struct md_fd_message *, const int *, unsigned, int *out);
/* Authenticates before importing metadata. Non-consuming and repeatable;
 * success owns annotated data descriptions, failure leaves output unchanged. */
int md_ipc_capsules_receive(struct md_ipc_capsules *, const struct md_ipc_binding *,
    int carrier, struct md_received_fds **out);
#endif
