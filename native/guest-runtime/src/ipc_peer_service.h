#ifndef MD_IPC_PEER_SERVICE_H
#define MD_IPC_PEER_SERVICE_H
#include "ipc_peer.h"

struct md_fs_worker;
struct md_ipc_peer_service;
struct md_ipc_peer_admission;
/* Supervisor-owned admission, using its existing worker/completion queue.
 * Public calls belong to one event-loop thread. No thread, socket or event
 * source is created by this owner. */
int md_ipc_peer_service_new(struct md_fs_worker *, struct md_ipc_peer_service **);
/* Stop/join the worker first. Retires even undelivered completions without
 * callbacks; no worker may still refer to admission records. */
void md_ipc_peer_service_destroy(struct md_ipc_peer_service *);
/* Application is an owned, already captured socket, never a guest FD number.
 * Control is an explicitly private channel. Success takes both descriptors;
 * failure leaves both and *out unchanged. No descriptor duplication.
 * The event-loop caller retains *out until take/cancel or service destruction.
 * Callback runs once via worker_dispatch, unless cancelled. It may take/cancel
 * this admission, but cannot destroy its service/worker during dispatch. */
int md_ipc_peer_begin(struct md_ipc_peer_service *, int application, int control,
    uint64_t supported, uint64_t required,
    void (*complete)(struct md_ipc_peer_admission *, int error, void *), void *context,
    struct md_ipc_peer_admission **out);
/* Completion means admission, not protocol agreement. On completed error this
 * still releases the request. EAGAIN/invalid output leave it caller-owned. */
int md_ipc_peer_take(struct md_ipc_peer_admission **, struct md_ipc_peer **);
/* Clears the caller's handle immediately. Pending work retains its record
 * until completion or worker join. Never waits, closes remembered guest slots,
 * or delivers a cancelled callback. */
void md_ipc_peer_cancel(struct md_ipc_peer_admission **);
#endif
