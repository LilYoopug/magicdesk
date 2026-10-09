#ifndef MD_FS_RPC_H
#define MD_FS_RPC_H
#include "fs_operation.h"
#include "image_identity.h"
#include <linux/limits.h>

enum md_fs_delivery { MD_FS_NOT_SENT, MD_FS_UNCONFIRMED, MD_FS_REPLIED };
struct md_fs_response {
    enum md_fs_delivery delivery;
    struct md_fs_result result;
    char data[sizeof(struct md_image_identity)];
};
/* Logical reply validation, shared by wire and mapped transports. Descriptor
 * custody/publication remains transport-owned; count includes retained results. */
int md_fs_result_valid(const struct md_fs_request *, const struct md_fs_result *,
        const char *data, size_t capacity, unsigned descriptors);
/* Guest adapter requests use bootstrap-mapped output and register control.
 * Native host clients use one RPC connection per call, without replay.
 * Return value is transport/protocol status; response.result.error is the remote errno.
 * UNCONFIRMED means a mutation may have committed. A timeout is not cancellation
 * of the remote operation. Success transfers ownership of response.result.fd to caller.
 * Inputs are adapter-owned memory, not unchecked guest pointers. AT_FDCWD uses
 * the authenticated exchange's retained anchor; guest kernel-path capture is
 * internal to the accepted request. A pure O_PATH lookup may select rights transfer before
 * descriptor publication; mutations and unconfirmed delivery are never replayed. */
long md_fs_call(const char *abstract_name, unsigned timeout_ms,
        const struct md_fs_request *, struct md_fs_response *);
/* WATCH_READ retains queue ownership until the local copy is acknowledged.
 * A rejected copy consumes nothing; lost acknowledgement is not replayable. */
long md_fs_call_deliver(const char *, unsigned, const struct md_fs_request *,
        struct md_fs_response *, int (*deliver)(void *, const void *, size_t), void *);
#endif
