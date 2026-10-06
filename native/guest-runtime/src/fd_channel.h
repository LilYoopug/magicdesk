#ifndef MD_FD_CHANNEL_H
#define MD_FD_CHANNEL_H
#include <stdint.h>
#include <sys/types.h>
#include "resource_order.h"

/* Infrastructure only. References never mirror application open descriptions.
 * The supervisor retains both receive queues, including the guest endpoint.
 * Cancelled packets can be drained without running code in a dying task. */
struct md_fd_channel;
struct md_fd_origins;
/* Task-local kernel observation; the enclosing owner retains the table turn.
 * A denied observation leaves the candidate unresolved. It never authorizes
 * closing the slot, and is not a hostile shared-memory authentication scheme. */
struct md_fd_channel_observation { uint64_t cookie; unsigned length, flags; int error; };
int md_fd_channel_resolve(struct md_fd_channel *, struct md_fd_origins *, int number,
        const struct md_fd_channel_observation *);
struct md_fd_channel_input {
    uint64_t request;
    pid_t peer;
    unsigned count;
    int fd[2];
};
/* Caller-owned, zero-initialized lease on an accepted input vector. The channel
 * dispatches all packets, so independent table/request owners cannot discard
 * each other's rights. Supervisor-thread only; no allocation or callback. */
struct md_fd_channel_capture {
    struct md_fd_channel *channel;
    struct md_fd_channel_capture *next;
    uint64_t request;
    pid_t peer;
    unsigned expected;
    struct md_fd_channel_input input;
};
int md_fd_channel_capture_begin(struct md_fd_channel *, pid_t peer, unsigned count,
        struct md_fd_channel_capture *);
/* Finish transfers exactly one matching vector or returns a negative errno;
 * both outcomes retire the lease. Cancel closes its queued/captured rights. */
int md_fd_channel_capture_finish(struct md_fd_channel_capture *, struct md_fd_channel_input *);
void md_fd_channel_capture_cancel(struct md_fd_channel_capture *);
int md_fd_channel_new(struct md_fd_channel **);
struct md_fd_channel *md_fd_channel_retain(struct md_fd_channel *);
void md_fd_channel_release(struct md_fd_channel *);
int md_fd_channel_endpoint(const struct md_fd_channel *);
/* Atomic CLOEXEC endpoint installation plus allocation-free metadata publication.
 * The caller owns the destination file-table turn throughout this operation. */
int md_fd_channel_admit(struct md_fd_channel *, struct md_fd_origins *, int listener, uint64_t notification);
void md_fd_channel_input_close(struct md_fd_channel_input *);
/* The caller retains the channel throughout its output turn. This queue spans
 * fork-copied tables and aliases, independently of destination table ordering.
 * One running owner sends one packet, observes its kernel receipt, then drains
 * any unreceived rights before releasing the turn. Input export is independent. */
int md_fd_channel_output_begin(struct md_fd_channel *, struct md_resource_order *, struct md_resource_wakeup *);
int md_fd_channel_output_send(struct md_fd_channel *, int source, uint64_t *request);
int md_fd_channel_output_discard(struct md_fd_channel *);
#endif
