#ifndef MD_INTERCEPTION_BUFFERS_H
#define MD_INTERCEPTION_BUFFERS_H
#include <stddef.h>
#include <stdint.h>

struct md_interception_buffers;
/* Supervisor-loop-owned metadata. Only bytes are shared with a tracee; no
 * allocator state, pointers, ownership counters or generations are writable
 * through the mapping. A worker borrows a pinned span, not the allocator. */
struct md_interception_buffer {
    struct md_interception_buffers *pool;
    uint64_t generation;
    unsigned index;
};
struct md_buffer_span { void *data; size_t size, offset; };

int md_buffers_create(unsigned slots, size_t capacity, size_t clear_prefix,
    unsigned reserved, struct md_interception_buffers **);
struct md_interception_buffers *md_buffers_retain(struct md_interception_buffers *);
void md_buffers_release(struct md_interception_buffers *);
/* Borrowed bootstrap transport only. Mapping setup/FD closure must complete
 * before guest entry. Ordinary buffer acquisition installs no tracee FD. */
int md_buffers_fd(const struct md_interception_buffers *);
size_t md_buffers_size(const struct md_interception_buffers *);
/* Empty output required. Exhaustion returns EAGAIN: the owner queues the task
 * and retries on buffer release, never polls or replays a submitted request.
 * Acquisition clears its declared header prefix, never unused payload pages;
 * callers initialize all published payload bytes. No per-request allocation or mmap. */
int md_buffers_take(struct md_interception_buffers *, struct md_interception_buffer *);
/* Separate control capacity within the same backing/mapping. These loans must
 * not wait on ordinary IO/resource turns while held. Payload is not cleared:
 * the control owner publishes its initialized bytes before resuming the task. */
int md_buffers_take_reserved(struct md_interception_buffers *, struct md_interception_buffer *);
/* Independent owner, e.g. a submitted request outliving its initiating task.
 * Copy handles only through pin; a released handle is invalid. */
int md_buffer_pin(const struct md_interception_buffer *, struct md_interception_buffer *);
int md_buffer_span(const struct md_interception_buffer *, struct md_buffer_span *);
int md_buffer_release(struct md_interception_buffer *);
#endif
