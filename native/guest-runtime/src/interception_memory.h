#ifndef MD_INTERCEPTION_MEMORY_H
#define MD_INTERCEPTION_MEMORY_H
#include <stdint.h>
#include "interception_buffers.h"
#include "resource_order.h"

/* Supervisor-owned mappings in one tracee address space. CLONE_VM shares this
 * owner; fork copies stack metadata and retains the shared buffer allocator.
 * Exec creates an empty owner. Worker pins may outlive every mapping owner. */
struct md_interception_memory;
struct md_interception_memory *md_memory_new(void);
struct md_interception_memory *md_memory_fork(struct md_interception_memory *, int shared);
void md_memory_release(struct md_interception_memory *);
uintptr_t md_memory_stack_take(struct md_interception_memory *);
int md_memory_stack_add(struct md_interception_memory *, uintptr_t);
void md_memory_stack_return(struct md_interception_memory *, uintptr_t);
int md_memory_buffers_prepare(struct md_interception_memory *, unsigned slots, size_t capacity, size_t clear_prefix);
struct md_interception_buffers *md_memory_buffers(struct md_interception_memory *);
int md_memory_buffers_mapped(struct md_interception_memory *, uintptr_t base, size_t size);
uintptr_t md_memory_buffer_address(struct md_interception_memory *, const struct md_interception_buffer *);
/* Mapping commit and destructive memory calls share this address-space turn.
 * The caller retains the memory owner until completing/cancelling the turn. */
int md_memory_order_begin(struct md_interception_memory *, struct md_resource_order *, struct md_resource_wakeup *);
#endif
