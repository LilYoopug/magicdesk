#ifndef MD_INTERCEPTION_MEMORY_H
#define MD_INTERCEPTION_MEMORY_H
#include <stdint.h>
#include <sys/types.h>
#include "interception_buffers.h"
#include "resource_order.h"
#include "private_memory.h"

/* Supervisor-owned mappings in one tracee address space. CLONE_VM shares this
 * owner; fork copies stack metadata and retains the shared buffer allocator.
 * Exec creates an empty owner. Worker pins may outlive every mapping owner. */
struct md_interception_memory;
struct md_interception_memory *md_memory_new(void);
/* Empty post-exec address space, sharing only retained file backing ownership
 * with its launch family. No mappings, private-memory authority or buffers survive. */
struct md_interception_memory *md_memory_new_image(struct md_interception_memory *);
struct md_interception_memory *md_memory_fork(struct md_interception_memory *, int shared);
void md_memory_release(struct md_interception_memory *);
/* Raw proc-memory authority may escape its opener's descriptor table. */
void md_memory_expose(struct md_interception_memory *);
int md_memory_exposed(const struct md_interception_memory *);
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
/* Optional task-affine proc access. CLONE_VM shares it; fork/exec do not, since
 * each proc file pins an exact mm even when its original task disappears. */
int md_memory_private_access_set(struct md_interception_memory *, const struct md_private_memory_access *);
/* The caller holds the exact task stopped throughout capture. Failure is
 * optional capability loss, never a reason to change dumpability or identity. */
int md_memory_private_access_capture(struct md_interception_memory *, pid_t);
const struct md_private_memory_access *md_memory_private_access(const struct md_interception_memory *);
/* File provenance and VM_MAYEXEC policy belong to the address space, not its
 * threads' descriptor tables. Prepare reserves storage before execution;
 * finish allocates nothing. All calls below require the address-space turn. */
struct md_memory_backing;
struct md_memory_file_range;
enum md_mapping_operation { MD_MAPPING_MAP, MD_MAPPING_UNMAP, MD_MAPPING_REMAP };
struct md_mapping_change {
    enum md_mapping_operation operation;
    uintptr_t address;
    size_t length, new_length;
    unsigned flags;
    int noexec, prepared;
    struct md_memory_backing *backing;
    uint64_t offset;
    struct md_memory_file_range *moving;
    size_t moving_count;
};
int md_memory_has_policy(const struct md_interception_memory *);
int md_memory_exec_check(const struct md_interception_memory *, uintptr_t, size_t);
int md_memory_mapping_prepare(struct md_interception_memory *, struct md_mapping_change *,
    enum md_mapping_operation, uintptr_t, size_t, size_t new_length, unsigned flags, int noexec);
/* Borrows a regular-file description and retains a shared CLOEXEC backing.
 * Independent address spaces share only file identity, not private bytes/offsets.
 * A failed syscall never publishes it. Native devices remain kernel-owned. */
int md_memory_mapping_backing(struct md_interception_memory *, struct md_mapping_change *, int fd, uint64_t offset);
/* Borrowed under the address-space turn. No pathname lookup or FD-number reuse.
 * Returns 1 for continuous provenance, 0 for an untracked/mixed range. */
int md_memory_file_view(const struct md_interception_memory *, uintptr_t, size_t,
    int *fd, uint64_t *offset);
void md_memory_mapping_finish(struct md_interception_memory *, struct md_mapping_change *, long result);
void md_memory_mapping_abandon(struct md_interception_memory *, struct md_mapping_change *);
#endif
