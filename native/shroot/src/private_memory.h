#ifndef MD_PRIVATE_MEMORY_H
#define MD_PRIVATE_MEMORY_H
#include <stddef.h>
#include <stdint.h>

/* Task-affine preparation, called only with the address-space turn and all
 * CLONE_VM writers quiescent. The retained source must be the original mapping
 * description. Native guest noexec checks precede this operation. Preparation
 * never changes the original VMA; the caller owns candidate publication and
 * cancellation. No anonymous replacement or application-specific policy. */
struct md_private_memory {
    uintptr_t address, candidate;
    size_t length, page_size, copied_pages;
    uint64_t offset;
    int source, protection;
};
/* Captured by the owning address space before it becomes nondumpable. These
 * proc descriptions refer to that exact mm, not a PID to reopen later. Exec
 * and non-CLONE_VM fork require independent capture; never inherit this tuple
 * as authority over a different address space. */
struct md_private_memory_access { int maps, memory, pagemap; };
struct md_private_memory_plan { unsigned advice; int flags; };
struct md_private_memory_scan;
enum { MD_PRIVATE_MEMORY_COPY_BYTES=65536 };
/* Pure request admission, before stopping writers or inspecting their VMAs. */
long md_private_memory_validate(const struct md_private_memory *);
/* Incremental preparation bounds supervisor work per event-loop turn. A step
 * returns 0 for more work, 1 for completion, or a negative errno. */
long md_private_memory_scan_begin(struct md_private_memory *, const struct md_private_memory_access *,
    struct md_private_memory_scan **);
long md_private_memory_scan_step(struct md_private_memory_scan *, struct md_private_memory_plan *);
void md_private_memory_scan_end(struct md_private_memory_scan *);
long md_private_memory_copy_step(struct md_private_memory *, const struct md_private_memory_access *,
    const struct md_private_memory_plan *, size_t *position, void *buffer, size_t buffer_size);
/* Supervisor-side preparation borrows exact-mm proc access. Only candidate
 * mmap and advice require execution in that mm; copy uses proc descriptions. */
long md_private_memory_plan(struct md_private_memory *, const struct md_private_memory_access *,
    struct md_private_memory_plan *);
long md_private_memory_copy(struct md_private_memory *, const struct md_private_memory_access *,
    const struct md_private_memory_plan *);
int md_private_memory_advice(const struct md_private_memory_plan *, unsigned index);
long md_private_memory_access_open(struct md_private_memory_access *);
void md_private_memory_access_close(struct md_private_memory_access *);
long md_private_memory_prepare(struct md_private_memory *, const struct md_private_memory_access *);
void md_private_memory_discard(struct md_private_memory *);
#endif
