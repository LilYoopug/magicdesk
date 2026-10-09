#ifndef MD_MEMORY_REPLACE_H
#define MD_MEMORY_REPLACE_H
#include <stddef.h>
#include <stdint.h>

enum md_memory_replace_phase {
    MD_MEMORY_REPLACE_EMPTY, MD_MEMORY_REPLACE_RESERVE, MD_MEMORY_REPLACE_SAVE,
    MD_MEMORY_REPLACE_INSTALL, MD_MEMORY_REPLACE_RESTORE,
    MD_MEMORY_REPLACE_DROP_CANDIDATE, MD_MEMORY_REPLACE_DROP_BACKUP,
    MD_MEMORY_REPLACE_DONE, MD_MEMORY_REPLACE_BROKEN
};
/* Owns candidate from successful begin through DONE. Original stays at backup
 * until installation or restoration is confirmed. The caller keeps every
 * CLONE_VM peer quiescent, executes each command once in the exact mm, and
 * observes its terminal result before requesting another. No target mapping
 * may be reused while a command is pending. BROKEN retains custody: the caller
 * must reconcile or terminate the address space, never resume it on faith. */
struct md_memory_replace {
    uintptr_t original, candidate, backup;
    size_t length, page_size;
    enum md_memory_replace_phase phase;
    int pending, cancelled, committed, displaced;
    long error;
};
struct md_memory_replace_call { long number; unsigned long args[6]; };
int md_memory_replace_begin(struct md_memory_replace *, uintptr_t original,
    uintptr_t candidate, size_t length, size_t page_size);
int md_memory_replace_next(struct md_memory_replace *, struct md_memory_replace_call *);
int md_memory_replace_observed(struct md_memory_replace *, long result);
void md_memory_replace_cancel(struct md_memory_replace *);
void md_memory_replace_lost(struct md_memory_replace *);
long md_memory_replace_result(const struct md_memory_replace *);
#endif
