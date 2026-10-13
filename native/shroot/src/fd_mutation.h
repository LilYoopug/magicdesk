#ifndef MD_FD_MUTATION_H
#define MD_FD_MUTATION_H
#include "fd_origins.h"

/* Prepared while holding the file-table turn. Allocation failure precedes the
 * kernel mutation; completion never allocates or substitutes a new owner. */
struct md_fd_mutation {
    struct md_fd_origin_update update;
    long nr;
    unsigned long args[3];
};
/* Cold admission for a mutation that can remove or change an operation-owned
 * slot in this exact table. 1 retains the conflicting loan; 0 does not require
 * rendezvous. Copy-on-unshare/exec affect another table, not its live waiters.
 * The caller owns a RUNNING table turn through this query and the mutation. */
int md_fd_mutation_loan(const struct md_fd_order *,long nr,const unsigned long args[6],
        int *number,struct md_fd_loan **);
int md_fd_mutation_prepare(struct md_fd_origins *, long nr,
        const unsigned long args[6], struct md_fd_mutation *);
int md_fd_mutation_finish(struct md_fd_mutation *, struct md_fd_origins *, long result);
void md_fd_mutation_discard(struct md_fd_mutation *);
/* Decode only the terminal register at an observed openat return gate. The
 * caller must establish that PC/syscall identity and retain the file-table
 * turn. A killed syscall may leave either ABI representation of AT_FDCWD.
 * Returns 1 with a publication result, or 0 without changing output. */
int md_fd_mutation_terminal_open(const struct md_fd_mutation *, unsigned long value, long *result);
/* Terminal task death without a syscall result is not rollback. Forget only
 * possibly changed slots; never retain a potentially wrong mount origin. */
int md_fd_mutation_abandon(struct md_fd_mutation *, struct md_fd_origins *);
#endif
