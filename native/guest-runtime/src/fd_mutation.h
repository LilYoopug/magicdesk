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
int md_fd_mutation_prepare(struct md_fd_origins *, long nr,
        const unsigned long args[6], struct md_fd_mutation *);
int md_fd_mutation_finish(struct md_fd_mutation *, struct md_fd_origins *, long result);
void md_fd_mutation_discard(struct md_fd_mutation *);
/* Terminal task death without a syscall result is not rollback. Forget only
 * possibly changed slots; never retain a potentially wrong mount origin. */
int md_fd_mutation_abandon(struct md_fd_mutation *, struct md_fd_origins *);
#endif
