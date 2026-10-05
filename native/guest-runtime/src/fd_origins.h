#ifndef MD_FD_ORIGINS_H
#define MD_FD_ORIGINS_H
#include "fs_anchor.h"

/* Guest provenance only: no kernel FD, offset or open description is owned.
 * Task-owner operations run on the supervisor; pins do not count as owners. */
struct md_fd_origins;
struct md_fd_origin_entry;
struct md_fd_origin_update {
    struct md_fd_origins *table;
    struct md_fd_origin_entry *entry;
};
struct md_fd_origins *md_fd_origins_new(void);
struct md_fd_origins *md_fd_origins_fork(struct md_fd_origins *, int shared);
struct md_fd_origins *md_fd_origins_unshare_prepare(struct md_fd_origins *);
void md_fd_origins_release(struct md_fd_origins *);
struct md_fd_origins *md_fd_origins_pin(struct md_fd_origins *);
void md_fd_origins_unpin(struct md_fd_origins *);
/* A retained origin, or NULL for an untracked descriptor, not proof of EBADF. */
struct md_fs_anchor *md_fd_origins_get(struct md_fd_origins *, int fd, unsigned *flags);
/* Prepare before a kernel mutation; finish is allocation-free. A negative
 * result discards it. NULL origin removes any prior destination annotation.
 * The caller orders kernel mutations; this lock alone cannot order syscalls. */
int md_fd_origins_prepare(struct md_fd_origins *, struct md_fs_anchor *, unsigned flags,
        struct md_fd_origin_update *);
void md_fd_origins_finish(struct md_fd_origin_update *, int result_fd);
int md_fd_origins_set_flags(struct md_fd_origins *, int fd, unsigned flags);
int md_fd_origins_close_range(struct md_fd_origins *, unsigned first, unsigned last, int cloexec);
void md_fd_origins_exec(struct md_fd_origins *);
#endif
