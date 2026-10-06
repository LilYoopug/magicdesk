#ifndef MD_FD_INSTALL_H
#define MD_FD_INSTALL_H
#include "fd_origins.h"
#include <stdint.h>

enum { MD_FD_INSTALL_WAIT=-4096 };
/* The caller retains the source FD and origin until completion/cancellation.
 * One supervisor event loop owns each record. No guest acknowledgement or
 * guessed close is needed: atomic ADDFD_SEND publishes the kernel result under
 * the destination table turn before any queued mutation can run. */
struct md_fd_install {
    struct md_fd_order files;
    struct md_fs_anchor *origin;
    uint64_t notification;
    int listener, source;
    int retire_error;
    unsigned flags;
};
int md_fd_install_begin(struct md_fd_install *, struct md_fd_origins *,
        int listener, uint64_t notification, int source, struct md_fs_anchor *,
        unsigned flags, struct md_resource_wakeup *);
/* WAIT retains the record; any other result completes it. A negative result
 * still needs an error reply (ENOENT permits the receiver to have died).
 * retire_error reports an internal turn/wakeup failure separately: it cannot
 * replace a committed kernel result or authorize a second notification reply. */
int md_fd_install_progress(struct md_fd_install *);
int md_fd_install_cancel(struct md_fd_install *);
#endif
