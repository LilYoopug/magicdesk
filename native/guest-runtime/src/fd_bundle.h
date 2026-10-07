#ifndef MD_FD_BUNDLE_H
#define MD_FD_BUNDLE_H

/* Immutable kernel-owned vector. Each node contains one seqpacket whose writer
 * is closed before publication. No shared read cursor or live sender is needed.
 * This is a private format, not an application descriptor classifier. */
int md_fd_bundle_pack(const int *fds, unsigned count, int *out);
/* Caller provides count slots. Repeated/concurrent peeks retain the queue.
 * Success owns all output FDs; failure closes partial results and sets -1. */
int md_fd_bundle_peek(int fd, unsigned count, int *out);
#endif
