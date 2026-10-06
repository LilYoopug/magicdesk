#ifndef MD_RECEIVED_FDS_H
#define MD_RECEIVED_FDS_H

/* Supervisor-owned custody. The helper builds the vector before sharing it;
 * worker requests pin the immutable vector without duplicating its FDs.
 * Reference changes run on the supervisor, after worker completion or join. */
struct md_received_fds { unsigned references, count, capacity; int fds[]; };
int md_received_fds_reserve(struct md_received_fds **, unsigned capacity);
struct md_received_fds *md_received_fds_retain(struct md_received_fds *);
void md_received_fds_release(struct md_received_fds *);

#endif
