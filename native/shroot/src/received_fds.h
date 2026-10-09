#ifndef MD_RECEIVED_FDS_H
#define MD_RECEIVED_FDS_H

/* Supervisor-owned custody. The helper builds the vector before sharing it;
 * worker requests pin the immutable vector without duplicating its FDs.
 * Reference changes run on the supervisor, after worker completion or join. */
struct md_fd_object;
struct md_received_fds {
    unsigned references, count, capacity;
    struct md_fd_object **origins;
    int fds[];
};
int md_received_fds_reserve(struct md_received_fds **, unsigned capacity);
/* Bind a complete, authenticated vector before sharing. NULL entries remain
 * unknown. Known origins freeze growth and are retained independently of their
 * importer; an all-unknown vector allocates nothing. */
int md_received_fds_annotate(struct md_received_fds *, struct md_fd_object *const *, unsigned count);
/* Borrow a selected, ordered vector until custody release. The caller owns an
 * immutable index array. Validate it completely before writing output.
 * A consumer without origin support must not
 * silently discard known provenance: NULL origins then returns EOPNOTSUPP. */
int md_received_fds_select(const struct md_received_fds *, const int *indices, unsigned count,
        int *fds, struct md_fd_object **origins);
struct md_received_fds *md_received_fds_retain(struct md_received_fds *);
void md_received_fds_release(struct md_received_fds *);

#endif
