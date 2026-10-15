#ifndef MD_INODE_PUBLICATION_H
#define MD_INODE_PUBLICATION_H
#include <stdint.h>
#include <sys/stat.h>

struct md_inode_store;
struct mdi_node;
/* These operations borrow the store gate. Recovery runs before a SQLite
 * snapshot; admission and namespace operations use the same owner. */
int mdi_publication_open(struct md_inode_store *, int prepare);
void mdi_publication_close(struct md_inode_store *);
int mdi_publication_pending(const struct md_inode_store *);
int mdi_publication_recover(struct md_inode_store *);
/* Admit one native regular leaf to the object catalogue without copying its
 * body. Requires the sole, unchanged operation snapshot. A durable intent may
 * survive failure: do not replay the enclosing guest mutation on an error.
 * Metadata is captured from the validated leaf, not supplied by the caller. */
int mdi_publication_promote(struct md_inode_store *, const struct mdi_node *parent,
        const char *name, const struct stat *expected, struct mdi_node *out);
#endif
