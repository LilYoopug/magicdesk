#ifndef MD_INODE_CUSTODY_H
#define MD_INODE_CUSTODY_H
#include "inode_lifetime.h"

enum { MD_INODE_CUSTODY_FDS=512 };
/* Owned captured rights: immutable manifest, root maintenance lease, then
 * each loaded lower's objects directory and maintenance lease. No data OFDs,
 * SQLite handles or paths. Larger vectors need bounded transport chunks. */
struct md_inode_custody_parcel { unsigned count; int fd[MD_INODE_CUSTODY_FDS]; };
void md_inode_custody_parcel_close(struct md_inode_custody_parcel *);
/* Worker-only snapshot of currently loaded sources. Output must be empty.
 * Duplicates existing descriptions/locks; never reopens or changes flock state.
 * Local references and ordinary IO do not use this cold publication path. */
int md_inode_custody_export(const struct md_inode_lifetime *, struct md_inode_custody_parcel *);
/* Always consumes the parcel, publishes only into an empty destination after
 * full validation. expected_root is borrowed from the authenticated local store
 * scope; its physical identity must match. Private peers must supply the actual
 * lease descriptions: inode equality alone cannot prove flock ownership. */
int md_inode_custody_import(struct md_inode_custody_parcel *, int expected_root,
        struct md_inode_lifetime **);
#endif
