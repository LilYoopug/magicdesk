#ifndef MD_INODE_VIEW_H
#define MD_INODE_VIEW_H
#include "inode_store.h"
#include "filesystem_kind.h"

/* A private namespace projection in the same transaction domain as its upper.
 * The retained scope selects both logical inode identities and its root. */
int md_inode_view_create(struct md_inode_store *, enum md_filesystem_kind,
        struct md_inode_store **);
int md_inode_view_validate(struct md_inode_store *);
/* Called with the store transaction held. Only unleased projections are removed. */
int mdi_views_collect(struct md_inode_store *);
int mdi_views_busy(struct md_inode_store *);
/* Requires the store's exclusive maintenance lease. */
int mdi_views_maintain(struct md_inode_store *);
#endif
