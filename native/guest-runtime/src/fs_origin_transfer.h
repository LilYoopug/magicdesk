#ifndef MD_FS_ORIGIN_TRANSFER_H
#define MD_FS_ORIGIN_TRANSFER_H
#include "fd_messages.h"
#include "inode_custody.h"
#include "mount_graph.h"
#include "fd_receipt.h"

enum { MD_FS_ORIGIN_MAX_RIGHTS=1+MD_FD_RECEIPT_MAX*(MD_INODE_CUSTODY_FDS+MD_MOUNT_GRAPH_FDS+2) };

/* Private control-plane rights, never application data. The sender exports a
 * pinned, bound message only after claim. Transport authenticates the peer and
 * owns bounded chunking/cancellation; matching a route is not authentication. */
struct md_fs_origin_parcel { unsigned count; int *fd; };
void md_fs_origin_parcel_close(struct md_fs_origin_parcel *);
int md_fs_origin_export(const struct md_fd_message *, struct md_fs_origin_parcel *);
/* A typed custody envelope can select only the filesystem entries while
 * preserving the authenticated route and original application indices. */
int md_fs_origin_export_entries(const struct md_fd_message *, struct md_fd_object *const *, struct md_fs_origin_parcel *);

/* One filesystem worker/store scope. Opens its own O_PATH reference relative
 * to the retained store directory, never duplicates its maintenance lock.
 * Views are interned while anchors retain
 * them; collect drops cache-only views. No data-call work or periodic scan. */
struct md_fs_origin_imports;
int md_fs_origin_imports_new(int root, struct md_fs_origin_imports **);
void md_fs_origin_imports_collect(struct md_fs_origin_imports *);
void md_fs_origin_imports_free(struct md_fs_origin_imports *);

/* Atomic publication into an empty output; always consumes the parcel. The
 * expected route must come from the verified carrier/claim, not this parcel.
 * Existing views/IDs are reused; new cache entries appear only after validation.
 * Vector entries are borrowed until release, and may be NULL (unknown). */
struct md_fs_origin_vector;
int md_fs_origin_import(struct md_fs_origin_imports *, const struct md_fd_message_route *,
        struct md_fs_origin_parcel *, struct md_fs_origin_vector **);
unsigned md_fs_origin_vector_count(const struct md_fs_origin_vector *);
struct md_fs_anchor *const *md_fs_origin_vector_entries(const struct md_fs_origin_vector *);
void md_fs_origin_vector_free(struct md_fs_origin_vector *);
#endif
