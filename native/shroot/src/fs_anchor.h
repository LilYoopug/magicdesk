#ifndef MD_FS_ANCHOR_H
#define MD_FS_ANCHOR_H
#include "fd_object.h"

/* Worker-produced path provenance, not an open-file-description mirror. Pins
 * the mount view, O_PATH identity and backing-store lifetime, not its SQLite
 * connection; the kernel owns data IO and locks. Process-local pointers never
 * cross RPC; private peers use the explicit origin-transfer contract. */
struct md_fs_anchor;
struct md_fd_object *md_fs_anchor_object(struct md_fs_anchor *);
struct md_fs_anchor *md_fs_anchor_from_object(struct md_fd_object *);
struct md_fs_anchor *md_fs_anchor_retain(struct md_fs_anchor *);
void md_fs_anchor_release(struct md_fs_anchor *);
/* Borrowed O_PATH descriptor, suitable for cwd/path traversal, not data IO. */
int md_fs_anchor_fd(const struct md_fs_anchor *);
/* Live mount policy under the caller's already retained provenance. */
unsigned md_fs_anchor_policy(const struct md_fs_anchor *);
struct md_fs_info;
/* Add placement identity to provider metadata without exposing its carrier. */
void md_fs_anchor_mount_info(const struct md_fs_anchor *,struct md_fs_info *);
int md_fs_anchor_same(const struct md_fs_anchor *, const struct md_fs_anchor *);
/* Object identity only, not authority to associate an arbitrary FD with a view.
 * Callers establish that association before checking the actual kernel object. */
int md_fs_anchor_check_fd(const struct md_fs_anchor *, int);
#endif
