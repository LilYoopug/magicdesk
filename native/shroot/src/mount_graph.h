#ifndef MD_MOUNT_GRAPH_H
#define MD_MOUNT_GRAPH_H
#include "fs_mounts.h"
#include "inode_custody.h"
struct md_fs_mounts;
struct md_view_mount;

enum { MD_MOUNT_GRAPH_PLACEMENT_FDS=6+4*MD_FS_MOUNTS_MAX,
    MD_MOUNT_GRAPH_FDS=MD_MOUNT_GRAPH_PLACEMENT_FDS+MD_FS_MOUNTS_MAX*MD_INODE_CUSTODY_FDS };
/* An owned parcel: manifest, root policy, pin carrier, then source/covered/policy per mount.
 * Portable providers carry one further live superblock policy descriptor.
 * Deduplicated backing-store custody follows placement. Allocate only the
 * actual vector on this cold path, never its maximum on normal filesystem IO.
 * No paths, data OFDs, process pointers or process-local mount IDs travel here.
 * Use only with authenticated store/connection custody, not guest input. */
struct md_mount_graph_parcel { unsigned count; int *fd; };
void md_mount_graph_parcel_close(struct md_mount_graph_parcel *);
unsigned md_mount_graph_rights(struct md_mount_namespace *);
/* Private providers retain process-local owners, not serializable host paths. */
int md_mount_graph_portable(const struct md_mount_namespace *);
/* Worker-only. The final right identifies the live topology stream. Snapshot
 * rights retain their own revision and backing stores until import completes. */
int md_mount_graph_export(struct md_mount_namespace *, int store_root, struct md_mount_graph_parcel *);
int md_mount_graph_foreign(const struct md_mount_namespace *);
int md_mount_graph_acquire_pin(struct md_mount_namespace *, const struct md_view_mount *);
int md_mount_graph_exclude(const struct md_mount_namespace *, const struct md_view_mount *, int *lease);
int md_mount_graph_check_pin(const struct md_mount_namespace *, int pin);
/* Publish a prepared tree before making it locally visible. Parent pointers
 * in the candidate refer to the namespace's stable mount slots. A nonportable
 * provider publishes an unavailable revision, not a native approximation.
 * Local mounts continue; foreign sync explicitly fails until a complete
 * portable revision is published again. */
struct md_mount_layout {
    const struct md_view_mount *base, *entries, *root;
    unsigned count;
};
int md_mount_graph_update(struct md_mount_namespace *, const struct md_mount_layout *);
struct md_mount_graph_change { struct md_mount_namespace *view; struct md_mount_layout layout; };
int md_mount_graph_update_many(const struct md_mount_graph_change *,unsigned);
int md_mount_graph_sync(struct md_mount_namespace *);
/* Always consumes the parcel. An empty destination receives a fully validated
 * view with local mount IDs; an existing destination must name the same stream.
 * Newer revisions merge only after complete validation, retaining object IDs.
 * Failure never replaces the destination.
 * The caller interns views within its worker; this does not authorize multiple
 * workers to share a mutable object cache. Backing leases remain independent of
 * worker connections and survive the publisher. */
int md_mount_graph_import(struct md_mount_graph_parcel *, struct md_mount_namespace **);

struct md_mount_graph;
void md_mount_graph_close(struct md_mount_graph *);
#endif
