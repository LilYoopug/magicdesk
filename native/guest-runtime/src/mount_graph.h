#ifndef MD_MOUNT_GRAPH_H
#define MD_MOUNT_GRAPH_H
#include "fs_mounts.h"
#include "inode_custody.h"

enum { MD_MOUNT_GRAPH_PLACEMENT_FDS=2+3*MD_FS_MOUNTS_MAX,
    MD_MOUNT_GRAPH_FDS=MD_MOUNT_GRAPH_PLACEMENT_FDS+MD_FS_MOUNTS_MAX*MD_INODE_CUSTODY_FDS };
/* An owned parcel: manifest, root policy, then source/covered/policy per mount.
 * Deduplicated backing-store custody follows placement. Allocate only the
 * actual vector on this cold path, never its maximum on normal filesystem IO.
 * No paths, data OFDs, process pointers or process-local mount IDs travel here.
 * Use only with authenticated store/connection custody, not guest input. */
struct md_mount_graph_parcel { unsigned count; int *fd; };
void md_mount_graph_parcel_close(struct md_mount_graph_parcel *);
unsigned md_mount_graph_rights(const struct md_mount_namespace *);
/* Worker-only. Output must be empty. Lazy publication freezes graph identity;
 * later topology changes fail ESTALE rather than replacing that identity.
 * Policy flags remain live. Failure leaves output empty and the view usable. */
int md_mount_graph_export(struct md_mount_namespace *, struct md_mount_graph_parcel *);
/* Always consumes the parcel. An empty destination receives a fully validated
 * view with local mount IDs; an existing destination must name the same sealed
 * graph and is reused unchanged. Failure never replaces the destination.
 * The caller interns views within its worker; this does not authorize multiple
 * workers to share a mutable object cache. Backing leases remain independent of
 * worker connections and survive the publisher. */
int md_mount_graph_import(struct md_mount_graph_parcel *, struct md_mount_namespace **);

struct md_mount_graph;
void md_mount_graph_close(struct md_mount_graph *);
#endif
