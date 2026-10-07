#ifndef MD_MOUNT_GRAPH_H
#define MD_MOUNT_GRAPH_H
#include "fs_mounts.h"

enum { MD_MOUNT_GRAPH_FDS=1+3*MD_FS_MOUNTS_MAX };
/* An owned, ordered parcel: manifest, then source/covered/policy for each mount.
 * No paths, data OFDs, process pointers or process-local mount IDs travel here.
 * Use only with authenticated store/connection custody, not guest input. */
struct md_mount_graph_parcel { unsigned count; int fd[MD_MOUNT_GRAPH_FDS]; };
void md_mount_graph_parcel_close(struct md_mount_graph_parcel *);
/* Worker-only. Output must be empty. Lazy publication freezes graph identity;
 * later topology changes fail ESTALE rather than replacing that identity.
 * Policy flags remain live. Failure leaves output empty and the view usable. */
int md_mount_graph_export(struct md_mount_namespace *, struct md_mount_graph_parcel *);
/* Always consumes the parcel. An empty destination receives a fully validated
 * view with local mount IDs; an existing destination must name the same sealed
 * graph and is reused unchanged. Failure never replaces the destination.
 * The caller interns views within its worker; this does not authorize multiple
 * workers to share a mutable object cache or transfer backing-store leases. */
int md_mount_graph_import(struct md_mount_graph_parcel *, struct md_mount_namespace **);

struct md_mount_graph;
void md_mount_graph_close(struct md_mount_graph *);
#endif
