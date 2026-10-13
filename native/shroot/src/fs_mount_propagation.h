#ifndef MD_FS_MOUNT_PROPAGATION_H
#define MD_FS_MOUNT_PROPAGATION_H
struct md_filesystem;
struct md_view_mount;
/* Candidates own only slots[]; other entries borrow the current tree. Success
 * adopts every new instance, including propagated copies. Failure leaves the
 * caller's candidates closeable and all live placements unchanged. */
int md_view_mount_attach(struct md_filesystem *,struct md_view_mount *entries,
    unsigned count,const unsigned *slots,unsigned created,unsigned root);
/* Existing slots keep their anchors, object IDs and source descriptions. Only
 * placement and prepared relationship references transfer on success. */
/* Placement slots use the common node numbering: base=0, tree entry=i+1. */
int md_view_mount_place(struct md_filesystem *,struct md_view_mount *base,struct md_view_mount *entries,
    unsigned count,const unsigned *slots,unsigned placed,unsigned root);
int md_view_mount_propagation(struct md_filesystem *,struct md_view_mount *,unsigned kind,int recursive);
int md_view_mount_propagate_detach(struct md_filesystem *,struct md_view_mount *,int lazy);
#endif
