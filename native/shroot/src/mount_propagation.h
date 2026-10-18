#ifndef MD_MOUNT_PROPAGATION_H
#define MD_MOUNT_PROPAGATION_H
#include <stdint.h>

struct md_mount_namespace;
struct md_mount_group;
struct md_resource_wakeup;
struct md_filesystem;
struct md_mount_links {
    struct md_mount_group *shared, *master;
    unsigned unbindable;
};
struct md_mount_members { struct md_mount_namespace **views; unsigned count; };
/* Weak family membership follows namespace copies. A worker snapshot pins each
 * live namespace; no namespace or mount is kept alive merely by a peer group. */
int md_mount_family_new(struct md_mount_namespace *);
void md_mount_family_leave(struct md_mount_namespace *);
void md_mount_family_join(struct md_mount_namespace *,struct md_mount_namespace *source);
int md_mount_family_capture(struct md_mount_namespace *,struct md_mount_members *);
void md_mount_members_release(struct md_mount_members *);
/* Last-anchor release may run outside the filesystem worker. It only schedules
 * collection; topology mutation stays on the owning event loop. */
void md_mount_family_wakeup(struct md_mount_namespace *,struct md_resource_wakeup *);
void md_mount_family_retire(struct md_mount_namespace *);
int md_mount_family_take_collection(struct md_mount_namespace *);
int md_mount_family_collect(struct md_filesystem *);
struct md_mount_links md_mount_links_copy(const struct md_mount_links *);
void md_mount_links_release(struct md_mount_links *);
unsigned md_mount_group_id(const struct md_mount_group *);
struct md_mount_group *md_mount_group_parent(const struct md_mount_group *);
int md_mount_group_contains(const struct md_mount_group *,const struct md_mount_group *);
struct md_mount_group *md_mount_group_retain(struct md_mount_group *);
void md_mount_group_release(struct md_mount_group *);
struct md_mount_group *md_mount_group_new(struct md_mount_group *master);
int md_mount_links_observe(unsigned shared,unsigned master,unsigned unbindable,struct md_mount_links *);
int md_mount_links_foreign(const struct md_mount_links *);
/* Prepared relationship; input and existing groups remain unchanged on error. */
int md_mount_links_change(const struct md_mount_members *,const struct md_mount_links *,
    unsigned propagation,struct md_mount_links *);
struct md_mount_group *md_mount_group_live(const struct md_mount_members *,struct md_mount_group *,
    const struct md_mount_links *excluded);
#endif
