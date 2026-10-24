#ifndef MD_MOUNT_NAMESPACE_H
#define MD_MOUNT_NAMESPACE_H
#include <stdint.h>

/* A task-owned mount view. References protect lifetime across the supervisor,
 * registry and filesystem worker; only that worker resolves or mutates it. */
struct md_mount_namespace;
struct md_user_namespace;
struct md_mount_namespace *md_mount_namespace_new(void);
uint64_t md_mount_namespace_inode(const struct md_mount_namespace *);
struct md_mount_namespace *md_mount_namespace_retain(struct md_mount_namespace *);
void md_mount_namespace_release(struct md_mount_namespace *);
int md_mount_namespace_attached(const struct md_mount_namespace *);
int md_mount_namespace_managed_paths(const struct md_mount_namespace *);
struct md_inode_mount_boundaries;
struct md_user_namespace *md_mount_namespace_owner(const struct md_mount_namespace *);
/* Only an unpublished namespace candidate may change its owner. */
void md_mount_namespace_set_owner(struct md_mount_namespace *, struct md_user_namespace *);
int md_mount_namespace_lock_inherited(struct md_mount_namespace *);
#endif
