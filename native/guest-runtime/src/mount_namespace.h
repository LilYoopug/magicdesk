#ifndef MD_MOUNT_NAMESPACE_H
#define MD_MOUNT_NAMESPACE_H

/* A task-owned mount view. References protect lifetime across the supervisor,
 * registry and filesystem worker; only that worker resolves or mutates it. */
struct md_mount_namespace;
struct md_mount_namespace *md_mount_namespace_new(void);
struct md_mount_namespace *md_mount_namespace_retain(struct md_mount_namespace *);
void md_mount_namespace_release(struct md_mount_namespace *);
int md_mount_namespace_attached(const struct md_mount_namespace *);
#endif
