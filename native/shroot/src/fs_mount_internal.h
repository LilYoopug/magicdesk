#ifndef MD_FS_MOUNT_INTERNAL_H
#define MD_FS_MOUNT_INTERNAL_H
#include "fs_mounts.h"
#include "mount_policy.h"
#include "mount_namespace_internal.h"
#include "pid_namespace.h"
#include "devpts_view.h"
#include "cgroup.h"
#include "sysfs_view.h"
#include "provider_tree.h"
#include "ipc_namespace.h"
#include "mqueue_view.h"
#include "mount_source.h"
#include "proc_namespace.h"
#include <limits.h>
#include <stdatomic.h>
#include <sys/mount.h>

/* Data IO retains the backing filesystem's timestamps. Atime requests are
 * compatibility hints, not per-mount timestamp guarantees. */
#define MD_FS_MOUNT_ATIME_HINTS (MS_NOATIME|MS_NODIRATIME|MS_RELATIME|MS_STRICTATIME|MS_LAZYTIME)
#define MD_FS_MOUNT_POLICY_FLAGS (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC)
#define MD_FS_MOUNT_FLAGS (MD_FS_MOUNT_POLICY_FLAGS|MD_FS_MOUNT_ATIME_HINTS)

static inline unsigned md_fs_mount_flags(unsigned flags) {
    return ((flags&MS_RDONLY) ? MD_MOUNT_READONLY : 0)
        | ((flags&MS_NOSUID) ? MD_MOUNT_NOSUID : 0)
        | ((flags&MS_NODEV) ? MD_MOUNT_NODEV : 0)
        | ((flags&MS_NOEXEC) ? MD_MOUNT_NOEXEC : 0);
}
struct md_view_location;
void md_fs_bpf(struct md_filesystem *,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
void md_fs_landlock(struct md_filesystem *,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
int md_fs_landlock_native(struct md_filesystem *,const struct md_fs_request *,struct md_view_mount *,int fd);
int md_fs_landlock_delegate(struct md_filesystem *,const struct md_fs_request *,const char *);
int md_fs_proc_operation(struct md_filesystem *,struct md_mount_namespace *,struct md_view_mount *,
    int,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
int md_fs_cgroup_operation(struct md_filesystem *,struct md_mount_namespace *,
    struct md_view_mount *,int fd,int parent,const char *name,const struct md_fs_request *,
    struct md_fs_result *,const struct md_fs_output *);
int md_fs_mount_file_operation(struct md_filesystem *,struct md_mount_namespace *,
    struct md_view_mount *,int,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
int md_fs_sysfs_operation(struct md_filesystem *,struct md_mount_namespace *,struct md_view_mount *,
    int,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
int md_fs_provider_operation(struct md_filesystem *,struct md_mount_namespace *,struct md_view_mount *,
    int,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
int md_fs_mqueue_operation(struct md_filesystem *,struct md_mount_namespace *,struct md_view_mount *,
    int,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
static inline const struct md_mount_namespace *md_view_file_namespace(struct md_control_file file) {
    const struct md_namespace_reference *ref=file.ops && file.ops->namespace_reference
        ? file.ops->namespace_reference(file.context) : NULL;
    return ref && ref->kind==MD_NAMESPACE_MOUNT ? ref->value.mount : NULL;
}
static inline int md_view_file_cycle(struct md_control_file file,const struct md_mount_namespace *view) {
    const struct md_mount_namespace *target=md_view_file_namespace(file);
    /* The base ID is allocated at namespace birth and never replaced. Like
     * Linux nsfs, only references to younger mount namespaces are admitted. */
    return target && view->base.id>=target->base.id;
}
int md_fs_mount_temporary(struct md_filesystem *, const struct md_fs_request *, struct md_mount_source *);
int md_fs_mount_overlay(struct md_filesystem *, const struct md_fs_request *, struct md_mount_source *);
int md_fs_private_mounts_parent(struct md_inode_store *);

enum { MD_VIEW_BUCKETS = 4096, MD_VIEW_OBJECT_LIMIT = 65536 };
static inline int md_view_base(const struct md_mount_namespace *view, const struct md_view_mount *m) {
    return !m || (view && m==&view->base);
}
static inline int md_view_inode(const struct md_view_mount *m) {
    return !m || m->backing==MD_MOUNT_INODE;
}
static inline int md_view_readonly(const struct md_view_mount *m) {
    return m && !!(md_mount_policy_flags(&m->policy)&MD_MOUNT_READONLY);
}
struct md_view_object {
    struct md_view_object *next, *id_next;
    struct stat identity;
    int fd;
    /* The object key is (mount, native device, native inode), not inode alone. */
    struct md_view_mount *mount;
    char id[33], inode[33];
};
struct md_fs_mounts {
    unsigned count, objects;
    struct md_view_mount mounts[MD_FS_MOUNTS_MAX];
    struct md_view_object *table[MD_VIEW_BUCKETS];
    struct md_view_object *by_id[MD_VIEW_BUCKETS];
};
static inline struct md_view_mount *md_view_mount_node(struct md_mount_namespace *view, unsigned node) {
    return node ? &view->tree->mounts[node-1] : &view->base;
}
/* Worker-only retirement. The caller excludes origins, selected roots and
 * child placements before discarding this slot and its object-cache entries. */
void md_view_mount_forget(struct md_fs_mounts *, struct md_view_mount *);
struct md_view_location {
    int parent, fd, boundary;
    struct md_mount_namespace *view;
    struct md_view_mount *mount;
    char name[NAME_MAX+1];
};
struct md_fs_anchor {
    struct md_fd_object object;
    struct md_inode_lifetime *lifetime;
    /* NULL view retains a native provider object with no logical mount policy.
     * It is an exact path anchor, not a claim on a matching mounted inode. */
    struct md_mount_namespace *view;
    struct md_view_mount *mount;
    int fd, mount_pin;
    dev_t device;
    ino_t inode;
};
int md_view_same(const struct stat *, const struct stat *);
struct md_view_mount *md_view_root_mount(struct md_filesystem *);
int md_view_root_fd(struct md_filesystem *);
int md_view_record(struct md_filesystem *, int fd, struct md_view_mount *, struct md_view_object **);
int md_view_identity(struct md_filesystem *, int fd, struct md_view_object **);
int md_view_path(struct md_filesystem *, int fd, struct md_view_mount *, char *, size_t);
int md_view_backing_path(struct md_filesystem *, int fd, const struct md_view_mount *, char *, size_t);
/* Worker-only publication of an already prepared filesystem. The caller owns
 * mount authorization; failure keeps the source and destination unchanged. */
int md_view_attach_source(struct md_filesystem *, const struct md_mount_source *,
        const struct md_view_location *target, struct md_view_mount **);
int md_view_mount_collect(struct md_filesystem *);
struct md_view_object *md_view_object(struct md_filesystem *, const char *id);
/* Internal lookup opt-in: report task-owned proc traversal to the adapter
 * before executing an operation. Never admitted as an openat2 resolve flag. */
#define MD_VIEW_TASK_PATH (UINT64_C(1)<<63)
/* Bind sources may capture an implicit provider from a retained old root. */
#define MD_VIEW_PROVIDER_SOURCE (UINT64_C(1)<<62)
/* Mount placement may cover the initial proc/dev provider's own dentry. */
#define MD_VIEW_MOUNT_TARGET (UINT64_C(1)<<61)
int md_view_descriptor(struct md_filesystem *, int, const struct md_fs_anchor *, struct md_view_location *);
/* Native device delegation is only for unannotated inherited descriptors.
 * Attached devices must complete in the mount engine, including nodev policy. */
int md_view_task_path(struct md_filesystem *, int, const char *, const char *, uint64_t, int native_devices);
int md_view_walk(struct md_filesystem *, int base, const struct md_fs_anchor *, const char *path, int follow, int missing,
        uint64_t resolve, struct md_view_location *);
void md_view_location_close(struct md_view_location *);
int md_view_fdpath(int fd, char *, size_t);
int md_mount_id_allocate(unsigned *);
int md_view_anchor_check(struct md_filesystem *, int fd, const struct md_fs_anchor *);
/* Consumes a validated O_PATH descriptor only on success; retains the owners. */
struct md_fs_anchor *md_view_anchor_new(struct md_inode_lifetime *, struct md_mount_namespace *,
        struct md_view_mount *, int fd, dev_t, ino_t);
struct md_fs_anchor *md_view_anchor_import(struct md_inode_lifetime *, struct md_mount_namespace *,
        struct md_view_mount *, int fd, int pin, dev_t, ino_t);
void md_view_capture(struct md_filesystem *, struct md_mount_namespace *, struct md_view_mount *,
        struct md_fs_result *, const struct md_fs_output *);
#endif
