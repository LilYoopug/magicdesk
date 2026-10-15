#ifndef MD_INODE_INTERNAL_H
#define MD_INODE_INTERNAL_H
#include "inode_store.h"
#include <limits.h>
#include <sqlite3.h>
#include "guest_identity.h"
#include "posix_acl.h"
#include "inode_lifetime.h"
#include <stdatomic.h>
#include "filesystem_kind.h"
#include "landlock_policy.h"
struct md_fs_result;
struct md_fs_output;
struct md_inode_boundary { char *path; size_t capacity; unsigned operand; int mount_root, native_directory; uint64_t proc_namespace; };

#define MDI_ROOT "00000000000000000000000000000000"
#define MDI_SOURCES 256
struct md_inode_lifetime {
    atomic_uint refs;
    int root, temporary;
    enum md_filesystem_kind filesystem_kind;
    struct md_user_namespace *owner;
    struct md_identity *overlay_identity;
    dev_t device;
    ino_t inode;
    char scope[33];
    int scope_lease;
    int sources[MDI_SOURCES], source_leases[MDI_SOURCES];
};
/* Consumes the validated root/lease FD only on success. */
struct md_inode_lifetime *mdi_lifetime_new(int root, const struct stat *);
enum mdi_query { MDI_NODE, MDI_FD, MDI_LOOKUP, MDI_DIRECTORY_NAME, MDI_READDIR,
    MDI_BEGIN, MDI_BEGIN_WRITE, MDI_COMMIT, MDI_ROLLBACK, MDI_EVENT, MDI_EVENT_TRIM,
    MDI_EVENT_END, MDI_EVENT_SCAN, MDI_EVENT_BIRTH, MDI_EVENT_NAMES, MDI_BACKING_OBJECT, MDI_FILE_PATH, MDI_ACL,
    MDI_OVERLAY_LINK, MDI_DATA_VERSION, MDI_ADD_NAME, MDI_DELETE_NAME, MDI_REPARENT,
    MDI_EMPTY, MDI_CREATE_OBJECT, MDI_METADATA, MDI_RESERVE_FIRST, MDI_RESERVE_ADD, MDI_RESERVE_TAKE, MDI_QUERY_COUNT };
struct mdi_read_cache;
struct mdi_stat_location {
    char path[PATH_MAX];
    dev_t device;
    ino_t inode;
    int root;
};
struct md_inode_store {
    sqlite3 *db;
    int objects, watch_presence, locked, recording, readonly, reflink_unavailable;
    int super_readonly, super_checked, nodev;
    int native_files;
    sqlite3_int64 super_version;
    struct md_inode_lifetime *lifetime;
    const struct md_identity *identity;
    const struct md_landlock_policy *landlock;
    int landlock_execute;
    const char *root_id;
    unsigned creation_mask;
    struct md_inode_boundary *boundary;
    struct mdi_stat_location *stat_location;
    struct md_inode_watches *watches;
    struct mdi_fifo_owner *fifos;
    struct md_inode_statistics *statistics;
    struct mdi_overlay_writer *overlay;
    int write_transaction;
    int sync_requested;
    struct mdi_read_cache *read_cache;
    int cache_checked;
    unsigned read_depth;
    sqlite3_stmt *queries[MDI_QUERY_COUNT];
    struct mdi_publication *publication;
    sqlite3_int64 operation_changes;
    sqlite3_int64 event_sequence;
#ifdef MD_INODE_TESTING
    void (*observe)(enum md_inode_checkpoint, void *);
    void *context;
#endif
};
static inline int mdi_readonly(const struct md_inode_store *s) {
    return s->readonly || s->super_readonly;
}
int mdi_super_refresh(struct md_inode_store *, sqlite3_int64 version);
static inline const char *mdi_root(const struct md_inode_store *s) {
    return s->root_id ? s->root_id : s->lifetime->scope;
}
struct mdi_node {
    char id[33], parent[33], backing[NAME_MAX+34], scope[33];
    mode_t kind;
    dev_t device, logical_device, rdev;
    ino_t inode, logical_inode;
    nlink_t links;
    int attached, shared, source;
    int mode;
    uint32_t uid, gid;
    unsigned acl_mask;
    /* Native leaves are never cached. A positive descriptor borrows fd+1 only
     * for the enclosing operation, including after unlink or pathname reuse. */
    int native, descriptor;
};
struct mdi_location {
    struct mdi_node node, parent;
    char name[NAME_MAX+1];
    int exists, special, trailing;
};
struct mdi_cache_key {
    enum mdi_query query;
    uint64_t device, inode;
    const char *id, *name;
};
struct mdi_path_name { char parent[33], name[NAME_MAX+1]; int ambiguous; };
int mdi_cache_name_get(struct md_inode_store *, const struct mdi_cache_key *, struct mdi_path_name *);
void mdi_cache_name_put(struct md_inode_store *, const struct mdi_cache_key *, const struct mdi_path_name *);
int mdi_cache_get(struct md_inode_store *, const struct mdi_cache_key *, struct mdi_node *, int *result);
void mdi_cache_put(struct md_inode_store *, const struct mdi_cache_key *, const struct mdi_node *, int result);
void mdi_cache_invalidate(struct md_inode_store *);
void mdi_cache_snapshot(struct md_inode_store *, sqlite3_int64 version);
int mdi_landlock(struct md_inode_store *,const struct mdi_node *,const struct mdi_node *,uint64_t);
int mdi_landlock_object(struct md_inode_store *,const struct mdi_node *,uint64_t);
/* ENTRY retains the final directory entry (unlink/rename/create). NOFOLLOW
 * retains a final symlink except when a trailing slash requires traversal. */
enum mdi_follow { MDI_FOLLOW, MDI_NOFOLLOW, MDI_ENTRY };
int mdi_sql_error(int);
int mdi_sql_failure(int);
int mdi_sql(struct md_inode_store *, const char *);
/* Publication durability follows the destination lifetime. Transient mounts
 * retain transaction rollback, but have no power-loss persistence contract. */
int mdi_sync(struct md_inode_store *, int fd);
/* The caller holds the store gate, outside a SQLite transaction. */
int mdi_checkpoint(struct md_inode_store *);
enum { MDI_RESERVE_BATCH = 32 };
/* Claims one durable, previously unpublished physical file in this transaction.
 * No live backing is recycled. The caller still syncs its final attributes. */
int mdi_reserve_file(struct md_inode_store *, char id[33], int flags, mode_t mode);
int mdi_begin(struct md_inode_store *, int write);
/* Promote the sole read snapshot under its already-held exclusive store gate.
 * Never releases the gate, re-resolves the pathname, or replays an operation. */
int mdi_write(struct md_inode_store *);
int mdi_prepare(struct md_inode_store *, const char *, sqlite3_stmt **);
int mdi_query_acquire(struct md_inode_store *, enum mdi_query, sqlite3_stmt **);
int mdi_query_release(sqlite3_stmt *, int result);
int mdi_step(struct md_inode_store *, sqlite3_stmt *);
int mdi_bind_id(sqlite3_stmt *, int, const char *);
int mdi_bind_name(sqlite3_stmt *, int, const char *);
int mdi_finish(struct md_inode_store *, int);
int mdi_name_valid(const char *);
int mdi_node(struct md_inode_store *, const char *, struct mdi_node *);
int mdi_fd(struct md_inode_store *, int, struct mdi_node *);
int mdi_fd_membership(struct md_inode_store *, int, struct mdi_node *, int *attached);
int mdi_lookup(struct md_inode_store *, const char *parent, const char *, struct mdi_node *);
int mdi_catalogue_lookup(struct md_inode_store *, const char *parent, const char *, struct mdi_node *);
int mdi_stat(struct md_inode_store *, const struct mdi_node *, struct stat *);
int mdi_backing_stat(struct md_inode_store *, const struct mdi_node *, struct stat *);
int mdi_fstat(struct md_inode_store *, int, struct mdi_node *, struct stat *);
int mdi_access(struct md_inode_store *, const struct mdi_node *, int);
int mdi_permission(struct md_inode_store *, const struct mdi_node *, int, int real);
int mdi_permission_as(struct md_inode_store *, const struct mdi_node *, int, const struct md_identity *);
int mdi_open_permission(struct md_inode_store *, const struct mdi_node *, int flags);
int mdi_sticky(struct md_inode_store *, const struct mdi_location *);
int mdi_sticky_as(struct md_inode_store *, const struct mdi_location *, const struct md_identity *);
int mdi_metadata(struct md_inode_store *, const struct mdi_node *, uint32_t, uint32_t, mode_t);
int mdi_device_number(struct md_inode_store *, struct mdi_node *, dev_t);
int mdi_file_capability(struct md_inode_store *, const struct mdi_node *, const void *, size_t);
int mdi_acl_store(struct md_inode_store *, const struct mdi_node *, unsigned, const void *, size_t);
int mdi_acl_permission(struct md_inode_store *, const struct mdi_node *, const struct md_identity *, unsigned);
int mdi_acl_chmod(struct md_inode_store *, const struct mdi_node *, unsigned);
int mdi_acl_inherit(struct md_inode_store *, const struct mdi_node *, const struct mdi_node *, unsigned);
void md_inode_acl(struct md_inode_store *, const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
int mdi_attributes(struct md_inode_store *, const struct mdi_node *, void *, size_t);
int mdi_xattr_permission(struct md_inode_store *, const struct mdi_node *, const char *, int);
int mdi_xattr_permission_as(struct md_inode_store *, const struct mdi_node *, const char *, int, const struct md_identity *);
int mdi_setattr_permission(struct md_inode_store *, const struct mdi_node *, const struct md_fs_request *, const struct md_identity *);
void md_inode_xattr(struct md_inode_store *, const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
int mdi_walk(struct md_inode_store *, int, const char *, enum mdi_follow, int missing, struct mdi_location *);
int mdi_path_step(struct md_inode_store *, const struct mdi_node *, const char *,
        const char *tail, uint64_t resolve, struct mdi_node *);
int mdi_host_boundary(struct md_inode_store *, const char *parent, const char *name, const char *tail, uint64_t resolve);
int mdi_walk_resolved(struct md_inode_store *, int, const char *, enum mdi_follow, int missing,
        uint64_t resolve, struct mdi_location *);
int mdi_location_path(struct md_inode_store *, const struct mdi_location *, char *, size_t);
int mdi_node_path(struct md_inode_store *, const struct mdi_node *, char *, size_t);
int mdi_parent_writable(struct md_inode_store *, const struct mdi_node *);
int mdi_ancestor(struct md_inode_store *, const char *ancestor, const char *child);
int mdi_add_name(struct md_inode_store *, const char *parent, const char *name, const char *object);
int mdi_delete_name(struct md_inode_store *, const char *parent, const char *name);
int mdi_reparent(struct md_inode_store *, const struct mdi_node *, const char *parent);
int mdi_empty(struct md_inode_store *, const struct mdi_node *);
int mdi_allocate(struct md_inode_store *, mode_t kind, mode_t mode, int flags, const char *target,
        const char *parent, struct mdi_node *, int *fd);
int mdi_allocate_root(struct md_inode_store *, struct mdi_node *);
int mdi_commit(struct md_inode_store *, int);
int mdi_random_id(char [33]);
/* Called within the namespace write transaction, before exposing any writable
 * descriptor. Native data IO remains outside the namespace after this point. */
int mdi_copy_up(struct md_inode_store *, struct mdi_node *);
int mdi_copy_attributes(int source, int destination);
int mdi_copy_body(struct md_inode_store *, int source, int destination, const struct stat *);
int mdi_replace_attributes(int source, int destination);
int mdi_overlay_replace_attributes(int source, int destination);
int mdi_sources_open(struct md_inode_store *);
/* Caller owns exclusive maintenance or an unpublished store. No live lower
 * store or ordinary open description may depend on untracked physical bodies. */
int mdi_discard_untracked_backings(struct md_inode_store *);
int mdi_source_register(struct md_inode_store *, int objects, int *source);
int mdi_import_shared(struct md_inode_store *, int source, const char *backing, struct mdi_node *);
int mdi_backing_directory(struct md_inode_store *, const struct mdi_node *);
int mdi_backing_open(struct md_inode_store *, const struct mdi_node *, int flags);
int mdi_backing_path(struct md_inode_store *, const struct mdi_node *, char *, size_t);
int mdi_fifo_prepare(struct md_inode_store *, int, struct md_open_completion *);
int mdi_channel(struct md_inode_store *, const struct mdi_node *, char [33], int *source);
int mdi_channel_copy(struct md_inode_store *, const struct mdi_node *, struct md_inode_store *, const struct mdi_node *);
int mdi_fifo_descriptor(struct md_inode_store *, const struct stat *, struct mdi_node *);
void mdi_fifo_close(struct md_inode_store *);
int mdi_event(struct md_inode_store *, const char *parent, const struct mdi_node *,
        const char *name, unsigned mask, unsigned *cookie);
int mdi_removed_event(struct md_inode_store *, const struct mdi_location *, int parent_event);
int mdi_watch_marker(struct md_inode_store *,const char *);
int mdi_events_committed(struct md_inode_store *);
#endif
