#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_watch.h"
#include "inode_view.h"
#include "inode_overlay.h"
#include "storage_database.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <unistd.h>

int mdi_sql_error(int rc) {
    return md_database_result(rc);
}
int mdi_sql(struct md_inode_store *s, const char *text) {
    mdi_cache_invalidate(s);
    struct md_cost *cost = s->statistics ? &s->statistics->transaction : NULL;
    int64_t begin = md_cost_begin(cost);
    int result = md_database_error(s->db, sqlite3_exec(s->db, text, NULL, NULL, NULL));
    md_cost_end(cost, begin); return result;
}
int mdi_sql_failure(int rc) {
    int error = mdi_sql_error(rc);
    return error ? error : -EIO;
}
int mdi_prepare(struct md_inode_store *s, const char *text, sqlite3_stmt **out) {
    struct md_cost *cost = s->statistics ? &s->statistics->prepare : NULL;
    int64_t begin = md_cost_begin(cost);
    int result = md_database_error(s->db, sqlite3_prepare_v2(s->db, text, -1, out, NULL));
    md_cost_end(cost, begin); return result;
}
int mdi_step(struct md_inode_store *s, sqlite3_stmt *q) {
    struct md_cost *cost = s->statistics ? &s->statistics->step : NULL;
    uint64_t before=cost ? cost->nanoseconds : 0;
    int64_t begin = md_cost_begin(cost);
    int result = md_database_step(q);
    md_cost_end(cost, begin);
    if (s->statistics) {
        struct md_cost *kind=q==s->queries[MDI_DATA_VERSION] ? &s->statistics->version
            : q==s->queries[MDI_FD] ? &s->statistics->descriptor
            : q==s->queries[MDI_DIRECTORY_NAME] || q==s->queries[MDI_FILE_PATH] ? &s->statistics->path : NULL;
        if (kind) { ++kind->calls; kind->nanoseconds+=cost->nanoseconds-before; }
    }
    return result;
}
void md_inode_measure(struct md_inode_store *s, struct md_inode_statistics *statistics) {
    s->statistics = statistics;
}
int mdi_name_valid(const char *name) {
    if (!name) return -EFAULT;
    size_t n = strnlen(name, NAME_MAX+1);
    if (!n) return -ENOENT;
    if (n > NAME_MAX) return -ENAMETOOLONG;
    if (!strcmp(name, ".") || !strcmp(name, "..") || strchr(name, '/')) return -EINVAL;
    return 0;
}
int mdi_bind_name(sqlite3_stmt *q, int slot, const char *name) {
    return mdi_sql_error(sqlite3_bind_blob(q, slot, name, (int)strlen(name), SQLITE_TRANSIENT));
}
int mdi_bind_id(sqlite3_stmt *q, int slot, const char *id) {
    return mdi_sql_error(sqlite3_bind_text(q, slot, id, -1, SQLITE_TRANSIENT));
}
static int acquire_lock(struct md_inode_store *s) {
    if (s->locked) return -EDEADLK;
    if (flock(s->objects, LOCK_EX | LOCK_NB)) {
        if (errno != EWOULDBLOCK) return -errno;
#ifdef MD_INODE_TESTING
        if (s->observe) s->observe(MD_STORE_CONTENDED, s->context);
#endif
        /* EVENT_WAIT: another store operation releases its kernel lock (also on
         * owner death). Signal interruption fails before BEGIN, never replays IO.
         * Client RPC deadlines remain cancellation bounds on observation only. */
        if (flock(s->objects, LOCK_EX)) return -errno;
    }
    s->locked = 1;
    return 0;
}
static int store_lock(struct md_inode_store *s) {
    struct md_cost *cost = s->statistics ? &s->statistics->lock : NULL;
    int64_t begin = md_cost_begin(cost);
    int result = acquire_lock(s);
    md_cost_end(cost, begin); return result;
}
static int store_unlock(struct md_inode_store *s, int result) {
    if (s->locked) {
        if (flock(s->objects, LOCK_UN)) return result ? result : -errno;
        s->locked = 0;
    }
    return result;
}
static int transaction(struct md_inode_store *s, enum mdi_query slot) {
    struct md_cost *cost = s->statistics ? &s->statistics->transaction : NULL;
    int64_t begin = md_cost_begin(cost);
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, slot, &q);
    if (!r) { int rc = mdi_step(s, q); r = rc == SQLITE_DONE ? 0 : mdi_sql_failure(rc); }
    r = mdi_query_release(q, r);
    md_cost_end(cost, begin);
    return r;
}
static int watch_writes(struct md_inode_store *s) {
    if (!flock(s->watch_presence,LOCK_EX|LOCK_NB))
        return flock(s->watch_presence,LOCK_UN) ? -errno : 0;
    if (errno!=EWOULDBLOCK) return -errno;
    s->recording=1; return 0;
}
int mdi_write(struct md_inode_store *s) {
    if (mdi_readonly(s)) return -EROFS;
    if (s->write_transaction) return 0;
    if (!s->locked || s->read_depth!=1) return -EDEADLK;
    int r=watch_writes(s);
    if (!r) {
        s->write_transaction=1; s->read_depth=0;
        if (s->statistics) ++s->statistics->write_admissions;
    }
    return r;
}
int mdi_begin(struct md_inode_store *s, int write) {
    if (write && s->readonly) return -EROFS;
    if (s->read_depth) {
        if (write) return -EDEADLK;
        ++s->read_depth; return 0;
    }
    int r = store_lock(s);
    if (r) return r;
    s->recording = 0;
    s->write_transaction=!!write;
    s->cache_checked=0;
    if (write) r=watch_writes(s);
    if (!r) r=transaction(s,write ? MDI_BEGIN_WRITE : MDI_BEGIN);
    if (!r && write && s->statistics) ++s->statistics->write_admissions;
    if (!r) {
        sqlite3_stmt *query=NULL;
        r=mdi_query_acquire(s,MDI_DATA_VERSION,&query);
        if (!r) {
            int rc=mdi_step(s,query);
            if (rc!=SQLITE_ROW) r=mdi_sql_failure(rc);
        }
        sqlite3_int64 version=!r ? sqlite3_column_int64(query,0) : 0;
        if (!r) mdi_cache_snapshot(s,version);
        r=mdi_query_release(query,r);
        if (!r) r=mdi_super_refresh(s,version);
        if (!r && write && s->super_readonly) r=-EROFS;
        if (r) transaction(s,MDI_ROLLBACK);
        else if (!write) s->read_depth=1;
    }
    return r ? store_unlock(s, r) : 0;
}
int mdi_finish(struct md_inode_store *s, int result) {
    if (s->read_depth && --s->read_depth) return result;
    s->cache_checked=0;
    if (!result && s->write_transaction && s->overlay) result=mdi_overlay_flush(s);
    if (!result) result = transaction(s, MDI_COMMIT);
    if (result) transaction(s, MDI_ROLLBACK);
    s->write_transaction=0;
    return store_unlock(s, result);
}
#ifndef MD_INODE_TESTING
enum { MD_OBJECT_SYNCED, MD_NAMESPACE_STAGED, MD_NAMESPACE_COMMITTED };
#endif
static int checkpoint(struct md_inode_store *s, int point) {
#ifdef MD_INODE_TESTING
    if (s->observe) {
        /* Force a real rollback journal before the deterministic kill point. */
        if (point == MD_NAMESPACE_STAGED) {
            int r = mdi_sql_error(sqlite3_db_cacheflush(s->db));
            if (r) return r;
        }
        s->observe(point, s->context);
    }
#else
    (void)s; (void)point;
#endif
    return 0;
}
int mdi_commit(struct md_inode_store *s, int r) {
    if (!r) r = checkpoint(s, MD_NAMESPACE_STAGED);
    r = mdi_finish(s, r);
    if (!r) r = checkpoint(s, MD_NAMESPACE_COMMITTED);
    return r;
}
static int read_id(sqlite3_stmt *q, int column, char out[33]) {
    const char *value = (const char *)sqlite3_column_text(q, column);
    if (!value || sqlite3_column_bytes(q, column) != 32
            || strspn(value, "0123456789abcdef") != 32) return -EIO;
    memcpy(out, value, 33);
    return 0;
}
static int read_node(struct md_inode_store *s, sqlite3_stmt *q, struct mdi_node *node) {
    int rc = mdi_step(s, q);
    if (rc != SQLITE_ROW) return rc == SQLITE_DONE ? -ENOENT : mdi_sql_failure(rc);
    struct mdi_node value = {0};
    int r = read_id(q, 0, value.id);
    value.kind = (mode_t)sqlite3_column_int(q, 1);
    value.device = (dev_t)sqlite3_column_int64(q, 2);
    value.inode = (ino_t)sqlite3_column_int64(q, 3);
    if (!r && value.kind == S_IFDIR) r = read_id(q, 4, value.parent);
    if (!r) r = read_id(q, 7, value.backing);
    if (!r) r = read_id(q,16,value.scope);
    value.shared = sqlite3_column_int(q, 8);
    value.logical_inode = (ino_t)sqlite3_column_int64(q, 9);
    value.logical_device = (dev_t)sqlite3_column_int64(q, 11);
    value.source = sqlite3_column_int(q, 10);
    value.mode = sqlite3_column_int(q, 12);
    value.uid = (uint32_t)sqlite3_column_int64(q, 13);
    value.gid = (uint32_t)sqlite3_column_int64(q, 14);
    value.acl_mask = (unsigned)sqlite3_column_int(q, 15);
    value.rdev = (dev_t)sqlite3_column_int64(q, 17);
    if (value.source < 0 || value.source >= MDI_SOURCES) r = -EIO;
    if (!r && value.kind != S_IFDIR && value.kind != S_IFREG && value.kind != S_IFLNK
            && value.kind != S_IFSOCK && value.kind != S_IFIFO
            && value.kind != S_IFCHR && value.kind != S_IFBLK) r = -EIO;
    sqlite3_int64 names = sqlite3_column_int64(q, 5), children = sqlite3_column_int64(q, 6);
    if (names < 0 || children < 0 || children > INT64_MAX - 2) r = -EIO;
    value.attached = names != 0 || (value.kind==S_IFDIR && !strcmp(value.id,value.parent));
    value.links = value.kind == S_IFDIR ? (value.attached ? (nlink_t)children + 2 : 0) : (nlink_t)names;
    if (!r) *node = value;
    return r;
}
int mdi_query_acquire(struct md_inode_store *s, enum mdi_query slot, sqlite3_stmt **out) {
    /* Namespace and virtual ownership share one transaction snapshot. Sizes
     * and data timestamps remain properties of the native open description. */
#define NODE_COLUMNS "o.object,o.kind,o.device,o.inode,o.parent,o.name_count,o.directory_count,o.backing,o.shared,o.logical_inode,o.source,o.logical_device,o.mode,o.uid,o.gid,o.acl_mask,o.scope,o.rdev"
    static const char *const sql[MDI_QUERY_COUNT] = {
        [MDI_NODE] = "SELECT " NODE_COLUMNS " FROM objects o WHERE o.object=?1",
        [MDI_FD] = "SELECT " NODE_COLUMNS " FROM objects o JOIN backings b ON b.object=o.object "
            "WHERE b.device=?1 AND b.inode=?2 AND b.scope=?3",
        [MDI_LOOKUP] = "SELECT " NODE_COLUMNS " FROM objects o "
            "JOIN names n ON n.object=o.object WHERE n.parent=?1 AND n.name=?2",
        [MDI_DIRECTORY_NAME] = "SELECT name FROM names WHERE parent=?1 AND object=?2",
        [MDI_READDIR] = ("SELECT n.cookie,n.name,o.logical_inode,o.kind FROM names n JOIN objects o ON o.object=n.object "
            "WHERE n.parent=?1 AND n.cookie>?2 ORDER BY n.cookie"),
        [MDI_BEGIN] = "BEGIN", [MDI_BEGIN_WRITE] = "BEGIN IMMEDIATE",
        [MDI_COMMIT] = "COMMIT", [MDI_ROLLBACK] = "ROLLBACK",
        [MDI_EVENT] = "INSERT INTO events(parent,object,name,mask,cookie) VALUES(?1,?2,?3,?4,?5)",
        [MDI_EVENT_TRIM] = "DELETE FROM events WHERE sequence<=?1-65536",
        [MDI_EVENT_END] = "SELECT coalesce(max(sequence),0) FROM events",
        [MDI_EVENT_SCAN] = "SELECT sequence,parent,object,name,mask,cookie FROM events WHERE sequence>?1 ORDER BY sequence",
        [MDI_EVENT_NAMES] = "SELECT n.parent,n.name FROM names n JOIN backings b ON b.object=n.object WHERE b.backing=?1 AND b.source=?2 AND b.scope=?3",
        [MDI_BACKING_OBJECT] = "SELECT object FROM backings WHERE backing=?1 AND source=?2 AND scope=?3",
        [MDI_FILE_PATH] = "SELECT parent,name,ambiguous FROM file_paths WHERE object=?1",
        [MDI_ACL] = "SELECT value FROM inode_acls WHERE object=?1 AND type=?2",
        [MDI_OVERLAY_LINK] = "SELECT upper,lower FROM overlay_links WHERE object=?1",
        [MDI_DATA_VERSION] = "PRAGMA main.data_version",
        [MDI_ADD_NAME] = "INSERT INTO names(parent,name,object) VALUES(?1,?2,?3)",
        [MDI_DELETE_NAME] = "DELETE FROM names WHERE parent=?1 AND name=?2",
        [MDI_REPARENT] = "UPDATE objects SET parent=?1 WHERE object=?2",
        [MDI_EMPTY] = "SELECT NOT EXISTS(SELECT 1 FROM names WHERE parent=?1)",
        [MDI_CREATE_OBJECT] = "INSERT INTO objects(object,kind,device,inode,parent,backing,logical_inode,logical_device,mode,uid,gid,scope) "
            "VALUES(?1,?2,?3,?4,?5,?1,?4,?3,?6,?7,?8,?9)",
        [MDI_METADATA] = "UPDATE objects SET uid=?1,gid=?2,mode=?3 WHERE object=?4 "
            "AND (uid!=?1 OR gid!=?2 OR mode!=?3)"
    };
#undef NODE_COLUMNS
    int result = 0;
    if (!s->queries[slot]) result = mdi_prepare(s, sql[slot], &s->queries[slot]);
    else if (s->statistics) s->statistics->query_reuses++;
    if (!result && (slot==MDI_FD || slot==MDI_EVENT_NAMES || slot==MDI_BACKING_OBJECT))
        result=mdi_sql_error(sqlite3_bind_text(s->queries[slot],3,s->lifetime->scope,32,SQLITE_STATIC));
    if (!result) *out = s->queries[slot];
    return result;
}
int mdi_query_release(sqlite3_stmt *q, int result) {
    if (!q) return result;
    /* Statement reuse never retains bindings or a read snapshot. */
    int reset = mdi_sql_error(sqlite3_reset(q));
    int clear = mdi_sql_error(sqlite3_clear_bindings(q));
    return result ? result : reset ? reset : clear;
}
int mdi_node(struct md_inode_store *s, const char *id, struct mdi_node *node) {
    /* Callers may select node->parent into that same node. Keep the lookup
     * key independent of the output overwritten by read_node/cache delivery. */
    char selected[33];
    int cacheable=strnlen(id,sizeof(selected))<sizeof(selected);
    if (cacheable) strcpy(selected,id);
    const struct mdi_cache_key key={.query=MDI_NODE,.id=selected};
    int cached;
    if (cacheable && mdi_cache_get(s,&key,node,&cached)) return cached;
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_NODE, &q);
    if (!r) r = mdi_bind_id(q, 1, id);
    if (!r) r = read_node(s, q, node);
    r=mdi_query_release(q,r);
    if (cacheable) mdi_cache_put(s,&key,node,r);
    return r;
}
static int descriptor_node(struct md_inode_store *s, const struct stat *st,
        struct mdi_node *node) {
    if (S_ISFIFO(st->st_mode)) return mdi_fifo_descriptor(s, st, node);
    const struct mdi_cache_key key={.query=MDI_FD,.device=st->st_dev,.inode=st->st_ino};
    int cached;
    if (mdi_cache_get(s,&key,node,&cached)) return cached==-ENOENT ? -EXDEV : cached;
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_FD, &q);
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 1, (sqlite3_int64)st->st_dev));
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 2, (sqlite3_int64)st->st_ino));
    if (!r) r = read_node(s, q, node);
    r=mdi_query_release(q,r); mdi_cache_put(s,&key,node,r);
    return r==-ENOENT ? -EXDEV : r;
}
int mdi_fd(struct md_inode_store *s, int fd, struct mdi_node *node) {
    struct stat st;
    return fstat(fd, &st) ? -errno : descriptor_node(s, &st, node);
}
int mdi_lookup(struct md_inode_store *s, const char *parent, const char *name, struct mdi_node *node) {
    char selected[33];
    int cacheable=strnlen(parent,sizeof(selected))<sizeof(selected);
    if (cacheable) strcpy(selected,parent);
    const struct mdi_cache_key key={.query=MDI_LOOKUP,.id=selected,.name=name};
    int cached;
    if (cacheable && mdi_cache_get(s,&key,node,&cached)) return cached;
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_LOOKUP, &q);
    if (!r) r = mdi_bind_id(q, 1, parent);
    if (!r) r = mdi_bind_name(q, 2, name);
    if (!r) r = read_node(s, q, node);
    r=mdi_query_release(q,r);
    if (cacheable) mdi_cache_put(s,&key,node,r);
    return r;
}
int mdi_add_name(struct md_inode_store *s, const char *parent, const char *name, const char *object) {
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_ADD_NAME, &q);
    if (!r) r = mdi_bind_id(q, 1, parent);
    if (!r) r = mdi_bind_name(q, 2, name);
    if (!r) r = mdi_bind_id(q, 3, object);
    if (!r) r = mdi_sql_error(mdi_step(s, q));
    return mdi_query_release(q,r);
}
int mdi_delete_name(struct md_inode_store *s, const char *parent, const char *name) {
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_DELETE_NAME, &q);
    if (!r) r = mdi_bind_id(q, 1, parent);
    if (!r) r = mdi_bind_name(q, 2, name);
    if (!r) r = mdi_sql_error(mdi_step(s, q));
    if (!r && !sqlite3_changes(s->db)) r = -ENOENT;
    return mdi_query_release(q,r);
}
int mdi_reparent(struct md_inode_store *s, const struct mdi_node *node, const char *parent) {
    if (node->kind != S_IFDIR) return 0;
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_REPARENT, &q);
    if (!r) r = mdi_bind_id(q, 1, parent);
    if (!r) r = mdi_bind_id(q, 2, node->id);
    if (!r) r = mdi_sql_error(mdi_step(s, q));
    return mdi_query_release(q,r);
}
int mdi_empty(struct md_inode_store *s, const struct mdi_node *node) {
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_EMPTY, &q);
    if (!r) r = mdi_bind_id(q, 1, node->id);
    if (!r) {
        int rc = mdi_step(s, q);
        r = rc == SQLITE_ROW ? sqlite3_column_int(q, 0) : mdi_sql_failure(rc);
    }
    return mdi_query_release(q,r);
}
static int backing_identity(const struct mdi_node *node, struct stat *st) {
    mode_t backing = node->kind == S_IFSOCK || node->kind == S_IFIFO
        || node->kind == S_IFCHR || node->kind == S_IFBLK ? S_IFREG : node->kind;
    if (st->st_dev != node->device || st->st_ino != node->inode || (st->st_mode & S_IFMT) != backing) return -EIO;
    st->st_mode = (st->st_mode & ~S_IFMT) | node->kind;
    if (node->kind == S_IFIFO || node->kind == S_IFCHR || node->kind == S_IFBLK)
        st->st_size = st->st_blocks = 0;
    st->st_rdev = node->rdev;
    return 0;
}
int mdi_backing_stat(struct md_inode_store *s, const struct mdi_node *node, struct stat *st) {
    int directory = mdi_backing_directory(s, node);
    return directory < 0 ? directory : fstatat(directory, node->backing, st, AT_SYMLINK_NOFOLLOW) ? -errno : backing_identity(node, st);
}
int mdi_fd_membership(struct md_inode_store *s, int fd, struct mdi_node *node, int *attached) {
    struct stat st;
    if (fstat(fd, &st)) return -errno;
    if (s->statistics) s->statistics->membership_queries++;
    int r = descriptor_node(s, &st, node);
    if (!r && (st.st_mode & S_IFMT) != (node->kind == S_IFSOCK ? S_IFREG : node->kind)
            && !((node->kind == S_IFIFO || node->kind == S_IFCHR || node->kind == S_IFBLK)
                && S_ISREG(st.st_mode))) r = -EIO;
    if (!r) *attached = node->attached;
    return r;
}
int mdi_fstat(struct md_inode_store *s, int fd, struct mdi_node *node, struct stat *st) {
    if (fstat(fd, st)) return -errno;
    if (s->statistics) s->statistics->link_count_queries++;
    int r = descriptor_node(s, st, node);
    if (!r && (st->st_mode & S_IFMT) != (node->kind == S_IFSOCK ? S_IFREG : node->kind)
            && !((node->kind == S_IFIFO || node->kind == S_IFCHR || node->kind == S_IFBLK)
                && S_ISREG(st->st_mode))) r = -EIO;
    if (!r) {
        st->st_mode = (st->st_mode & ~S_IFMT) | node->kind;
        if (node->kind == S_IFIFO || node->kind == S_IFCHR || node->kind == S_IFBLK)
            st->st_size = st->st_blocks = 0;
        st->st_rdev = node->rdev;
        if (node->mode >= 0) { st->st_mode = node->kind | node->mode; st->st_uid = node->uid; st->st_gid = node->gid; }
        st->st_nlink = node->links; st->st_ino = node->logical_inode; st->st_dev = node->logical_device;
    }
    return r;
}
int mdi_stat(struct md_inode_store *s, const struct mdi_node *node, struct stat *st) {
    int r = mdi_backing_stat(s, node, st);
    if (!r) {
        st->st_nlink = node->links; st->st_ino = node->logical_inode; st->st_dev = node->logical_device;
        if (node->mode >= 0) { st->st_mode = node->kind | node->mode; st->st_uid = node->uid; st->st_gid = node->gid; }
    }
    return r;
}
int mdi_access(struct md_inode_store *s, const struct mdi_node *node, int mode) {
    if (node->kind != S_IFDIR) return -ENOTDIR;
    return mdi_permission(s, node, mode, 0);
}
int mdi_parent_writable(struct md_inode_store *s, const struct mdi_node *node) {
    int r = mdi_access(s, node, W_OK | X_OK);
    struct stat st;
    if (!r) r = mdi_backing_stat(s, node, &st);
    if (!r && !node->attached) r = -ENOENT;
    return r;
}
static int make_object(struct md_inode_store *s, const char *id, mode_t kind, mode_t mode, int flags,
        const char *target, const char *parent, struct mdi_node *node, int *fd) {
    uint32_t uid = s->identity ? s->identity->uid.fs : (uint32_t)geteuid();
    uint32_t gid = s->identity ? s->identity->gid.fs : (uint32_t)getegid();
    struct mdi_node p={0};
    unsigned requested=mode;
    if (s->identity && parent && strcmp(parent, id)) {
        struct stat st;
        int r = mdi_node(s, parent, &p);
        if (!r) r = mdi_stat(s, &p, &st);
        if (r) return r;
        if (st.st_mode & S_ISGID) { gid = st.st_gid; if (kind == S_IFDIR) mode |= S_ISGID; }
        if (kind != S_IFDIR && (mode & S_ISGID) && !md_identity_file_capable(s->identity,st.st_uid,st.st_gid,CAP_FSETID)
                && !md_identity_in_group(s->identity, gid)) mode &= ~S_ISGID;
    }
    if (kind!=S_IFLNK && !(p.acl_mask&MD_ACL_DEFAULT)) mode&=~s->creation_mask;
    mode_t native = s->identity ? (kind == S_IFDIR ? 0700 : 0600 | ((mode & 0111) ? 0100 : 0)) : mode;
    *fd = -1;
    if (kind == S_IFIFO || kind == S_IFCHR || kind == S_IFBLK) native = 0600;
    if (kind == S_IFREG || kind == S_IFSOCK || kind == S_IFIFO || kind == S_IFCHR || kind == S_IFBLK) {
        *fd = openat(s->objects, id, O_CREAT | O_EXCL | flags | O_CLOEXEC | O_NOFOLLOW, native);
        if (*fd < 0) return -errno;
    } else if (kind == S_IFDIR) {
        if (mkdirat(s->objects, id, native)) return -errno;
    } else if (symlinkat(target, s->objects, id)) return -errno;
    struct stat st;
    int r = fstatat(s->objects, id, &st, AT_SYMLINK_NOFOLLOW) ? -errno : 0;
    if (!r && *fd >= 0) r = mdi_sync(s,*fd);
    if (!r) r = mdi_sync(s,s->objects);
    if (!r) r = checkpoint(s, MD_OBJECT_SYNCED);
    sqlite3_stmt *q = NULL;
    if (!r) r = mdi_query_acquire(s, MDI_CREATE_OBJECT, &q);
    if (!r) r = mdi_bind_id(q, 1, id);
    if (!r) r = mdi_sql_error(sqlite3_bind_int(q, 2, (int)kind));
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 3, (sqlite3_int64)st.st_dev));
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 4, (sqlite3_int64)st.st_ino));
    if (!r) r = kind == S_IFDIR && parent ? mdi_bind_id(q, 5, parent) : mdi_sql_error(sqlite3_bind_null(q, 5));
    if (!r) r = mdi_sql_error(sqlite3_bind_int(q, 6, s->identity || kind == S_IFIFO
        || kind == S_IFCHR || kind == S_IFBLK ? (int)(mode & 07777) : -1));
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 7, uid));
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 8, gid));
    if (!r) r = mdi_bind_id(q,9,s->lifetime->scope);
    if (!r) r = mdi_sql_error(mdi_step(s, q));
    r = mdi_query_release(q,r);
    if (!r) r = mdi_node(s, id, node);
    if (!r && (p.acl_mask&MD_ACL_DEFAULT) && kind!=S_IFLNK) {
        r=mdi_acl_inherit(s,&p,node,(mode&07000)|(requested&0777));
        if (!r) r=mdi_node(s,id,node);
    }
    return r;
}
int mdi_random_id(char id[33]) {
    unsigned char random[16];
    long n = syscall(SYS_getrandom, random, sizeof(random), 0);
    if (n != sizeof(random)) return n < 0 ? -errno : -EIO;
    for (size_t i = 0; i < sizeof(random); ++i) {
        id[2*i] = "0123456789abcdef"[random[i] >> 4];
        id[2*i+1] = "0123456789abcdef"[random[i] & 15];
    }
    id[32] = 0;
    if (!strcmp(id, MDI_ROOT)) return -EEXIST;
    return 0;
}
int mdi_allocate(struct md_inode_store *s, mode_t kind, mode_t mode, int flags, const char *target,
        const char *parent, struct mdi_node *node, int *fd) {
    char id[33];
    int r = mdi_random_id(id);
    return r ? r : make_object(s, id, kind, mode, flags, target, parent, node, fd);
}
int mdi_allocate_root(struct md_inode_store *s, struct mdi_node *node) {
    int fd;
    return make_object(s,s->lifetime->scope,S_IFDIR,0700,0,NULL,s->lifetime->scope,node,&fd);
}
static int prepare_lookup_indexes(struct md_inode_store *s) {
    /* Foreign-key checks run per removed parent. All child lookups must be
     * indexed; otherwise collecting a view repeatedly scans the whole store.
     * This is cold admission work, not part of retained worker reconnects. */
    int r=mdi_sql(s,"BEGIN IMMEDIATE;"
        "CREATE INDEX IF NOT EXISTS objects_parent ON objects(parent);"
        "CREATE INDEX IF NOT EXISTS backings_object ON backings(object);"
        "CREATE INDEX IF NOT EXISTS inode_views_upper ON inode_views(upper);"
        "CREATE INDEX IF NOT EXISTS inode_views_work ON inode_views(work);"
        "CREATE INDEX IF NOT EXISTS overlay_origins_object ON overlay_origins(object);"
        "CREATE INDEX IF NOT EXISTS overlay_links_upper ON overlay_links(upper);"
        "CREATE INDEX IF NOT EXISTS file_paths_parent ON file_paths(parent);"
        "COMMIT;");
    if (r) mdi_sql(s,"ROLLBACK");
    return r;
}
int mdi_sync(struct md_inode_store *s, int fd) {
    return s->lifetime->temporary || !fsync(fd) ? 0 : -errno;
}
static int journal_mode(struct md_inode_store *s, const char *sql, const char *expected) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,sql,&q);
    if (!r) {
        int rc=mdi_step(s,q);
        if (rc!=SQLITE_ROW) r=mdi_sql_failure(rc);
        else {
            const char *mode=(const char *)sqlite3_column_text(q,0);
            if (!mode || strcmp(mode,expected)) r=-ENOTSUP;
        }
    }
    sqlite3_finalize(q); return r;
}
static int store_open(const char *directory, int create, int exclusive,
        struct md_inode_lifetime *retained, struct md_inode_store **out) {
    if (!out) return -EFAULT;
    *out = NULL;
    if (!retained && (!directory || directory[0] != '/')) return -EINVAL;
    if (create && !retained && mkdir(directory, 0700)) return -errno;
    int root = retained ? fcntl(retained->root,F_DUPFD_CLOEXEC,3)
        : open(directory, O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) return -errno;
    /* Lifetime admission is independent of the short objects-directory transaction lock. */
    if (!retained && flock(root, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB)) {
        int error = errno == EWOULDBLOCK ? -EBUSY : -errno;
        close(root); return error;
    }
    struct stat named, opened;
    if (fstat(root, &opened) || (!retained && (lstat(directory, &named)
            || !opened.st_nlink || named.st_dev != opened.st_dev || named.st_ino != opened.st_ino))) {
        close(root); return -ESTALE;
    }
    int r = create && mkdirat(root, "objects", 0700) ? -errno : 0;
    struct md_inode_store *s = calloc(1, sizeof(*s));
    if (!s) { close(root); return -ENOMEM; }
    s->lifetime = retained ? md_inode_lifetime_retain(retained) : mdi_lifetime_new(root, &opened);
    if (!s->lifetime) { close(root); free(s); return -ENOMEM; }
    if (retained) { close(root); root=retained->root; }
    s->objects = s->watch_presence = -1;
    if (!r && (s->objects = openat(root, "objects", O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0) r = -errno;
    if (!r) r = store_lock(s);
    if (!r) r = md_database_open(root,"namespace.db",create,&s->db);
    if (!r) r = mdi_sql_error(sqlite3_extended_result_codes(s->db, 1));
    /* Every store retains rollback and interprocess isolation. Only persistent
     * lifetimes require power-loss durability, including retained reconnects. */
    if (!r) r = journal_mode(s,"PRAGMA journal_mode","delete");
    if (!r) r = journal_mode(s,"PRAGMA journal_mode=PERSIST","persist");
    if (!r) r = mdi_sql(s, "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF");
    if (!r) r = mdi_sql(s,s->lifetime->temporary ? "PRAGMA synchronous=OFF" : "PRAGMA synchronous=EXTRA");
    if (!r) r = mdi_sql(s,"PRAGMA journal_size_limit=1048576");
    if (!r && create) {
        r = mdi_sql(s, "BEGIN IMMEDIATE;"
            "CREATE TABLE objects(object TEXT PRIMARY KEY CHECK(length(object)=32),kind INTEGER NOT NULL,"
                "device INTEGER NOT NULL,inode INTEGER NOT NULL,parent TEXT REFERENCES objects,"
                "name_count INTEGER NOT NULL DEFAULT 0 CHECK(name_count>=0),"
                "directory_count INTEGER NOT NULL DEFAULT 0 CHECK(directory_count>=0),"
                "backing TEXT NOT NULL CHECK(length(backing)=32),shared INTEGER NOT NULL DEFAULT 0 CHECK(shared IN (0,1)),"
                "logical_inode INTEGER NOT NULL,logical_device INTEGER NOT NULL,"
                "source INTEGER NOT NULL DEFAULT 0 CHECK(source>=0 AND source<256),"
                "mode INTEGER NOT NULL DEFAULT -1 CHECK(mode>=-1 AND mode<=4095),"
                "uid INTEGER NOT NULL DEFAULT 0 CHECK(uid>=0 AND uid<4294967295),"
                "gid INTEGER NOT NULL DEFAULT 0 CHECK(gid>=0 AND gid<4294967295),"
                "acl_mask INTEGER NOT NULL DEFAULT 0 CHECK(acl_mask>=0 AND acl_mask<=3),"
                "scope TEXT NOT NULL CHECK(length(scope)=32),"
                "rdev INTEGER NOT NULL DEFAULT 0 CHECK(rdev>=0),"
                "UNIQUE(scope,device,inode),CHECK(kind IN (32768,16384,40960,49152,4096,8192,24576)),"
                "CHECK((kind=16384)=(parent IS NOT NULL))) STRICT;"
            "CREATE TABLE sources(id INTEGER NOT NULL,path TEXT NOT NULL,device INTEGER NOT NULL,inode INTEGER NOT NULL,"
                "scope TEXT NOT NULL CHECK(length(scope)=32),PRIMARY KEY(scope,id),"
                "UNIQUE(scope,device,inode),CHECK(id>0 AND id<256)) STRICT;"
            "CREATE TABLE backings(backing TEXT NOT NULL,object TEXT NOT NULL REFERENCES objects,"
                "device INTEGER NOT NULL,inode INTEGER NOT NULL,source INTEGER NOT NULL,"
                "scope TEXT NOT NULL CHECK(length(scope)=32),"
                "UNIQUE(scope,device,inode),PRIMARY KEY(scope,backing,source)) STRICT;"
            "CREATE TRIGGER objects_added AFTER INSERT ON objects BEGIN "
                "INSERT INTO backings VALUES(NEW.backing,NEW.object,NEW.device,NEW.inode,NEW.source,NEW.scope); END;"
            "CREATE TRIGGER objects_copied AFTER UPDATE OF backing ON objects WHEN NEW.backing!=OLD.backing BEGIN "
                "INSERT INTO backings VALUES(NEW.backing,NEW.object,NEW.device,NEW.inode,NEW.source,NEW.scope); END;"
            "CREATE TABLE inode_views(scope TEXT PRIMARY KEY REFERENCES objects,kind INTEGER NOT NULL,"
                "upper TEXT REFERENCES objects,work TEXT REFERENCES objects,"
                "writable INTEGER NOT NULL DEFAULT 0 CHECK(writable IN (0,1)),"
                "user_xattr INTEGER NOT NULL DEFAULT 0 CHECK(user_xattr IN (0,1)),"
                "CHECK(length(scope)=32)) STRICT;"
            "CREATE TABLE overlay_origins(scope TEXT NOT NULL,device INTEGER NOT NULL,inode INTEGER NOT NULL,"
                "origin TEXT NOT NULL,object TEXT NOT NULL REFERENCES objects ON DELETE CASCADE,"
                "PRIMARY KEY(scope,device,inode,origin)) WITHOUT ROWID;"
            "CREATE TABLE overlay_links(object TEXT PRIMARY KEY REFERENCES objects ON DELETE CASCADE,"
                "upper TEXT REFERENCES objects,lower INTEGER NOT NULL CHECK(lower IN (0,1))) STRICT;"
            "CREATE TABLE overlay_lower_names(parent TEXT NOT NULL REFERENCES objects ON DELETE CASCADE,"
                "name BLOB NOT NULL,PRIMARY KEY(parent,name)) WITHOUT ROWID;"
            "CREATE TABLE overlay_attributes(object TEXT NOT NULL REFERENCES objects ON DELETE CASCADE,"
                "name INTEGER NOT NULL CHECK(name BETWEEN 1 AND 4),value BLOB CHECK(length(value)<=65536),"
                "PRIMARY KEY(object,name)) STRICT;"
            "CREATE TABLE properties(key TEXT PRIMARY KEY,value INTEGER NOT NULL) STRICT;"
            "INSERT INTO properties VALUES('sealed',0);"
            "CREATE TABLE names(cookie INTEGER PRIMARY KEY AUTOINCREMENT,"
                "parent TEXT NOT NULL REFERENCES objects,name BLOB NOT NULL,"
                "object TEXT NOT NULL REFERENCES objects,UNIQUE(parent,name),"
                "CHECK(cookie>0 AND cookie<9223372036854775805)) STRICT;"
            "CREATE INDEX names_object ON names(object);"
            "CREATE INDEX names_cursor ON names(parent,cookie);"
            "CREATE TABLE file_paths(object TEXT PRIMARY KEY REFERENCES objects,"
                "parent TEXT NOT NULL REFERENCES objects,name BLOB NOT NULL,"
                "ambiguous INTEGER NOT NULL CHECK(ambiguous IN (0,1))) STRICT;"
            "CREATE TRIGGER names_added AFTER INSERT ON names BEGIN "
                "UPDATE objects SET name_count=name_count+1 WHERE object=NEW.object;"
                "INSERT INTO file_paths SELECT NEW.object,NEW.parent,NEW.name,name_count>1 "
                    "FROM objects WHERE object=NEW.object AND kind!=16384 "
                    "ON CONFLICT(object) DO UPDATE SET parent=excluded.parent,name=excluded.name,"
                    "ambiguous=max(file_paths.ambiguous,excluded.ambiguous);"
                "UPDATE objects SET directory_count=directory_count+1 WHERE object=NEW.parent "
                    "AND (SELECT kind FROM objects WHERE object=NEW.object)=16384; END;"
            "CREATE TRIGGER names_removed AFTER DELETE ON names BEGIN "
                "UPDATE objects SET name_count=name_count-1 WHERE object=OLD.object;"
                "UPDATE objects SET directory_count=directory_count-1 WHERE object=OLD.parent "
                    "AND (SELECT kind FROM objects WHERE object=OLD.object)=16384; END;"
            "CREATE TRIGGER names_immutable BEFORE UPDATE ON names BEGIN "
                "SELECT RAISE(ABORT,'replace namespace entries with delete and insert'); END;"
            "CREATE TABLE sockets(object TEXT PRIMARY KEY REFERENCES objects, address TEXT NOT NULL) STRICT;"
            "CREATE TABLE inode_channels(object TEXT PRIMARY KEY REFERENCES objects ON DELETE CASCADE,"
                "scope TEXT NOT NULL CHECK(length(scope)=32),channel TEXT NOT NULL CHECK(length(channel)=32),"
                "source INTEGER NOT NULL DEFAULT 0 CHECK(source>=0 AND source<256),UNIQUE(scope,channel)) STRICT;"
            "CREATE TRIGGER channel_added AFTER INSERT ON objects WHEN NEW.kind IN (4096,49152) BEGIN "
                "INSERT INTO inode_channels(object,scope,channel) VALUES(NEW.object,NEW.scope,NEW.object); END;"
            "CREATE TABLE fifo_pins(channel TEXT NOT NULL CHECK(length(channel)=32),owner TEXT NOT NULL CHECK(length(owner)=32),"
                "pid INTEGER NOT NULL,descriptor INTEGER NOT NULL,device INTEGER NOT NULL,inode INTEGER NOT NULL,"
                "PRIMARY KEY(channel,owner)) STRICT;"
            "CREATE INDEX fifo_identity ON fifo_pins(device,inode);"
            "CREATE TABLE file_capabilities(object TEXT PRIMARY KEY REFERENCES objects, value BLOB NOT NULL "
                "CHECK(length(value) IN (12,20,24))) STRICT;"
            "CREATE TABLE inode_acls(object TEXT NOT NULL REFERENCES objects,type INTEGER NOT NULL CHECK(type IN (1,2)),"
                "value BLOB NOT NULL CHECK(length(value)>=28 AND length(value)<=65532),PRIMARY KEY(object,type)) STRICT;"
            "CREATE TRIGGER acl_added AFTER INSERT ON inode_acls BEGIN "
                "UPDATE objects SET acl_mask=acl_mask|NEW.type WHERE object=NEW.object; END;"
            "CREATE TRIGGER acl_removed AFTER DELETE ON inode_acls BEGIN "
                "UPDATE objects SET acl_mask=acl_mask&~OLD.type WHERE object=OLD.object; END;"
            "CREATE TABLE events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, parent TEXT NOT NULL,"
                "object TEXT NOT NULL,name BLOB NOT NULL,mask INTEGER NOT NULL,cookie INTEGER NOT NULL) STRICT;"
            "PRAGMA user_version=14;");
        struct mdi_node node; int fd;
        if (!r) r = make_object(s, MDI_ROOT, S_IFDIR, 0700, 0, NULL, MDI_ROOT, &node, &fd);
        if (!r) r = mdi_sql(s,"INSERT INTO inode_views(scope,kind) VALUES('" MDI_ROOT "',0)");
        if (!r) r = mdi_sql(s, "COMMIT");
        if (r) mdi_sql(s, "ROLLBACK");
    }
    sqlite3_stmt *q = NULL;
    if (!r) r = mdi_prepare(s, "PRAGMA user_version", &q);
    if (!r) {
        int rc = mdi_step(s, q);
        if (rc != SQLITE_ROW) r = mdi_sql_failure(rc);
        else if (sqlite3_column_int(q, 0) != 14) r = -EPROTONOSUPPORT;
    }
    sqlite3_finalize(q); q = NULL;
    if (!r && (!retained || create)) r=prepare_lookup_indexes(s);
    if (!r) r = mdi_prepare(s, "SELECT value FROM properties WHERE key='sealed'", &q);
    if (!r) {
        int rc = mdi_step(s, q);
        if (rc != SQLITE_ROW) r = mdi_sql_failure(rc);
        else s->readonly = sqlite3_column_int(q, 0) != 0;
    }
    sqlite3_finalize(q);
    if (!r && (s->watch_presence = openat(root, "watch.lock",
            O_RDWR | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT | O_EXCL : 0), 0600)) < 0) r = -errno;
    if (!r && create) r = mdi_sync(s,root);
    if (!r) r = mdi_sources_open(s);
    if (!r) r = md_inode_view_validate(s);
    if (!r) r = mdi_overlay_writer_open(s);
    r = store_unlock(s, r);
    if (!r && exclusive) r=mdi_views_maintain(s);
    if (r) md_inode_store_close(s); else *out = s;
    return r;
}
int md_inode_store_open(const char *directory, int create, struct md_inode_store **out) {
    return store_open(directory, create, 0, NULL, out);
}
int md_inode_store_open_exclusive(const char *directory, struct md_inode_store **out) {
    return store_open(directory, 0, 1, NULL, out);
}
int md_inode_store_reconnect(struct md_inode_lifetime *owner, struct md_inode_store **out) {
    if (!owner) return -EINVAL;
    return store_open(NULL,0,0,owner,out);
}
int md_inode_store_initialize(struct md_inode_lifetime *owner, struct md_inode_store **out) {
    if (!owner) return -EINVAL;
    return store_open(NULL,1,0,owner,out);
}
void md_inode_store_close(struct md_inode_store *s) {
    if (!s) return;
    mdi_overlay_writer_close(s);
    md_inode_watch_close(s);
    mdi_fifo_close(s);
    for (unsigned i = 0; i < MDI_QUERY_COUNT; i++) sqlite3_finalize(s->queries[i]);
    if (s->db) sqlite3_close(s->db);
    if (s->objects >= 0) close(s->objects);
    if (s->watch_presence >= 0) close(s->watch_presence);
    md_inode_lifetime_release(s->lifetime);
    free(s->read_cache); free(s);
}
#ifdef MD_INODE_TESTING
void md_inode_observe(struct md_inode_store *s, void (*observer)(enum md_inode_checkpoint, void *), void *context) {
    s->observe = observer; s->context = context;
}
int md_inode_audit(struct md_inode_store *s, struct md_inode_audit *audit) {
    memset(audit, 0, sizeof(*audit));
    int r = mdi_begin(s, 0);
    if (r) return r;
    sqlite3_stmt *q = NULL;
    r = mdi_prepare(s, "PRAGMA integrity_check", &q);
    if (!r && (mdi_step(s, q) != SQLITE_ROW || strcmp((const char *)sqlite3_column_text(q, 0), "ok"))) r = -EIO;
    sqlite3_finalize(q); q = NULL;
    if (!r) r = mdi_prepare(s, "PRAGMA foreign_key_check", &q);
    if (!r && mdi_step(s, q) != SQLITE_DONE) r = -EIO;
    sqlite3_finalize(q); q = NULL;
    if (!r) r = mdi_prepare(s, "SELECT 1 FROM objects o WHERE "
        "name_count!=(SELECT count(*) FROM names WHERE object=o.object) OR "
        "acl_mask!=(SELECT coalesce(sum(type),0) FROM inode_acls WHERE object=o.object) OR "
        "directory_count!=(SELECT count(*) FROM names n JOIN objects c ON c.object=n.object "
            "WHERE n.parent=o.object AND c.kind=16384) LIMIT 1", &q);
    if (!r && mdi_step(s, q) != SQLITE_DONE) r = -EIO;
    sqlite3_finalize(q); q = NULL;
    if (!r) r = mdi_prepare(s, "SELECT 1 FROM objects o LEFT JOIN file_paths p ON p.object=o.object "
        "WHERE o.kind!=16384 AND o.name_count>0 AND (p.object IS NULL OR "
        "(p.ambiguous=0 AND (o.name_count!=1 OR NOT EXISTS(SELECT 1 FROM names n "
        "WHERE n.parent=p.parent AND n.name=p.name AND n.object=o.object)))) LIMIT 1", &q);
    if (!r && mdi_step(s, q) != SQLITE_DONE) r = -EIO;
    sqlite3_finalize(q); q = NULL;
    if (!r) r = mdi_prepare(s, "SELECT object,kind,device,inode,parent,name_count,directory_count,backing,shared,logical_inode,source,logical_device,mode,uid,gid,acl_mask,scope,rdev FROM objects", &q);
    while (!r) {
        struct mdi_node node;
        r = read_node(s, q, &node);
        if (r == -ENOENT) { r = 0; break; }
        struct stat st;
        if (!r) r = mdi_stat(s, &node, &st);
        if (!r && node.kind == S_IFDIR && st.st_nlink) {
            int rooted = mdi_ancestor(s, node.scope, node.id);
            if (rooted != 1) r = rooted < 0 ? rooted : -EIO;
        }
        if (!r) { ++audit->objects; audit->detached += !st.st_nlink; }
    }
    sqlite3_finalize(q); q = NULL;
    if (!r) r = mdi_prepare(s, "SELECT n.parent,n.name,n.object,o.parent,o.kind "
        "FROM names n JOIN objects o ON n.object=o.object", &q);
    while (!r) {
        int rc = mdi_step(s, q);
        if (rc != SQLITE_ROW) { r = mdi_sql_error(rc); break; }
        char parent[33], object[33];
        r = read_id(q, 0, parent);
        if (!r) r = read_id(q, 2, object);
        int size = sqlite3_column_bytes(q, 1);
        if (size < 1 || size > NAME_MAX) r = -EIO;
        if (!r) {
            char name[NAME_MAX+1]; memcpy(name, sqlite3_column_blob(q, 1), (size_t)size); name[size] = 0;
            if (memchr(name, 0, (size_t)size) || mdi_name_valid(name)) r = -EIO;
        }
        struct mdi_node node;
        if (!r) r = mdi_node(s, parent, &node);
        if (!r && node.kind != S_IFDIR) r = -EIO;
        if (!r && sqlite3_column_int(q, 4) == S_IFDIR) {
            char owner[33]; r = read_id(q, 3, owner);
            if (!r && (strcmp(owner, parent) || !strcmp(object, MDI_ROOT))) r = -EIO;
        }
        if (!r) ++audit->names;
    }
    sqlite3_finalize(q); q = NULL;
    if (!r) r = mdi_prepare(s, "SELECT n.object FROM names n JOIN objects o ON n.object=o.object "
        "WHERE o.kind=16384 GROUP BY n.object HAVING count(*)>1", &q);
    if (!r && mdi_step(s, q) != SQLITE_DONE) r = -EIO;
    sqlite3_finalize(q);
    int fd = r ? -1 : openat(s->objects, ".", O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd < 0 ? NULL : fdopendir(fd);
    if (!dir && !r) { r = -errno; if (fd >= 0) close(fd); }
    while (!r) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) r = -errno; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        sqlite3_stmt *backing = NULL;
        r = mdi_prepare(s,"SELECT object FROM backings WHERE backing=?1 AND source=?2 LIMIT 1",&backing);
        if (!r) r = mdi_bind_id(backing, 1, entry->d_name);
        if (!r) r = mdi_sql_error(sqlite3_bind_int(backing, 2, 0));
        if (!r) {
            int rc = mdi_step(s, backing);
            if (rc == SQLITE_DONE) ++audit->untracked;
            else if (rc != SQLITE_ROW) r = mdi_sql_failure(rc);
        }
        sqlite3_finalize(backing);
    }
    if (dir) closedir(dir);
    return mdi_finish(s, r);
}
#endif
