#define _GNU_SOURCE
#include "inode_view.h"
#include "inode_internal.h"
#include "inode_overlay.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

static int branch(struct md_inode_lifetime *from, struct md_inode_lifetime **out) {
    int root=fcntl(from->root,F_DUPFD_CLOEXEC,3);
    if (root<0) return -errno;
    struct stat st;
    if (fstat(root,&st)) { int r=-errno; close(root); return r; }
    struct md_inode_lifetime *p=mdi_lifetime_new(root,&st);
    if (!p) { close(root); return -ENOMEM; }
    p->temporary=from->temporary;
    p->owner=md_user_namespace_retain(from->owner);
    memcpy(p->scope,from->scope,sizeof(p->scope));
    p->filesystem_kind=from->filesystem_kind;
    int r=0;
    if (from->scope_lease>=0 && (p->scope_lease=fcntl(from->scope_lease,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    for (unsigned i=1; !r && i<MDI_SOURCES; ++i) {
        if (from->sources[i]<0) continue;
        p->sources[i]=fcntl(from->sources[i],F_DUPFD_CLOEXEC,3);
        if (p->sources[i]<0) r=-errno;
        if (!r && (p->source_leases[i]=fcntl(from->source_leases[i],F_DUPFD_CLOEXEC,3))<0) r=-errno;
    }
    if (r) md_inode_lifetime_release(p);
    else *out=p;
    return r;
}
int md_inode_view_validate(struct md_inode_store *s) {
    if (!strcmp(s->lifetime->scope,MDI_ROOT)) return s->lifetime->scope_lease<0 ? 0 : -EPROTO;
    if (s->lifetime->scope_lease<0) return -ESTALE;
    struct mdi_node root;
    /* The initial root body owns the lease even when a writable overlay
     * projects another directory. Backing history retains this identity. */
    int r=mdi_fd(s,s->lifetime->scope_lease,&root);
    struct stat st;
    if (!r && fstat(s->lifetime->scope_lease,&st)) r=-errno;
    if (!r && (root.kind!=S_IFDIR || !S_ISDIR(st.st_mode)
            || strcmp(root.id,s->lifetime->scope) || strcmp(root.parent,root.id)
            || strcmp(root.scope,s->lifetime->scope))) r=-ESTALE;
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(s,"SELECT kind FROM inode_views WHERE scope=?1",&q);
    if (!r) r=mdi_bind_id(q,1,s->lifetime->scope);
    if (!r) {
        int next=mdi_step(s,q);
        r=next==SQLITE_DONE ? -ESTALE : next!=SQLITE_ROW ? mdi_sql_failure(next)
            : sqlite3_column_int(q,0)!=(int)s->lifetime->filesystem_kind ? -EPROTO : 0;
    }
    sqlite3_finalize(q); return r;
}
int md_inode_view_create(struct md_inode_store *base, enum md_filesystem_kind kind,
        struct md_inode_store **out) {
    if (!base || !out || *out || kind!=MD_FILESYSTEM_OVERLAY) return -EINVAL;
    if (base->readonly) return -EROFS;
    struct md_inode_lifetime *owner=NULL;
    int r=branch(base->lifetime,&owner);
    struct md_inode_store *s=NULL;
    if (!r) r=md_inode_store_reconnect(owner,&s);
    md_inode_lifetime_release(owner);
    if (r) return r;
    mdi_overlay_writer_close(s);
    s->identity=base->identity;
    r=mdi_begin(s,1);
    if (r) { md_inode_store_close(s); return r; }
    r=mdi_views_collect(s);
    if (!r) r=mdi_random_id(s->lifetime->scope);
    s->super_checked=0;
    if (!r && s->lifetime->scope_lease>=0) {
        close(s->lifetime->scope_lease); s->lifetime->scope_lease=-1;
    }
    if (!r) for (unsigned i=1; i<MDI_SOURCES; ++i) {
        if (s->lifetime->sources[i]>=0) close(s->lifetime->sources[i]);
        if (s->lifetime->source_leases[i]>=0) close(s->lifetime->source_leases[i]);
        s->lifetime->sources[i]=s->lifetime->source_leases[i]=-1;
    }
    struct mdi_node root;
    if (!r) r=mdi_allocate_root(s,&root);
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(s,"INSERT INTO inode_views(scope,kind) VALUES(?1,?2)",&q);
    if (!r) r=mdi_bind_id(q,1,root.id);
    if (!r) r=mdi_sql_error(sqlite3_bind_int(q,2,kind));
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q);
    if (!r) {
        s->lifetime->scope_lease=openat(s->objects,root.backing,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (s->lifetime->scope_lease<0) r=-errno;
        else if (flock(s->lifetime->scope_lease,LOCK_SH|LOCK_NB)) r=-errno;
    }
    r=mdi_commit(s,r);
    if (r) md_inode_store_close(s);
    else { s->lifetime->filesystem_kind=kind; *out=s; }
    return r;
}
static int scope_delete(struct md_inode_store *s, const char *scope) {
    /* Other stores may retain these native bodies through source leases. Remove
     * only the projection metadata while ordinary maintenance leases are held.
     * Event rows have no live object ownership. Keep them until journal trimming:
     * holes in its shared sequence would falsely overflow unrelated watchers. */
    static const char *const queries[]={
        "DELETE FROM names WHERE parent IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM file_paths WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM dentry_paths WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM sockets WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM file_capabilities WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM inode_acls WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM native_cookies WHERE parent IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM backings WHERE scope=?1",
        "DELETE FROM inode_views WHERE scope=?1",
        "DELETE FROM properties WHERE key='runtime_readonly/'||?1",
        "DELETE FROM objects WHERE scope=?1",
        "DELETE FROM sources WHERE scope=?1"
    };
    int r=0;
    for (unsigned i=0; !r && i<sizeof(queries)/sizeof(queries[0]); ++i) {
        sqlite3_stmt *q=NULL;
        r=mdi_prepare(s,queries[i],&q);
        if (!r) r=mdi_bind_id(q,1,scope);
        if (!r) r=mdi_sql_error(mdi_step(s,q));
        sqlite3_finalize(q);
    }
    return r;
}
static int collection_plan(struct md_inode_store *s) {
    /* Snapshot ownership once under the writer transaction. Busy descendants
     * keep their edges; deleting a leaf wakes only its direct parents. */
    return mdi_sql(s,
        "CREATE TEMP TABLE view_edges(child TEXT,parent TEXT,PRIMARY KEY(child,parent)) WITHOUT ROWID;"
        "INSERT OR IGNORE INTO view_edges SELECT c.scope,u.scope FROM inode_views c "
            "JOIN objects u ON u.object=c.upper WHERE c.scope!=u.scope;"
        "INSERT OR IGNORE INTO view_edges SELECT c.scope,u.scope FROM inode_views c "
            "JOIN objects u ON u.object=c.work WHERE c.scope!=u.scope;"
        "INSERT OR IGNORE INTO view_edges SELECT c.scope,u.scope FROM overlay_links l "
            "JOIN objects c ON c.object=l.object JOIN objects u ON u.object=l.upper WHERE c.scope!=u.scope;"
        "CREATE INDEX temp.view_edges_parent ON view_edges(parent);"
        "CREATE TEMP TABLE view_gc(scope TEXT PRIMARY KEY,blockers INTEGER NOT NULL) WITHOUT ROWID;"
        "INSERT INTO view_gc SELECT v.scope,(SELECT count(*) FROM view_edges e WHERE e.parent=v.scope) "
            "FROM inode_views v JOIN objects o ON o.object=v.scope WHERE v.scope>'" MDI_ROOT "';"
        "CREATE INDEX temp.view_gc_ready ON view_gc(scope) WHERE blockers=0;");
}
static int collection_advance(struct md_inode_store *s,const char *scope,int removed) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,removed
        ? "UPDATE temp.view_gc SET blockers=blockers-1 WHERE blockers>0 "
          "AND scope IN (SELECT parent FROM temp.view_edges WHERE child=?1)"
        : "UPDATE temp.view_gc SET blockers=-1 WHERE scope=?1",&q);
    if (!r) r=mdi_bind_id(q,1,scope);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q); q=NULL;
    if (!r && removed) {
        r=mdi_prepare(s,"DELETE FROM temp.view_gc WHERE scope=?1",&q);
        if (!r) r=mdi_bind_id(q,1,scope);
        if (!r) r=mdi_sql_error(mdi_step(s,q));
        sqlite3_finalize(q);
    }
    return r;
}
static int views(struct md_inode_store *s, int collect) {
    char after[33]=MDI_ROOT;
    int r=0;
    if (collect) {
        sqlite3_stmt *q=NULL;
        r=mdi_prepare(s,"SELECT 1 FROM inode_views WHERE scope>?1 LIMIT 1",&q);
        if (!r) r=mdi_bind_id(q,1,after);
        int next=r ? SQLITE_ERROR : mdi_step(s,q);
        if (!r && next!=SQLITE_ROW && next!=SQLITE_DONE) r=mdi_sql_failure(next);
        sqlite3_finalize(q);
        if (r || next==SQLITE_DONE) return r;
        r=collection_plan(s);
    }
    while (!r) {
        sqlite3_stmt *q=NULL;
        r=mdi_prepare(s,collect
            ? "SELECT scope FROM temp.view_gc WHERE blockers=0 ORDER BY scope LIMIT 1"
            : "SELECT v.scope FROM inode_views v "
              "JOIN objects o ON o.object=v.scope WHERE v.scope>?1 ORDER BY v.scope LIMIT 1",&q);
        if (!r && !collect) r=mdi_bind_id(q,1,after);
        int next=r ? SQLITE_ERROR : mdi_step(s,q);
        char scope[33];
        if (!r && next==SQLITE_ROW) {
            const char *id=(const char *)sqlite3_column_text(q,0);
            if (!id || strlen(id)!=32) r=-EIO;
            else memcpy(scope,id,sizeof(scope));
        } else if (!r && next!=SQLITE_DONE) r=mdi_sql_failure(next);
        sqlite3_finalize(q);
        if (r || next==SQLITE_DONE) break;
        memcpy(after,scope,sizeof(after));
        int lease=openat(s->objects,scope,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (lease<0) { r=-errno; break; }
        if (flock(lease,LOCK_EX|LOCK_NB)) {
            if (errno!=EWOULDBLOCK) r=-errno;
            else if (!collect) r=-EBUSY;
            else r=collection_advance(s,scope,0);
        } else if (collect) {
            r=scope_delete(s,scope);
            if (!r) r=collection_advance(s,scope,1);
        }
        close(lease);
    }
    if (collect) {
        int cleanup=mdi_sql(s,"DROP TABLE IF EXISTS temp.view_gc; DROP TABLE IF EXISTS temp.view_edges;");
        if (!r) r=cleanup;
    }
    return r;
}
int mdi_views_collect(struct md_inode_store *s) { return views(s,1); }
int mdi_views_busy(struct md_inode_store *s) { return views(s,0); }
int mdi_views_maintain(struct md_inode_store *s) {
    int r=0;
    if (!s->readonly) {
        r=mdi_begin(s,1);
        if (!r) { s->sync_requested=1; r=mdi_commit(s,mdi_views_collect(s)); }
    }
    if (!r) {
        r=mdi_begin(s,0);
        if (!r) r=mdi_finish(s,mdi_discard_untracked_backings(s));
    }
    return r;
}
