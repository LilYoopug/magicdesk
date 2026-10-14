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
    int r=mdi_node(s,s->lifetime->scope,&root);
    struct stat st;
    if (!r && fstat(s->lifetime->scope_lease,&st)) r=-errno;
    if (!r && (root.kind!=S_IFDIR || !S_ISDIR(st.st_mode)
            || root.device!=st.st_dev || root.inode!=st.st_ino
            || strcmp(root.parent,root.id) || strcmp(root.scope,s->lifetime->scope))) r=-ESTALE;
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
     * only the projection metadata while ordinary maintenance leases are held. */
    static const char *const queries[]={
        ("DELETE FROM events WHERE object IN (SELECT object FROM objects WHERE scope=?1) "
            "OR parent IN (SELECT object FROM objects WHERE scope=?1)"),
        "DELETE FROM names WHERE parent IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM file_paths WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM sockets WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM file_capabilities WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM inode_acls WHERE object IN (SELECT object FROM objects WHERE scope=?1)",
        "DELETE FROM backings WHERE scope=?1",
        "DELETE FROM inode_views WHERE scope=?1",
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
static int views(struct md_inode_store *s, int collect) {
    char after[33]=MDI_ROOT;
    int r=0;
    while (!r) {
        sqlite3_stmt *q=NULL;
        r=mdi_prepare(s,collect
            ? "SELECT v.scope,o.backing FROM inode_views v JOIN objects o ON o.object=v.scope "
              "WHERE v.scope>?1 AND NOT EXISTS(SELECT 1 FROM inode_views c JOIN objects u "
              "ON u.object IN(c.upper,c.work) WHERE u.scope=v.scope AND c.scope!=v.scope) "
              "AND NOT EXISTS(SELECT 1 FROM overlay_links l JOIN objects u ON u.object=l.upper "
              "JOIN objects c ON c.object=l.object WHERE u.scope=v.scope AND c.scope!=v.scope) "
              "ORDER BY v.scope LIMIT 1"
            : "SELECT v.scope,o.backing FROM inode_views v "
              "JOIN objects o ON o.object=v.scope WHERE v.scope>?1 ORDER BY v.scope LIMIT 1",&q);
        if (!r) r=mdi_bind_id(q,1,after);
        int next=r ? SQLITE_ERROR : mdi_step(s,q);
        char scope[33],name[33];
        if (!r && next==SQLITE_ROW) {
            const char *id=(const char *)sqlite3_column_text(q,0);
            const char *backing=(const char *)sqlite3_column_text(q,1);
            if (!id || strlen(id)!=32 || !backing || strlen(backing)!=32) r=-EIO;
            else { memcpy(scope,id,sizeof(scope)); memcpy(name,backing,sizeof(name)); }
        } else if (!r && next!=SQLITE_DONE) r=mdi_sql_failure(next);
        sqlite3_finalize(q);
        if (r || next==SQLITE_DONE) break;
        memcpy(after,scope,sizeof(after));
        int lease=openat(s->objects,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (lease<0) { r=-errno; break; }
        if (flock(lease,LOCK_EX|LOCK_NB)) {
            if (errno!=EWOULDBLOCK) r=-errno;
            else if (!collect) r=-EBUSY;
        } else if (collect) {
            r=scope_delete(s,scope);
            /* Removing a child can make an earlier parent collectable. */
            if (!r) memcpy(after,MDI_ROOT,sizeof(after));
        }
        close(lease);
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
