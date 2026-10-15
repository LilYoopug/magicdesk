#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_overlay.h"
#include "inode_xattr.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

struct mdi_overlay_writer {
    struct md_inode_store upper;
    sqlite3_stmt *touch;
    int user_xattr,flushing;
};
static int link_info(struct md_inode_store *s,const struct mdi_node *node,char upper[33],int *lower) {
    *upper=0; *lower=0;
    sqlite3_stmt *q=NULL;
    int r=mdi_query_acquire(s,MDI_OVERLAY_LINK,&q);
    if (!r) r=mdi_bind_id(q,1,node->id);
    if (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_ROW) {
            const char *id=(const char *)sqlite3_column_text(q,0);
            if (id && strlen(id)!=32) r=-EIO;
            else if (id) memcpy(upper,id,33);
            *lower=sqlite3_column_int(q,1);
        } else if (next!=SQLITE_DONE) r=mdi_sql_failure(next);
    }
    return mdi_query_release(q,r);
}
int mdi_overlay_upper(struct md_inode_store *s,const struct mdi_node *node,
        struct md_inode_store **store,struct mdi_node *out) {
    if (!s->overlay) return 0;
    if (node->native) { *store=&s->overlay->upper; *out=*node; return 1; }
    char mapped[33]; int lower=0;
    int r=link_info(s,node,mapped,&lower);
    if (r || !*mapped) return r;
    *store=&s->overlay->upper;
    r=mdi_node(*store,mapped,out);
    return r ? r : 1;
}
int mdi_overlay_rename_directory(struct md_inode_store *s,const struct mdi_node *node) {
    if (!s->overlay || node->kind!=S_IFDIR) return 0;
    char id[33]; int lower=0;
    int r=link_info(s,node,id,&lower);
    return r ? r : lower ? -EXDEV : 0;
}
int mdi_overlay_touch(struct md_inode_store *s,const struct mdi_node *node) {
    struct mdi_overlay_writer *w=s->overlay;
    if (!w || w->flushing || node->native) return 0;
    char upper[33]; int lower=0;
    int r=s->lifetime->overlay_identity ? link_info(s,node,upper,&lower) : 0;
    if (!r && s->lifetime->overlay_identity && lower && !*upper && node->kind==S_IFREG)
        r=mdi_permission_as(s,node,R_OK,s->lifetime->overlay_identity);
    if (!r) r=mdi_bind_id(w->touch,1,node->id);
    if (!r) r=mdi_sql_error(mdi_step(s,w->touch));
    return mdi_query_release(w->touch,r);
}
static int metadata(struct md_inode_store *s,const struct mdi_node *from,struct mdi_node *to) {
    struct md_inode_store *u=&s->overlay->upper;
    struct stat st={0};
    int r=mdi_stat(s,from,&st);
    if (!r) r=mdi_metadata(u,to,st.st_uid,st.st_gid,st.st_mode&07777);
    if (!r) r=mdi_device_number(u,to,from->rdev);
    if (!r && from->kind!=S_IFLNK) r=mdi_acl_store(u,to,MD_ACL_ACCESS,NULL,0);
    if (!r && from->kind==S_IFDIR) r=mdi_acl_store(u,to,MD_ACL_DEFAULT,NULL,0);
    if (!r) r=mdi_file_capability(u,to,NULL,0);
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(s,"SELECT type,value FROM inode_acls WHERE object=?1 "
        "UNION ALL SELECT 4,value FROM file_capabilities WHERE object=?1",&q);
    if (!r) r=mdi_bind_id(q,1,from->id);
    while (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        int type=sqlite3_column_int(q,0);
        const void *value=sqlite3_column_blob(q,1); size_t size=(size_t)sqlite3_column_bytes(q,1);
        r=type==4 ? mdi_file_capability(u,to,value,size) : mdi_acl_store(u,to,(unsigned)type,value,size);
    }
    sqlite3_finalize(q);
    if (!r && from->kind!=S_IFREG && (from->device!=to->device || from->inode!=to->inode)) {
        struct timespec times[2]={st.st_atim,st.st_mtim};
        if (!r && utimensat(u->objects,to->backing,times,AT_SYMLINK_NOFOLLOW)) r=-errno;
        if (!r && from->kind==S_IFDIR) {
            int a=openat(s->objects,from->backing,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            int b=openat(u->objects,to->backing,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if (a<0 || b<0) r=-errno;
            else r=mdi_overlay_replace_attributes(a,b);
            if (a>=0) close(a);
            if (b>=0) close(b);
        }
    }
    if (!r) r=mdi_channel_copy(u,to,s,from);
    return r;
}
static int clear_detached_directory(struct md_inode_store *s,const struct mdi_node *old) {
    if (old->kind!=S_IFDIR) return 0;
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT 1 FROM overlay_links l JOIN objects o ON o.object=l.object "
        "WHERE l.upper=?1 AND o.scope=?2 AND o.name_count>0",&q);
    if (!r) r=mdi_bind_id(q,1,old->id);
    if (!r) r=mdi_bind_id(q,2,s->lifetime->scope);
    int retained=0;
    if (!r) {
        int next=mdi_step(s,q);
        retained=next==SQLITE_ROW;
        if (next!=SQLITE_ROW && next!=SQLITE_DONE) r=mdi_sql_failure(next);
    }
    sqlite3_finalize(q); q=NULL;
    if (r || retained) return r;
    /* A logically empty merged directory may still contain upper whiteouts.
     * Retire their names, never the bodies retained by open descriptors. */
    r=mdi_prepare(s,"WITH RECURSIVE dirs(id) AS (SELECT ?1 UNION "
        "SELECT n.object FROM names n JOIN dirs d ON n.parent=d.id JOIN objects o "
        "ON o.object=n.object WHERE o.kind=16384) DELETE FROM names WHERE parent IN(SELECT id FROM dirs)",&q);
    if (!r) r=mdi_bind_id(q,1,old->id);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q); return r;
}
static int set_name(struct md_inode_store *s,const struct mdi_node *parent,const char *name,
        const struct mdi_node *node) {
    struct md_inode_store *u=&s->overlay->upper;
    struct mdi_node old;
    int r=mdi_lookup(u,parent->id,name,&old);
    if (!r && node && !strcmp(old.id,node->id)) return 0;
    if (r && r!=-ENOENT) return r;
    int permission=mdi_permission_as(u,parent,W_OK|X_OK,s->lifetime->overlay_identity);
    if (permission) return permission;
    if (!r) {
        struct mdi_location loc={.parent=*parent,.node=old};
        r=mdi_sticky_as(u,&loc,s->lifetime->overlay_identity);
        if (!r) r=clear_detached_directory(s,&old);
        if (!r) r=mdi_delete_name(u,parent->id,name);
        if (!r) {
            memcpy(loc.name,name,strlen(name)+1);
            r=mdi_removed_event(u,&loc,1);
        }
    } else if (r==-ENOENT) r=0;
    if (!r && node) r=mdi_add_name(u,parent->id,name,node->id);
    if (!r && node) r=mdi_reparent(u,node,parent->id);
    if (!r && node) r=mdi_event(u,parent->id,node,name,IN_CREATE,NULL);
    return r;
}
static int promote(struct md_inode_store *s,const char *id,struct mdi_node *upper,unsigned depth) {
    if (depth>256) return -ELOOP;
    struct mdi_node node;
    int r=mdi_node(s,id,&node);
    char mapped[33]; int lower=0;
    if (!r) r=link_info(s,&node,mapped,&lower);
    struct md_inode_store *u=&s->overlay->upper;
    if (!r && *mapped) r=mdi_node(u,mapped,upper);
    if (!r && node.kind==S_IFREG) r=mdi_copy_up(s,&node);
    if (!r && !*mapped) {
        if (node.kind==S_IFREG) {
            r=mdi_import_shared(u,0,node.backing,upper);
            if (!r) r=mdi_bind_body(s,&node,upper);
        } else if (node.kind==S_IFDIR || node.kind==S_IFLNK || node.kind==S_IFIFO || node.kind==S_IFSOCK
                || node.kind==S_IFCHR || node.kind==S_IFBLK) {
            char target[PATH_MAX];
            if (node.kind==S_IFLNK) {
                ssize_t n=readlinkat(s->objects,node.backing,target,sizeof(target));
                if (n<0) r=-errno;
                else if ((size_t)n==sizeof(target)) r=-ENAMETOOLONG;
                else target[n]=0;
            }
            int fd=-1;
            if (!r) r=mdi_allocate(u,node.kind,0700,O_RDWR,node.kind==S_IFLNK ? target : NULL,
                mdi_root(u),upper,&fd);
            if (fd>=0) close(fd);
            if (!r && node.kind==S_IFDIR) r=mdi_bind_body(s,&node,upper);
            if (!r && node.kind==S_IFDIR && !lower) r=mdi_overlay_attribute_set(u,upper,
                s->overlay->user_xattr ? "user.overlay.opaque" : "trusted.overlay.opaque","y",1);
        } else r=-EOPNOTSUPP;
        sqlite3_stmt *q=NULL;
        if (!r) r=mdi_prepare(s,"INSERT INTO overlay_links(object,upper,lower) VALUES(?1,?2,0) "
            "ON CONFLICT(object) DO UPDATE SET upper=excluded.upper",&q);
        if (!r) r=mdi_bind_id(q,1,node.id);
        if (!r) r=mdi_bind_id(q,2,upper->id);
        if (!r) r=mdi_sql_error(mdi_step(s,q));
        sqlite3_finalize(q);
    } else if (!r && node.kind==S_IFREG) r=mdi_bind_body(s,&node,upper);
    if (!r) r=metadata(s,&node,upper);
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(s,"SELECT parent,name FROM names WHERE object=?1",&q);
    if (!r) r=mdi_bind_id(q,1,node.id);
    while (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        char parent[33],name[NAME_MAX+1];
        const char *p=(const char *)sqlite3_column_text(q,0);
        int size=sqlite3_column_bytes(q,1);
        if (!p || strlen(p)!=32 || size<1 || size>NAME_MAX) { r=-EIO; break; }
        memcpy(parent,p,33); memcpy(name,sqlite3_column_blob(q,1),(size_t)size); name[size]=0;
        struct mdi_node upper_parent;
        r=promote(s,parent,&upper_parent,depth+1);
        if (!r) r=set_name(s,&upper_parent,name,upper);
    }
    sqlite3_finalize(q); return r;
}
static int sync_name(struct md_inode_store *s,const char *parent,const char *name) {
    struct mdi_node up,node;
    int r=promote(s,parent,&up,0);
    int found=r ? r : mdi_lookup(s,parent,name,&node);
    if (found && found!=-ENOENT) return found;
    if (!found) {
        struct mdi_node target;
        r=promote(s,node.id,&target,0);
        return r ? r : set_name(s,&up,name,&target);
    }
    sqlite3_stmt *q=NULL;
    r=mdi_prepare(s,"SELECT 1 FROM overlay_lower_names WHERE parent=?1 AND name=?2",&q);
    if (!r) r=mdi_bind_id(q,1,parent);
    if (!r) r=mdi_bind_name(q,2,name);
    int lower=0;
    if (!r) {
        int next=mdi_step(s,q); lower=next==SQLITE_ROW;
        if (next!=SQLITE_ROW && next!=SQLITE_DONE) r=mdi_sql_failure(next);
    }
    sqlite3_finalize(q);
    if (r) return r;
    if (!lower) return set_name(s,&up,name,NULL);
    int fd=-1; struct md_inode_store *u=&s->overlay->upper;
    r=mdi_allocate(u,S_IFREG,0600,O_RDWR,NULL,up.id,&node,&fd);
    if (fd>=0) close(fd);
    if (!r) r=mdi_overlay_attribute_set(u,&node,
        s->overlay->user_xattr ? "user.overlay.whiteout" : "trusted.overlay.whiteout","",0);
    if (!r) r=set_name(s,&up,name,&node);
    return r;
}
int mdi_overlay_flush(struct md_inode_store *s) {
    struct mdi_overlay_writer *w=s->overlay;
    if (!w || w->flushing) return 0;
    w->flushing=1;
    w->upper.recording=s->recording;
    w->upper.identity=s->lifetime->overlay_identity;
    int r=mdi_sql(s,"UPDATE temp.overlay_journal SET flushing=1");
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(s,"SELECT object FROM temp.overlay_dirty",&q);
    while (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        const char *id=(const char *)sqlite3_column_text(q,0);
        struct mdi_node upper;
        r=promote(s,id,&upper,0);
    }
    sqlite3_finalize(q); q=NULL;
    if (!r) r=mdi_prepare(s,"SELECT parent,name FROM temp.overlay_names",&q);
    while (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        const char *parent=(const char *)sqlite3_column_text(q,0);
        int size=sqlite3_column_bytes(q,1); char name[NAME_MAX+1];
        if (size<1 || size>NAME_MAX) { r=-EIO; break; }
        memcpy(name,sqlite3_column_blob(q,1),(size_t)size); name[size]=0;
        r=sync_name(s,parent,name);
    }
    sqlite3_finalize(q);
    if (!r) r=mdi_sql(s,"DELETE FROM temp.overlay_dirty; DELETE FROM temp.overlay_names; "
        "UPDATE temp.overlay_journal SET flushing=0");
    w->flushing=0; return r;
}
void mdi_overlay_writer_close(struct md_inode_store *s) {
    struct mdi_overlay_writer *w=s->overlay;
    if (!w) return;
    sqlite3_finalize(w->touch);
    for (unsigned i=0;i<MDI_QUERY_COUNT;++i) sqlite3_finalize(w->upper.queries[i]);
    md_inode_lifetime_release(w->upper.lifetime);
    mdi_sql(s,"DROP TRIGGER IF EXISTS temp.overlay_insert; DROP TRIGGER IF EXISTS temp.overlay_update; "
        "DROP TRIGGER IF EXISTS temp.overlay_name_add; DROP TRIGGER IF EXISTS temp.overlay_name_remove; "
        "DROP TRIGGER IF EXISTS temp.overlay_cap_add; DROP TRIGGER IF EXISTS temp.overlay_cap_remove; "
        "DROP TABLE IF EXISTS temp.overlay_names; DROP TABLE IF EXISTS temp.overlay_dirty; "
        "DROP TABLE IF EXISTS temp.overlay_journal");
    free(w); s->overlay=NULL;
}
int mdi_overlay_writer_open(struct md_inode_store *s) {
    if (s->overlay || s->lifetime->filesystem_kind!=MD_FILESYSTEM_OVERLAY
            || !strcmp(s->lifetime->scope,MDI_ROOT)) return 0;
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT o.scope,v.user_xattr FROM inode_views v JOIN objects o ON o.object=v.upper "
        "WHERE v.scope=?1 AND v.writable=1",&q);
    if (!r) r=mdi_bind_id(q,1,s->lifetime->scope);
    char scope[33]={0}; int user=0;
    if (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_ROW) {
            const char *id=(const char *)sqlite3_column_text(q,0);
            if (!id || strlen(id)!=32) r=-EIO;
            else { memcpy(scope,id,33); user=sqlite3_column_int(q,1); }
        } else if (next!=SQLITE_DONE) r=mdi_sql_failure(next);
    }
    sqlite3_finalize(q);
    if (r || !*scope) return r;
    if (strcmp(scope,MDI_ROOT)) return -EOPNOTSUPP;
    struct mdi_overlay_writer *w=calloc(1,sizeof(*w));
    if (!w) return -ENOMEM;
    s->overlay=w; w->user_xattr=user;
    int root=fcntl(s->lifetime->root,F_DUPFD_CLOEXEC,3);
    if (root<0) r=-errno;
    struct stat st;
    if (!r && fstat(root,&st)) r=-errno;
    if (!r) {
        w->upper.lifetime=mdi_lifetime_new(root,&st);
        if (!w->upper.lifetime) r=-ENOMEM;
        else {
            root=-1; w->upper.lifetime->temporary=s->lifetime->temporary;
            w->upper.db=s->db; w->upper.objects=s->objects;
            r=mdi_sources_open(&w->upper);
        }
    }
    if (root>=0) close(root);
    if (!r) r=mdi_sql(s,"CREATE TEMP TABLE overlay_dirty(object TEXT PRIMARY KEY); "
        "CREATE TEMP TABLE overlay_names(parent TEXT,name BLOB,PRIMARY KEY(parent,name)); "
        "CREATE TEMP TABLE overlay_journal(flushing INTEGER); INSERT INTO overlay_journal VALUES(0)");
    char *sql=NULL;
    if (!r) {
        sql=sqlite3_mprintf(
            "CREATE TEMP TRIGGER overlay_insert AFTER INSERT ON main.objects "
            "WHEN NEW.scope='%q' AND (SELECT flushing FROM overlay_journal)=0 BEGIN "
            "INSERT OR IGNORE INTO overlay_dirty VALUES(NEW.object); END;"
            "CREATE TEMP TRIGGER overlay_update AFTER UPDATE OF uid,gid,mode,backing,source,acl_mask,parent ON main.objects "
            "WHEN NEW.scope='%q' AND (SELECT flushing FROM overlay_journal)=0 BEGIN "
            "INSERT OR IGNORE INTO overlay_dirty VALUES(NEW.object); END;"
            "CREATE TEMP TRIGGER overlay_name_add AFTER INSERT ON main.names "
            "WHEN (SELECT scope FROM objects WHERE object=NEW.parent)='%q' AND (SELECT flushing FROM overlay_journal)=0 BEGIN "
            "INSERT OR IGNORE INTO overlay_names VALUES(NEW.parent,NEW.name); END;"
            "CREATE TEMP TRIGGER overlay_name_remove AFTER DELETE ON main.names "
            "WHEN (SELECT scope FROM objects WHERE object=OLD.parent)='%q' AND (SELECT flushing FROM overlay_journal)=0 BEGIN "
            "INSERT OR IGNORE INTO overlay_names VALUES(OLD.parent,OLD.name); END;"
            "CREATE TEMP TRIGGER overlay_cap_add AFTER INSERT ON main.file_capabilities "
            "WHEN (SELECT scope FROM objects WHERE object=NEW.object)='%q' AND (SELECT flushing FROM overlay_journal)=0 BEGIN "
            "INSERT OR IGNORE INTO overlay_dirty VALUES(NEW.object); END;"
            "CREATE TEMP TRIGGER overlay_cap_remove AFTER DELETE ON main.file_capabilities "
            "WHEN (SELECT scope FROM objects WHERE object=OLD.object)='%q' AND (SELECT flushing FROM overlay_journal)=0 BEGIN "
            "INSERT OR IGNORE INTO overlay_dirty VALUES(OLD.object); END;",
            s->lifetime->scope,s->lifetime->scope,s->lifetime->scope,
            s->lifetime->scope,s->lifetime->scope,s->lifetime->scope);
        if (!sql) r=-ENOMEM;
    }
    if (!r) r=mdi_sql(s,sql);
    sqlite3_free(sql);
    if (!r) r=mdi_prepare(s,"INSERT OR IGNORE INTO temp.overlay_dirty VALUES(?1)",&w->touch);
    if (r) mdi_overlay_writer_close(s);
    return r;
}
int md_inode_overlay_activate(struct md_inode_store *s) {
    if (!s || s->readonly || s->overlay || s->lifetime->filesystem_kind!=MD_FILESYSTEM_OVERLAY) return -EINVAL;
    int r=mdi_begin(s,1);
    if (r) return r;
    sqlite3_stmt *q=NULL;
    r=mdi_prepare(s,"UPDATE inode_views SET writable=1 WHERE scope=?1 AND upper IS NOT NULL AND writable=0",&q);
    if (!r) r=mdi_bind_id(q,1,s->lifetime->scope);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    if (!r && sqlite3_changes(s->db)!=1) r=-EINVAL;
    sqlite3_finalize(q);
    r=mdi_commit(s,r);
    return r ? r : mdi_overlay_writer_open(s);
}
