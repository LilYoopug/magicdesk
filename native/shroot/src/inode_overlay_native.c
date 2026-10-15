#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_leaf.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int mdi_overlay_native_name(struct md_inode_store *s,const struct mdi_node *parent,const char *name) {
    if (!s->overlay) return 0;
    sqlite3_stmt *q=NULL;
    int r=mdi_query_acquire(s,MDI_OVERLAY_NATIVE_NAME,&q);
    if (!r) r=mdi_bind_id(q,1,parent->id);
    if (!r) r=mdi_bind_id(q,2,parent->backing);
    if (!r) r=mdi_bind_name(q,3,name);
    if (!r) {
        int next=mdi_step(s,q);
        r=next==SQLITE_ROW ? 0 : next==SQLITE_DONE ? -EOPNOTSUPP : mdi_sql_failure(next);
    }
    return mdi_query_release(q,r);
}

/* Publication owns the transaction and durable intent. Every writable alias
 * of this directory is catalogued before the native name disappears from the
 * recovery protocol; no runtime-only callback is needed after a crash. */
int mdi_overlay_publish_leaf(struct md_inode_store *s,const struct mdi_node *parent,
        const struct mdi_node *node,const char *name) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT object,scope FROM objects WHERE backing=?1 AND source=0 "
        "AND kind=16384 AND object!=?2",&q);
    if (!r) r=mdi_bind_id(q,1,parent->backing);
    if (!r) r=mdi_bind_id(q,2,parent->id);
    while (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        const char *id=(const char *)sqlite3_column_text(q,0),*scope=(const char *)sqlite3_column_text(q,1);
        if (!id || !scope || strlen(id)!=32 || strlen(scope)!=32) { r=-EIO; break; }
        char alias[33]; struct stat st={.st_dev=node->logical_device,.st_ino=node->logical_inode};
        r=mdi_leaf_id(&st,scope,alias);
        sqlite3_stmt *insert=NULL;
        if (!r) r=mdi_prepare(s,"INSERT INTO objects(object,kind,device,inode,backing,logical_inode,logical_device,mode,uid,gid,scope) "
            "SELECT ?1,kind,device,inode,backing,logical_inode,logical_device,mode,uid,gid,?2 FROM objects WHERE object=?3",&insert);
        if (!r) r=mdi_bind_id(insert,1,alias);
        if (!r) r=mdi_bind_id(insert,2,scope);
        if (!r) r=mdi_bind_id(insert,3,node->id);
        if (!r) r=mdi_sql_error(mdi_step(s,insert));
        sqlite3_finalize(insert);
        struct mdi_node target;
        if (!r) r=mdi_node(s,alias,&target);
        int fd=r ? -1 : mdi_backing_open(s,node,O_PATH);
        if (!r) r=fd<0 ? fd : mdi_leaf_import_attributes(s,&target,fd);
        if (fd>=0) close(fd);
        if (!r) r=mdi_add_name(s,id,name,alias);
    }
    sqlite3_finalize(q); q=NULL;
    if (!r) r=mdi_prepare(s,"INSERT INTO overlay_links(object,upper,lower) "
        "SELECT v.object,u.object,0 FROM overlay_links l "
        "JOIN names v ON v.parent=l.object JOIN names u ON u.parent=l.upper AND u.name=v.name "
        "JOIN objects o ON o.object=v.object WHERE o.backing=?1 AND v.name=?2 "
        "ON CONFLICT(object) DO UPDATE SET upper=excluded.upper",&q);
    if (!r) r=mdi_bind_id(q,1,node->backing);
    if (!r) r=mdi_bind_name(q,2,name);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q); return r;
}
