#include "inode_internal.h"
#include <errno.h>
#include <string.h>

int mdi_channel(struct md_inode_store *s,const struct mdi_node *node,char id[33],int *source) {
    if (node->kind!=S_IFIFO && node->kind!=S_IFSOCK) return -EINVAL;
    sqlite3_stmt *q=NULL;
    int origin=0;
    int r=mdi_prepare(s,"SELECT channel,source FROM inode_channels WHERE object=?1",&q);
    if (!r) r=mdi_bind_id(q,1,node->id);
    if (!r) {
        int next=mdi_step(s,q);
        if (next!=SQLITE_ROW) r=next==SQLITE_DONE ? -EIO : mdi_sql_failure(next);
        else {
            const char *value=(const char *)sqlite3_column_text(q,0);
            origin=sqlite3_column_int(q,1);
            if (!value || strlen(value)!=32 || strspn(value,"0123456789abcdef")!=32
                    || origin<0 || origin>=MDI_SOURCES) r=-EIO;
            else { memcpy(id,value,33); if (source) *source=origin; }
        }
    }
    sqlite3_finalize(q);
    if (!r && origin && s->lifetime->sources[origin]<0) r=mdi_sources_open(s);
    return r;
}
int mdi_channel_copy(struct md_inode_store *target,const struct mdi_node *to,
        struct md_inode_store *source,const struct mdi_node *from) {
    if (from->kind!=S_IFIFO && from->kind!=S_IFSOCK) return 0;
    if (from->kind!=to->kind) return -EINVAL;
    char id[33]; int origin=0,local=0;
    int r=mdi_channel(source,from,id,&origin);
    int directory=origin ? source->lifetime->sources[origin] : source->objects;
    if (!r && directory<0) r=-ESTALE;
    if (!r) r=mdi_source_register(target,directory,&local);
    if (!r) r=mdi_sources_open(target);
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(target,"UPDATE inode_channels SET channel=?1,source=?2 WHERE object=?3",&q);
    if (!r) r=mdi_bind_id(q,1,id);
    if (!r) r=mdi_sql_error(sqlite3_bind_int(q,2,local));
    if (!r) r=mdi_bind_id(q,3,to->id);
    if (!r) r=mdi_sql_error(mdi_step(target,q));
    if (!r && sqlite3_changes(target->db)!=1) r=-EIO;
    sqlite3_finalize(q); q=NULL;
    if (!r && from->kind==S_IFSOCK) {
        r=mdi_prepare(source,"SELECT address FROM sockets WHERE object=?1",&q);
        if (!r) r=mdi_bind_id(q,1,from->id);
        if (!r) {
            int next=mdi_step(source,q);
            if (next!=SQLITE_ROW) r=next==SQLITE_DONE ? -EIO : mdi_sql_failure(next);
            else {
                sqlite3_stmt *out=NULL;
                r=mdi_prepare(target,"INSERT INTO sockets VALUES(?1,?2) "
                    "ON CONFLICT(object) DO UPDATE SET address=excluded.address",&out);
                if (!r) r=mdi_bind_id(out,1,to->id);
                if (!r) r=mdi_sql_error(sqlite3_bind_value(out,2,sqlite3_column_value(q,0)));
                if (!r) r=mdi_sql_error(mdi_step(target,out));
                sqlite3_finalize(out);
            }
        }
        sqlite3_finalize(q);
    }
    return r;
}
