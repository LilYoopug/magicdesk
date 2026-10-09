#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_xattr.h"
#include "fs_operation.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/xattr.h>
#include <unistd.h>

static const char *const controls[]={"user.overlay.whiteout","user.overlay.opaque",
    "trusted.overlay.whiteout","trusted.overlay.opaque"};
int mdi_overlay_attribute(const char *name) {
    for (unsigned i=0;i<sizeof(controls)/sizeof(*controls);++i)
        if (!strcmp(name,controls[i])) return (int)i+1;
    return 0;
}
static int private_name(const char *name) {
    return !strncmp(name,"user.overlay.",13) || !strncmp(name,"trusted.overlay.",16);
}
static int path(struct md_inode_store *s,const struct mdi_node *node,char out[96]) {
    int dir=mdi_backing_directory(s,node);
    if (dir<0) return dir;
    snprintf(out,96,"/proc/self/fd/%d/%s",dir,node->backing); return 0;
}
static ssize_t control_get(struct md_inode_store *s,const struct mdi_node *node,int key,void *out,size_t capacity) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT value FROM overlay_attributes WHERE object=?1 AND name=?2",&q);
    if (!r) r=mdi_bind_id(q,1,node->id);
    if (!r) r=mdi_sql_error(sqlite3_bind_int(q,2,key));
    ssize_t size=0;
    if (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) r=-ENOENT;
        else if (next!=SQLITE_ROW) r=mdi_sql_failure(next);
        else if (sqlite3_column_type(q,0)==SQLITE_NULL) r=-ENODATA;
        else {
            size=sqlite3_column_bytes(q,0);
            if (capacity && capacity<(size_t)size) r=-ERANGE;
            else if (capacity && size) memcpy(out,sqlite3_column_blob(q,0),(size_t)size);
        }
    }
    sqlite3_finalize(q); return r ? r : size;
}
int mdi_overlay_attribute_set(struct md_inode_store *s,const struct mdi_node *node,
        const char *name,const void *value,size_t size) {
    int key=mdi_overlay_attribute(name);
    if (!key || size>MD_FS_VALUE_MAX || (!value && size)) return -EINVAL;
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"INSERT INTO overlay_attributes(object,name,value) VALUES(?1,?2,?3) "
        "ON CONFLICT(object,name) DO UPDATE SET value=excluded.value",&q);
    if (!r) r=mdi_bind_id(q,1,node->id);
    if (!r) r=mdi_sql_error(sqlite3_bind_int(q,2,key));
    if (!r && value) r=mdi_sql_error(sqlite3_bind_blob(q,3,value,(int)size,SQLITE_STATIC));
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q); return r;
}
ssize_t mdi_xattr_get(struct md_inode_store *s,const struct mdi_node *node,
        const char *name,void *out,size_t capacity) {
    int key=mdi_overlay_attribute(name);
    if (key) {
        ssize_t r=control_get(s,node,key,out,capacity);
        if (r!=-ENOENT) return r;
    }
    char target[96]; int r=path(s,node,target);
    if (r) return r;
    ssize_t size=lgetxattr(target,name,out,capacity);
    return size<0 ? -errno : size;
}
int mdi_overlay_attributes_copy(struct md_inode_store *target,const struct mdi_node *to,
        struct md_inode_store *source,const struct mdi_node *from) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(target,"DELETE FROM overlay_attributes WHERE object=?1",&q);
    if (!r) r=mdi_bind_id(q,1,to->id);
    if (!r) r=mdi_sql_error(mdi_step(target,q));
    sqlite3_finalize(q); q=NULL;
    if (!r) r=mdi_prepare(source,"SELECT name,value FROM overlay_attributes WHERE object=?1",&q);
    if (!r) r=mdi_bind_id(q,1,from->id);
    while (!r) {
        int next=mdi_step(source,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        int key=sqlite3_column_int(q,0),size=sqlite3_column_bytes(q,1);
        if (key<1 || key>4) { r=-EIO; break; }
        const void *value=sqlite3_column_type(q,1)==SQLITE_NULL ? NULL : size ? sqlite3_column_blob(q,1) : "";
        r=mdi_overlay_attribute_set(target,to,controls[key-1],value,(size_t)size);
    }
    sqlite3_finalize(q); return r;
}
static int visible(struct md_inode_store *s,const char *name,int internal) {
    if (!strcmp(name,MD_FILE_CAPABILITY_NAME) || !strcmp(name,MD_ACL_ACCESS_NAME)
            || !strcmp(name,MD_ACL_DEFAULT_NAME)) return 0;
    if (internal) return 1;
    if (s->lifetime->filesystem_kind==MD_FILESYSTEM_OVERLAY && private_name(name)) return 0;
    return strncmp(name,"trusted.",8) || !s->identity || md_identity_capable_in(s->identity,NULL,CAP_SYS_ADMIN);
}
static int append(void *out,size_t capacity,size_t *length,const char *name) {
    size_t n=strlen(name)+1;
    if (*length>MD_FS_VALUE_MAX-n) return -E2BIG;
    if (out) {
        if (*length>capacity || n>capacity-*length) return -ERANGE;
        memcpy((char *)out+*length,name,n);
    }
    *length+=n; return 0;
}
ssize_t mdi_xattr_names(struct md_inode_store *s,const struct mdi_node *node,
        void *out,size_t capacity,int internal) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT name,value IS NOT NULL FROM overlay_attributes WHERE object=?1",&q);
    if (!r) r=mdi_bind_id(q,1,node->id);
    unsigned replaced=0,present=0;
    while (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        int key=sqlite3_column_int(q,0);
        if (key<1 || key>4) { r=-EIO; break; }
        replaced|=1U<<(key-1);
        if (sqlite3_column_int(q,1)) present|=1U<<(key-1);
    }
    sqlite3_finalize(q);
    char target[96]; if (!r) r=path(s,node,target);
    ssize_t bytes=r ? 0 : llistxattr(target,NULL,0);
    if (bytes<0) r=-errno;
    else if (bytes>MD_FS_VALUE_MAX) r=-E2BIG;
    char *names=NULL;
    if (!r && bytes) {
        names=malloc((size_t)bytes);
        if (!names) r=-ENOMEM;
        else if ((bytes=llistxattr(target,names,(size_t)bytes))<0) r=-errno;
    }
    size_t length=0;
    for (size_t at=0;!r && at<(size_t)bytes;) {
        const char *name=names+at; size_t n=strnlen(name,(size_t)bytes-at);
        if (n==(size_t)bytes-at) { r=-EIO; break; }
        at+=n+1;
        int key=mdi_overlay_attribute(name);
        if ((!key || !(replaced&(1U<<(key-1)))) && visible(s,name,internal)) r=append(out,capacity,&length,name);
    }
    free(names);
    for (unsigned i=0;!r && i<4;++i)
        if ((present&(1U<<i)) && visible(s,controls[i],internal)) r=append(out,capacity,&length,controls[i]);
    return r ? r : (ssize_t)length;
}
void md_inode_xattr(struct md_inode_store *s,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    int set=q->mode==MD_FS_XATTR_SET,remove=q->mode==MD_FS_XATTR_REMOVE;
    int write=set || remove,list=q->mode==MD_FS_XATTR_LIST;
    const char *name=q->path[1] ? q->path[1] : "";
    int r=mdi_begin(s,write);
    if (r) { out->error=r; return; }
    struct mdi_node node;
    r=mdi_fd(s,q->directory[0],&node);
    if (!r && !list && s->lifetime->filesystem_kind==MD_FILESYSTEM_OVERLAY && private_name(name))
        r=write ? -EPERM : -ENODATA;
    if (!r) r=mdi_xattr_permission(s,&node,name,list ? F_OK : write ? W_OK : R_OK);
    if (!r && !write && q->capacity && (!output || !output->data || output->capacity<q->capacity)) r=-ERANGE;
    void *data=q->capacity && output ? output->data : NULL;
    ssize_t result=0;
    if (!r && list) {
        char security[128]; int count=mdi_attributes(s,&node,security,sizeof(security));
        if (count<0) r=count;
        else if (q->capacity && q->capacity<(unsigned)count) r=-ERANGE;
        else {
            result=mdi_xattr_names(s,&node,data,q->capacity ? q->capacity-(unsigned)count : 0,0);
            if (result<0) r=(int)result;
            else if (result>MD_FS_VALUE_MAX-count) r=-E2BIG;
            else {
                if (data) memcpy((char *)data+result,security,(size_t)count);
                result+=count;
            }
        }
    } else if (!r && !write) {
        result=mdi_xattr_get(s,&node,name,data,q->capacity);
        if (result<0) r=(int)result;
    } else if (!r) {
        if (q->flags&~(XATTR_CREATE|XATTR_REPLACE)) r=-EINVAL;
        int control=mdi_overlay_attribute(name);
        if (!r && control) {
            ssize_t size=mdi_xattr_get(s,&node,name,NULL,0);
            if (size<0 && size!=-ENODATA) r=(int)size;
            else if (size>=0 && set && (q->flags&XATTR_CREATE)) r=-EEXIST;
            else if (size==-ENODATA && (remove || (q->flags&XATTR_REPLACE))) r=-ENODATA;
            if (!r) r=mdi_overlay_attribute_set(s,&node,name,remove ? NULL : q->value_size ? q->value : "",q->value_size);
        } else if (!r) {
            r=mdi_copy_up(s,&node);
            char target[96]; if (!r) r=path(s,&node,target);
            if (!r && (set ? lsetxattr(target,name,q->value,q->value_size,q->flags)
                    : lremovexattr(target,name))) r=-errno;
        }
        if (!r) r=mdi_event(s,NULL,&node,NULL,IN_ATTRIB,NULL);
    }
    r=mdi_commit(s,r);
    out->error=r;
    if (!r && !write) { out->position=result; out->size=q->capacity ? (size_t)result : 0; }
    else out->size=out->position=0;
}
