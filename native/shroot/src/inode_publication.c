#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_publication.h"
#include "inode_native.h"
#include "inode_leaf.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct mdi_publication { atomic_uint *pending; int inspect; };
struct intent {
    char object[33],parent[33],name[NAME_MAX+1];
    dev_t device; ino_t inode;
    uint32_t uid,gid; mode_t mode;
};
static int watch_boundary(struct md_inode_store *s,int begin) {
    return mdi_watch_marker(s,begin ? "publication-v1.begin" : "publication-v1.end");
}
_Static_assert(ATOMIC_INT_LOCK_FREE==2 && sizeof(atomic_uint)==4,"shared publication marker");
#ifndef MD_INODE_TESTING
enum { MD_PUBLICATION_INTENT, MD_PUBLICATION_MOVED, MD_PUBLICATION_CATALOGUED, MD_PUBLICATION_STAGED };
#endif
static void observed(struct md_inode_store *s,int point) {
#ifdef MD_INODE_TESTING
    if (s->observe) s->observe(point,s->context);
#else
    (void)s; (void)point;
#endif
}
static int id(sqlite3_stmt *q,int column,char out[33]) {
    const char *value=(const char *)sqlite3_column_text(q,column);
    if (!value || sqlite3_column_bytes(q,column)!=32 || strspn(value,"0123456789abcdef")!=32) return -EIO;
    memcpy(out,value,33); return 0;
}
static int load(struct md_inode_store *s,struct intent *p) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT object,parent,name,device,inode,uid,gid,mode FROM native_publication WHERE slot=1",&q);
    if (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) r=-ENOENT;
        else if (next!=SQLITE_ROW) r=mdi_sql_failure(next);
        else {
            r=id(q,0,p->object);
            if (!r) r=id(q,1,p->parent);
            int length=sqlite3_column_bytes(q,2);
            const void *name=sqlite3_column_blob(q,2);
            if (!r && (!name || length<1 || length>NAME_MAX || memchr(name,0,(size_t)length))) r=-EIO;
            if (!r) {
                memcpy(p->name,name,(size_t)length); p->name[length]=0;
                if (mdi_name_valid(p->name)) r=-EIO;
            }
            p->device=(dev_t)sqlite3_column_int64(q,3); p->inode=(ino_t)sqlite3_column_int64(q,4);
            sqlite3_int64 uid=sqlite3_column_int64(q,5),gid=sqlite3_column_int64(q,6),mode=sqlite3_column_int64(q,7);
            if (uid<0 || uid>=UINT32_MAX || gid<0 || gid>=UINT32_MAX || mode<0 || mode>07777) r=-EIO;
            p->uid=(uint32_t)uid; p->gid=(uint32_t)gid; p->mode=(mode_t)mode;
        }
    }
    sqlite3_finalize(q); return r;
}
static int bind_intent(sqlite3_stmt *q,const struct intent *p) {
    int r=mdi_bind_id(q,1,p->object);
    if (!r) r=mdi_bind_id(q,2,p->parent);
    if (!r) r=mdi_bind_name(q,3,p->name);
    if (!r) r=mdi_sql_error(sqlite3_bind_int64(q,4,(sqlite3_int64)p->device));
    if (!r) r=mdi_sql_error(sqlite3_bind_int64(q,5,(sqlite3_int64)p->inode));
    if (!r) r=mdi_sql_error(sqlite3_bind_int64(q,6,p->uid));
    if (!r) r=mdi_sql_error(sqlite3_bind_int64(q,7,p->gid));
    if (!r) r=mdi_sql_error(sqlite3_bind_int(q,8,(int)p->mode));
    return r;
}
static int commit(struct md_inode_store *s,int r) {
    if (!r) r=mdi_sql(s,"COMMIT");
    if (r) mdi_sql(s,"ROLLBACK");
    return r;
}
static int parent_directory(struct md_inode_store *s,const struct intent *p,struct mdi_node *parent,
        struct timespec times[2]) {
    int r=mdi_node(s,p->parent,parent);
    if (!r && (parent->kind!=S_IFDIR || parent->source || !parent->attached)) r=-ESTALE;
    struct stat st;
    if (!r) r=mdi_backing_stat(s,parent,&st);
    if (r) return r;
    int fd=openat(s->objects,parent->backing,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -errno;
    if (fstat(fd,&st)) r=-errno;
    if (!r && (st.st_dev!=parent->device || st.st_ino!=parent->inode)) r=-ESTALE;
    if (!r && times) { times[0]=st.st_atim; times[1]=st.st_mtim; }
    if (r) close(fd);
    return r ? r : fd;
}
static int matches(const struct stat *st,const struct intent *p) {
    return S_ISREG(st->st_mode) && st->st_dev==p->device && st->st_ino==p->inode && st->st_nlink==1;
}
static int named(int directory,const char *name,struct stat *st) {
    if (!fstatat(directory,name,st,AT_SYMLINK_NOFOLLOW)) return 1;
    return errno==ENOENT ? 0 : -errno;
}
static int publish(struct md_inode_store *s,const struct intent *p) {
    struct mdi_node parent;
    struct timespec times[2];
    int directory=parent_directory(s,p,&parent,times);
    if (directory<0) return directory;
    struct stat source,target;
    int a=named(directory,p->name,&source),b=named(s->objects,p->object,&target);
    int r=a<0 ? a : b<0 ? b : (a && b) || (!a && !b) ? -ESTALE
        : !matches(a ? &source : &target,p) ? -ESTALE : 0;
    if (!r) r=watch_boundary(s,1);
    if (!r && a && renameat2(directory,p->name,s->objects,p->object,RENAME_NOREPLACE)) r=-errno;
    /* Promotion changes representation, not the visible parent contents. */
    if (!r && a && futimens(directory,times)) r=-errno;
    if (!r) r=mdi_sync(s,s->objects);
    if (!r) r=mdi_sync(s,directory);
    close(directory);
    if (r) return r;
    observed(s,MD_PUBLICATION_MOVED);
    r=mdi_sql(s,"BEGIN IMMEDIATE");
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(s,"INSERT INTO objects(object,kind,device,inode,backing,logical_inode,logical_device,mode,uid,gid,scope) "
        "VALUES(?1,32768,?4,?5,?1,?5,?4,?8,?6,?7,?9)",&q);
    if (!r) r=bind_intent(q,p);
    if (!r) r=mdi_bind_id(q,9,parent.scope);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q);
    if (!r) {
        struct mdi_node node;
        r=mdi_node(s,p->object,&node);
        int fd=r ? -1 : mdi_backing_open(s,&node,O_PATH);
        if (!r) r=fd<0 ? fd : mdi_leaf_import_attributes(s,&node,fd);
        if (fd>=0) close(fd);
    }
    if (!r) r=mdi_add_name(s,p->parent,p->name,p->object);
    if (!r) {
        struct mdi_node node;
        r=mdi_node(s,p->object,&node);
        if (!r) r=mdi_overlay_publish_leaf(s,&parent,&node,p->name);
    }
    if (!r) r=mdi_sql(s,"DELETE FROM native_publication WHERE slot=1");
    if (!r) observed(s,MD_PUBLICATION_STAGED);
    r=commit(s,r);
    if (!r) observed(s,MD_PUBLICATION_CATALOGUED);
    if (!r) r=watch_boundary(s,0);
    return r;
}
int mdi_publication_pending(const struct md_inode_store *s) {
    return s->publication && atomic_load_explicit(s->publication->pending,memory_order_acquire);
}
int mdi_publication_recover(struct md_inode_store *s) {
    if (!s->locked || !sqlite3_get_autocommit(s->db) || !s->publication) return -EDEADLK;
    struct intent p;
    int r=load(s,&p);
    if (r==-ENOENT) {
        if (!s->publication->inspect && mdi_publication_pending(s)) {
            r=watch_boundary(s,0);
            if (r) return r;
        }
        if (!s->publication->inspect) atomic_store_explicit(s->publication->pending,0,memory_order_release);
        return 0;
    }
    if (!r && s->publication->inspect) return -EBUSY;
    if (!r) atomic_store_explicit(s->publication->pending,1,memory_order_release);
    if (!r) r=mdi_sql(s,"PRAGMA synchronous=FULL");
    if (!r) r=publish(s,&p);
    if (!r) atomic_store_explicit(s->publication->pending,0,memory_order_release);
    int restore=mdi_sql(s,s->lifetime->temporary ? "PRAGMA synchronous=OFF" : "PRAGMA synchronous=NORMAL");
    return r ? r : restore;
}
int mdi_publication_open(struct md_inode_store *s,int prepare) {
    if (!s->locked || s->publication) return -EINVAL;
    int fd=openat(s->lifetime->root,"publication-v1.state",O_RDWR|O_CLOEXEC|O_NOFOLLOW|(prepare ? O_CREAT : 0),0600);
    if (fd<0) return -errno;
    struct stat st;
    int r=fstat(fd,&st) ? -errno : 0;
    if (!r && (!S_ISREG(st.st_mode) || st.st_nlink!=1 || (st.st_mode&0777)!=0600)) r=-ESTALE;
    if (!r && !st.st_size && prepare) { if (ftruncate(fd,sizeof(atomic_uint))) r=-errno; }
    else if (!r && st.st_size!=sizeof(atomic_uint)) r=-EIO;
    struct mdi_publication *p=r ? NULL : calloc(1,sizeof(*p));
    if (!r && !p) r=-ENOMEM;
    if (!r) {
        p->pending=mmap(NULL,sizeof(*p->pending),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        if (p->pending==MAP_FAILED) r=-errno;
        p->inspect=!prepare;
    }
    close(fd);
    if (r) { free(p); return r; }
    s->publication=p;
    /* The mapping is a live-process hint, not a durable journal. Cold admission
     * always reads the authoritative intent, even after a power cycle. */
    return mdi_publication_recover(s);
}
void mdi_publication_close(struct md_inode_store *s) {
    if (!s->publication) return;
    munmap(s->publication->pending,sizeof(*s->publication->pending));
    free(s->publication); s->publication=NULL;
}
int mdi_publication_promote(struct md_inode_store *s,const struct mdi_node *parent,
        const char *name,const struct stat *expected,struct mdi_node *out) {
    if (!s->publication || !s->locked
            || s->read_depth>1 || sqlite3_total_changes64(s->db)!=s->operation_changes) return -EDEADLK;
    /* Publication preserves the guest inode, contents and names. Exec and
     * watches may need it on read-only mounts/superblocks; only a sealed
     * backing store or an inspection owner forbids representation changes. */
    if (s->readonly || s->publication->inspect) return -EROFS;
    if (!parent || !expected || !out || parent->kind!=S_IFDIR || parent->source
            || !parent->attached || strcmp(parent->scope,s->lifetime->scope)
            || !S_ISREG(expected->st_mode) || expected->st_nlink!=1) return -EINVAL;
    int r=mdi_name_valid(name);
    struct intent p={.device=expected->st_dev,.inode=expected->st_ino};
    if (!r) r=mdi_leaf_id(expected,parent->scope,p.object);
    if (r) return r;
    strcpy(p.parent,parent->id); strcpy(p.name,name);
    struct mdi_node ignored;
    r=mdi_catalogue_lookup(s,parent->id,name,&ignored);
    if (r!=-ENOENT) return r ? r : -EEXIST;
    r=mdi_node(s,p.object,&ignored);
    if (r!=-ENOENT) return r ? r : -EEXIST;
    struct stat existing;
    r=named(s->objects,p.object,&existing);
    if (r) return r<0 ? r : -EEXIST;
    int directory=parent_directory(s,&p,&ignored,NULL);
    if (directory<0) return directory;
    int fd=openat(directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    r=fd<0 ? -errno : 0;
    struct stat st;
    if (!r && fstat(fd,&st)) r=-errno;
    if (!r && !matches(&st,&p)) r=-ESTALE;
    if (!r) r=mdi_native_stat(fd,&st);
    if (!r) { p.uid=st.st_uid; p.gid=st.st_gid; p.mode=st.st_mode&07777; }
    if (!r) r=mdi_sync(s,fd);
    if (!r) r=mdi_sync(s,directory);
    if (fd>=0) close(fd);
    close(directory);
    if (r) return r;
    int write=s->write_transaction;
    if (!sqlite3_get_autocommit(s->db)) r=mdi_sql(s,"ROLLBACK");
    if (!r) r=mdi_sql(s,"PRAGMA synchronous=FULL");
    /* Set before publishing the intent. A killed owner cannot leave its live
     * peers believing that an uncompleted native move is an ordinary lookup. */
    if (!r) atomic_store_explicit(s->publication->pending,1,memory_order_release);
    if (!r) r=mdi_sql(s,"BEGIN IMMEDIATE");
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_prepare(s,"INSERT INTO native_publication VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8)",&q);
    if (!r) r=bind_intent(q,&p);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q);
    r=commit(s,r);
    if (!r) observed(s,MD_PUBLICATION_INTENT);
    if (!r) r=publish(s,&p);
    if (!r) atomic_store_explicit(s->publication->pending,0,memory_order_release);
    int restore=mdi_sql(s,s->lifetime->temporary ? "PRAGMA synchronous=OFF" : "PRAGMA synchronous=NORMAL");
    if (!r) r=restore;
    restore=write ? mdi_sql(s,"BEGIN IMMEDIATE") : 0;
    if (!r) r=restore;
    s->operation_changes=sqlite3_total_changes64(s->db);
    if (!r) r=mdi_node(s,p.object,out);
    return r;
}
