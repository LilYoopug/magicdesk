#define _GNU_SOURCE
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

static int refill(struct md_inode_store *s) {
    char ids[MDI_RESERVE_BATCH][33];
    int r=0;
    unsigned count=0;
    for (;count<MDI_RESERVE_BATCH && !r;++count) {
        r=mdi_random_id(ids[count]);
        int fd=r ? -1 : openat(s->objects,ids[count],O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
        if (!r && fd<0) {
            r=-errno;
            if (count && (r==-ENOSPC || r==-EDQUOT)) { r=0; break; }
        }
        if (!r) r=mdi_sync(s,fd);
        if (fd>=0 && close(fd) && !r) r=-errno;
    }
    /* Persist every dentry before any inventory row can reach the WAL, even
     * through cache spill or an unrelated checkpoint. Failed refills orphan
     * only unpublished files; exclusive maintenance can collect them. */
    if (!r) r=mdi_sync(s,s->objects);
    for (unsigned i=0;i<count && !r;++i) {
        sqlite3_stmt *q=NULL;
        r=mdi_query_acquire(s,MDI_RESERVE_ADD,&q);
        if (!r) r=mdi_bind_id(q,1,ids[i]);
        if (!r) r=mdi_sql_error(mdi_step(s,q));
        r=mdi_query_release(q,r);
    }
    return r;
}
static int first(struct md_inode_store *s,char id[33]) {
    sqlite3_stmt *q=NULL;
    int r=mdi_query_acquire(s,MDI_RESERVE_FIRST,&q);
    if (!r) {
        int rc=mdi_step(s,q);
        if (rc==SQLITE_DONE) r=-ENOENT;
        else if (rc!=SQLITE_ROW) r=mdi_sql_failure(rc);
        else {
            const char *text=(const char *)sqlite3_column_text(q,0);
            if (!text || sqlite3_column_bytes(q,0)!=32 || strspn(text,"0123456789abcdef")!=32) r=-EIO;
            else memcpy(id,text,33);
        }
    }
    return mdi_query_release(q,r);
}
static int clear_attributes(int fd) {
    char names[65536];
    ssize_t size=flistxattr(fd,names,sizeof(names));
    if (size<0) return errno==ENOTSUP ? 0 : -errno;
    for (ssize_t i=0;i<size;) {
        size_t n=strnlen(names+i,(size_t)(size-i));
        if (!n || n==(size_t)(size-i)) return -EIO;
        /* The host owns its SELinux label, not a previous logical guest file. */
        if (strcmp(names+i,"security.selinux") && fremovexattr(fd,names+i)) return -errno;
        i+=(ssize_t)n+1;
    }
    return 0;
}
int mdi_reserve_file(struct md_inode_store *s,char id[33],int flags,mode_t mode) {
    int r=first(s,id);
    if (r==-ENOENT) { r=refill(s); if (!r) r=first(s,id); }
    /* A lost, unsynced claim may reappear after power failure. Reset contents,
     * attributes and times before handing it out again. Committed claims and
     * retained/unlinked backings are absent from this inventory. */
    if (!r && fchmodat(s->objects,id,0600,0)) r=-errno;
    int reset=r ? -1 : openat(s->objects,id,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if (!r && reset<0) r=-errno;
    struct stat st;
    if (!r && fstat(reset,&st)) r=-errno;
    if (!r && (!S_ISREG(st.st_mode) || st.st_nlink!=1)) r=-EIO;
    if (!r && ftruncate(reset,0)) r=-errno;
    if (!r) r=clear_attributes(reset);
    if (!r && futimens(reset,NULL)) r=-errno;
    int fd=r ? -1 : openat(s->objects,id,(flags&~(O_CREAT|O_EXCL|O_TRUNC))|O_CLOEXEC|O_NOFOLLOW);
    if (!r && fd<0) r=-errno;
    if (!r && fchmod(reset,mode)) r=-errno;
    if (reset>=0) close(reset);
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_query_acquire(s,MDI_RESERVE_TAKE,&q);
    if (!r) r=mdi_bind_id(q,1,id);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    r=mdi_query_release(q,r);
    if (r && fd>=0) close(fd);
    return r ? r : fd;
}
