#define _GNU_SOURCE
#include "inode_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Cookies remain in the shared directory OFD, including across cold SCM
 * transfer. Small native cookies encode directly; large opaque filesystem
 * cookies use a store-wide mapping, never a process-local cursor. Keep the
 * public offset below INT32_MAX: f2fs bounds directory seeks by its maximum
 * file size even though the OFD itself has a signed 64-bit position. */
#define NATIVE_BASE (INT64_C(1)<<30)
#define NATIVE_DIRECT (INT64_C(1)<<29)
#define NATIVE_MAPPED (NATIVE_BASE+NATIVE_DIRECT)
static int cookie(struct md_inode_store *s,const char *parent,int64_t value,int encode,int64_t *out) {
    if (encode && value<0) return -EIO;
    if (encode && value<NATIVE_DIRECT) { *out=NATIVE_BASE+value; return 0; }
    if (!encode && value<NATIVE_MAPPED) { *out=value-NATIVE_BASE; return 0; }
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,encode
        ? "SELECT cookie FROM native_cookies WHERE parent=?1 AND position=?2"
        : "SELECT position FROM native_cookies WHERE parent=?1 AND cookie=?2",&q);
    if (!r) r=mdi_bind_id(q,1,parent);
    if (!r) r=mdi_sql_error(sqlite3_bind_int64(q,2,encode ? value : value-NATIVE_MAPPED));
    if (!r) {
        int rc=mdi_step(s,q);
        if (rc!=SQLITE_ROW) r=rc==SQLITE_DONE ? -ENOENT : mdi_sql_failure(rc);
        else {
            int64_t n=sqlite3_column_int64(q,0);
            if (n<0 || (encode && n>=INT32_MAX-NATIVE_MAPPED)) r=-EOVERFLOW;
            else *out=encode ? NATIVE_MAPPED+n : n;
        }
    }
    sqlite3_finalize(q);
    if (r==-ENOENT && encode) {
        r=mdi_prepare(s,"INSERT INTO native_cookies(parent,position) VALUES(?1,?2)",&q);
        if (!r) r=mdi_bind_id(q,1,parent);
        if (!r) r=mdi_sql_error(sqlite3_bind_int64(q,2,value));
        if (!r) r=mdi_sql_error(mdi_step(s,q));
        sqlite3_finalize(q);
        if (!r) {
            int64_t n=sqlite3_last_insert_rowid(s->db);
            if (n<=0 || n>=INT32_MAX-NATIVE_MAPPED) r=-EOVERFLOW;
            else *out=NATIVE_MAPPED+n;
        }
    }
    return r==-ENOENT ? -EINVAL : r;
}
static int directory(struct md_inode_store *s, int fd, struct mdi_node *node, int require_attached) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -errno;
    if (flags & O_PATH) return -EBADF;
    int attached = 1;
    int r = require_attached ? mdi_fd_membership(s, fd, node, &attached) : mdi_fd(s, fd, node);
    return r ? r : node->kind != S_IFDIR ? -ENOTDIR : attached ? 0 : -ENOENT;
}
static int native_entries(struct md_inode_store *s,const struct mdi_node *node,void *out,
        size_t capacity,size_t *used,int64_t *offset) {
    if (node->mode<0) return 0;
    int64_t position;
    int r=cookie(s,node->id,*offset,0,&position);
    int fd=r ? -1 : mdi_backing_open(s,node,O_RDONLY|O_DIRECTORY);
    if (!r && fd<0) r=fd;
    if (!r && lseek(fd,position,SEEK_SET)!=position) r=-errno;
    unsigned char buffer[16384] __attribute__((aligned(8)));
    while (!r) {
        ssize_t count=syscall(SYS_getdents64,fd,buffer,sizeof(buffer));
        if (count<0) { r=-errno; break; }
        if (!count) break;
        for (size_t at=0;!r && at<(size_t)count;) {
            struct md_directory_entry entry;
            size_t length=md_directory_record_read(buffer+at,(size_t)count-at,&entry);
            if (!length || length>NAME_MAX) { r=-EIO; break; }
            const char *name=(const char *)buffer+at+offsetof(struct md_directory_entry,name);
            at+=entry.size;
            if (!strcmp(name,".") || !strcmp(name,"..")) continue;
            int regular=entry.type==DT_REG;
            if (entry.type==DT_UNKNOWN) {
                struct stat st;
                if (fstatat(fd,name,&st,AT_SYMLINK_NOFOLLOW)) { r=-errno; break; }
                regular=S_ISREG(st.st_mode);
            }
            if (!regular) { r=-EIO; break; }
            size_t size=md_directory_record_size(length);
            if (capacity-*used<size) {
                if (!*used) r=-EINVAL;
                goto done;
            }
            int64_t next;
            r=cookie(s,node->id,entry.next,1,&next);
            if (!r) {
                *used+=md_directory_record_write((char *)out+*used,capacity-*used,name,length,entry.inode,next,DT_REG);
                *offset=next;
            }
        }
    }
done:
    if (fd>=0) close(fd);
    return r;
}
int64_t md_inode_seekdir(struct md_inode_store *s, int fd, int64_t offset, int whence) {
    if (whence != SEEK_SET && whence != SEEK_CUR) return -EINVAL;
    int r = mdi_begin(s, 0); if (r) return r;
    struct mdi_node node; r = directory(s, fd, &node, 0);
    r = mdi_finish(s, r);
    if (r) return r;
    off_t result = lseek(fd, offset, whence);
    return result < 0 ? -errno : result;
}
static ssize_t getdents(struct md_inode_store *s, int fd, void *out, size_t capacity,
        int (*deliver)(void *, const void *, size_t), void *context, int64_t *next) {
    if (!out) return -EFAULT;
    if (capacity > INT_MAX) return -EINVAL;
    int r = mdi_begin(s, 0); if (r) return r;
    struct mdi_node node;
    r = directory(s, fd, &node, 1);
    int64_t offset = 0;
    if (!r && (offset = lseek(fd, 0, SEEK_CUR)) < 0) r = -errno;
    size_t used = 0;
    while (!r && offset < 2) {
        struct mdi_node entry = node;
        if (offset == 1) r = mdi_node(s, !strcmp(node.id, mdi_root(s)) ? node.id : node.parent, &entry);
        if (r) break;
        size_t n = md_directory_record_write((char *)out + used, capacity-used, offset ? ".." : ".",
            offset ? 2 : 1, entry.logical_inode, offset+1, DT_DIR);
        if (!n) { if (!used) r = -EINVAL; break; }
        used += n; ++offset;
    }
    sqlite3_stmt *q = NULL;
    if (!r && offset >= 2 && offset<NATIVE_BASE) r = mdi_query_acquire(s, MDI_READDIR, &q);
    if (!r && q) r = mdi_bind_id(q, 1, node.id);
    if (!r && q) r = mdi_sql_error(sqlite3_bind_int64(q, 2, offset-2));
    while (!r && q) {
        int rc = mdi_step(s, q);
        if (rc == SQLITE_DONE) { if (node.mode>=0) offset=NATIVE_BASE; break; }
        if (rc != SQLITE_ROW) { r = mdi_sql_failure(rc); break; }
        int length = sqlite3_column_bytes(q, 1);
        const char *name = sqlite3_column_blob(q, 1);
        if (!name || length < 1 || length > NAME_MAX || memchr(name, 0, (size_t)length)
                || memchr(name, '/', (size_t)length)) { r = -EIO; break; }
        int64_t next = sqlite3_column_int64(q, 0) + 2;
        if (next <= offset || next>=NATIVE_BASE) { r = -EOVERFLOW; break; }
        size_t n = md_directory_record_write((char *)out + used, capacity-used, name, (size_t)length,
            (uint64_t)sqlite3_column_int64(q, 2), next, (uint8_t)(sqlite3_column_int(q, 3) >> 12));
        if (!n) { if (!used) r = -EINVAL; break; }
        used += n; offset = next;
    }
    r = mdi_query_release(q, r);
    if (!r && offset>=NATIVE_BASE && used<capacity) r=native_entries(s,&node,out,capacity,&used,&offset);
    r = mdi_finish(s, r);
    if (!r && deliver) r = deliver(context, out, used);
    if (!r && next) *next=offset;
    else if (!r && used && lseek(fd, offset, SEEK_SET) != offset) r = -EIO;
    return r ? r : (ssize_t)used;
}
ssize_t md_inode_getdents_prepare(struct md_inode_store *s, int fd, void *out, size_t capacity, int64_t *next) {
    if (!next) return -EINVAL;
    return getdents(s,fd,out,capacity,NULL,NULL,next);
}
ssize_t md_inode_getdents_deliver(struct md_inode_store *s, int fd, void *out, size_t capacity,
        int (*deliver)(void *, const void *, size_t), void *context) {
    return getdents(s,fd,out,capacity,deliver,context,NULL);
}
ssize_t md_inode_getdents(struct md_inode_store *s, int fd, void *out, size_t capacity) {
    return md_inode_getdents_deliver(s, fd, out, capacity, NULL, NULL);
}
