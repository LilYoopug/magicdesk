#define _GNU_SOURCE
#include "file_snapshot.h"
#include "inode_store.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int md_file_snapshot_flags(unsigned flags) {
    if (flags&O_DIRECTORY) return -ENOTDIR;
    if ((flags&O_ACCMODE)!=O_RDONLY || (flags&O_TRUNC)) return -EACCES;
    if ((flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) return -EEXIST;
    return 0;
}
void md_file_snapshot_close(struct md_file_snapshot *s) {
    if (s->fd>=0) close(s->fd);
    s->fd=-1;
}
int md_file_snapshot_begin(struct md_file_snapshot *s, struct md_inode_store *store, unsigned flags) {
    if (s->fd>=0) return -EBUSY;
    int error=md_file_snapshot_flags(flags);
    if (error) return error;
    int fd=md_inode_temporary(store);
    if (fd<0) return fd;
    s->fd=fd; s->flags=flags;
    return 0;
}
int md_file_snapshot_append(struct md_file_snapshot *s, const void *data, size_t size) {
    if (s->fd<0) return -EBADF;
    while (size) {
        ssize_t n=write(s->fd,data,size);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return n ? -errno : -EIO;
        data=(const char *)data+n; size-=(size_t)n;
    }
    return 0;
}
int md_file_snapshot_finish(struct md_file_snapshot *s) {
    if (s->fd<0) return -EBADF;
    char path[64];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",s->fd);
    int fd=open(path,(s->flags&~(O_CREAT|O_EXCL|O_NOFOLLOW))|O_CLOEXEC);
    int result=fd<0 ? -errno : fd;
    md_file_snapshot_close(s);
    return result;
}
