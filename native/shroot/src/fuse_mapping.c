#define _GNU_SOURCE
#include "fuse_mapping.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

struct md_fuse_mapping { int writer,reader,error; int64_t size; };
void md_fuse_mapping_destroy(struct md_fuse_mapping *m) {
    if (!m) return;
    if (m->reader>=0) close(m->reader);
    if (m->writer>=0) close(m->writer);
    free(m);
}
static int failed(struct md_fuse_mapping *m,int error) {
    /* A confirmed daemon mutation cannot be rolled back. Stop exposing stale
     * pages if its local backing fails; existing mappings fault with SIGBUS. */
    m->error=error;
    (void)ftruncate(m->writer,0);
    return error;
}
int md_fuse_mapping_write(struct md_fuse_mapping *m,const void *data,size_t size,int64_t offset) {
    if (!m) return 0;
    if (m->error) return m->error;
    for (size_t done=0;done<size;) {
        ssize_t n=pwrite(m->writer,(const char *)data+done,size-done,offset+done);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return failed(m,n<0 ? -errno : -EIO);
        done+=(size_t)n;
    }
    if (m->size<offset+(int64_t)size) m->size=offset+size;
    return 0;
}
int md_fuse_mapping_resize(struct md_fuse_mapping *m,int64_t size) {
    if (!m) return 0;
    if (m->error) return m->error;
    if (m->size!=size && ftruncate(m->writer,size)) return failed(m,-errno);
    m->size=size; return 0;
}
int md_fuse_mapping_publish(struct md_fuse_mapping **owner,int directory,int image) {
    struct md_fuse_mapping *m=*owner;
    int error=0;
    if (!m) {
        m=calloc(1,sizeof(*m)); if (!m) return -ENOMEM;
        m->reader=m->writer=-1;
        /* Like mount contents, this needs an independently opened read-only
         * description. Shell policy can forbid reopening memfd through proc. */
        m->writer=openat(directory,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0700);
        if (m->writer<0) error=-errno;
        if (!error) {
            char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",m->writer);
            m->reader=open(path,O_RDONLY|O_CLOEXEC);
            if (m->reader<0) error=-errno;
        }
        if (error) { md_fuse_mapping_destroy(m); return error; }
    }
    struct stat st;
    if (fstat(image,&st)) error=-errno;
    else error=md_fuse_mapping_resize(m,st.st_size);
    unsigned char bytes[16384];
    for (int64_t offset=0;!error && offset<st.st_size;) {
        size_t count=st.st_size-offset<(int64_t)sizeof(bytes) ? (size_t)(st.st_size-offset) : sizeof(bytes);
        ssize_t n=pread(image,bytes,count,offset);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { error=failed(m,n<0 ? -errno : -EIO); break; }
        error=md_fuse_mapping_write(m,bytes,(size_t)n,offset); offset+=n;
    }
    if (error) { if (!*owner) md_fuse_mapping_destroy(m); return error; }
    *owner=m;
    int fd=fcntl(m->reader,F_DUPFD_CLOEXEC,3);
    return fd<0 ? -errno : fd;
}
