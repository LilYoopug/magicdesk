#define _GNU_SOURCE
#include "fuse_image.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct md_fuse_image {
    struct md_fuse_session *session;
    struct md_fuse_request *request;
    struct md_identity identity;
    struct fuse_attr attributes;
    uint64_t node,handle,offset;
    uint32_t pid,requested;
    int fd,checking;
};
int md_fuse_image_same(const struct fuse_attr *a,const struct fuse_attr *b) {
    return a->size==b->size && a->mtime==b->mtime && a->mtimensec==b->mtimensec
        && a->ctime==b->ctime && a->ctimensec==b->ctimensec && a->mode==b->mode;
}
void md_fuse_image_destroy(struct md_fuse_image *p) {
    if (!p) return;
    md_fuse_request_cancel(p->request); md_fuse_request_release(p->request);
    md_fuse_session_release(p->session); md_identity_release(&p->identity);
    if (p->fd>=0) close(p->fd);
    free(p);
}
int md_fuse_image_new(struct md_fuse_session *session,const struct md_identity *identity,uint32_t pid,
        uint64_t node,uint64_t handle,const struct fuse_attr *attr,struct md_fuse_image **out) {
    if (!S_ISREG(attr->mode) || attr->size>INT64_MAX) return -EACCES;
    struct md_fuse_image *p=calloc(1,sizeof(*p));
    if (!p) return -ENOMEM;
    p->fd=-1; p->session=md_fuse_session_retain(session); p->identity=md_identity_copy(identity);
    p->node=node; p->handle=handle; p->attributes=*attr; p->pid=pid;
    p->fd=syscall(SYS_memfd_create,"shroot-fuse-image",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    /* Keep the kernel's executable memfd mode. Android may permit creating and
     * sealing this object while denying chmod; guest permissions were checked
     * against the FUSE inode, and seals prevent later mutation. */
    int error=p->fd<0 ? -errno : 0;
    if (error) md_fuse_image_destroy(p); else *out=p;
    return error;
}
int md_fuse_image_ready(struct md_fuse_image *p) {
    return p->request ? md_fuse_request_ready(p->request) : 1;
}
int md_fuse_image_advance(struct md_fuse_image *p,struct md_resource_wakeup *wake) {
    if (p->request) {
        union { unsigned char bytes[MD_FUSE_IO_SIZE]; struct fuse_attr_out attr; } reply;
        long n=md_fuse_request_result(p->request,&reply,sizeof(reply));
        if (n<0) return n;
        md_fuse_request_release(p->request); p->request=NULL;
        if (p->checking) {
            if (n!=sizeof(reply.attr)) return -EPROTO;
            const struct fuse_attr *a=&reply.attr.attr,*b=&p->attributes;
            if (!md_fuse_image_same(a,b)) return -EAGAIN;
            if (fcntl(p->fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)) return -errno;
            int fd=p->fd; p->fd=-1; return fd;
        }
        if (!n || n>p->requested) return -EIO;
        size_t done=0;
        while (done<(size_t)n) {
            ssize_t written=pwrite(p->fd,reply.bytes+done,(size_t)n-done,p->offset+done);
            if (written<0 && errno==EINTR) continue;
            if (written<=0) return written ? -errno : -EIO;
            done+=(size_t)written;
        }
        p->offset+=(size_t)n;
    }
    int error;
    if (p->offset==p->attributes.size) {
        struct fuse_getattr_in in={.getattr_flags=FUSE_GETATTR_FH,.fh=p->handle};
        p->checking=1;
        error=md_fuse_session_request(p->session,&p->identity,p->pid,FUSE_GETATTR,p->node,
            &in,sizeof(in),sizeof(struct fuse_attr_out),0,wake,&p->request);
    } else {
        uint64_t remaining=p->attributes.size-p->offset;
        p->requested=md_fuse_session_read_size(p->session);
        if (remaining<p->requested) p->requested=(uint32_t)remaining;
        struct fuse_read_in in={.fh=p->handle,.offset=p->offset,.size=p->requested,.flags=O_RDONLY};
        error=md_fuse_session_request(p->session,&p->identity,p->pid,FUSE_READ,p->node,
            &in,sizeof(in),p->requested,0,wake,&p->request);
    }
    return error ? error : -EINPROGRESS;
}
