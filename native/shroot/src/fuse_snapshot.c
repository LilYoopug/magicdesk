#define _GNU_SOURCE
#include "fuse_view_internal.h"
#include "fuse_image.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

enum { IMAGE_COUNT=64 };
static const uint64_t image_bytes=256ULL*1024*1024;
struct fuse_snapshot {
    struct fuse_snapshot *previous,*next;
    struct fuse_node *node;
    struct fuse_attr attr;
    uint64_t changes;
    int fd;
};
/* The view lock protects this bounded inode cache, shared by exec and mmap.
 * Opening and authorizing a file still goes through its daemon. */
static void unlink_image(struct fuse_view *v,struct fuse_snapshot *p) {
    if (p->previous) p->previous->next=p->next; else v->images_first=p->next;
    if (p->next) p->next->previous=p->previous; else v->images_last=p->previous;
}
static void recent(struct fuse_view *v,struct fuse_snapshot *p) {
    p->previous=NULL; p->next=v->images_first;
    if (p->next) p->next->previous=p; else v->images_last=p;
    v->images_first=p;
}
static void discard(struct fuse_view *v,struct fuse_snapshot *p) {
    unlink_image(v,p); p->node->snapshot=NULL;
    v->images_bytes-=p->attr.size; --v->images_count;
    close(p->fd); free(p);
}
void md_fuse_snapshot_clear(struct fuse_view *v) {
    while (v->images_last) discard(v,v->images_last);
}
uint64_t md_fuse_snapshot_open(struct fuse_view *v,struct fuse_node *n,unsigned flags) {
    pthread_mutex_lock(&v->lock);
    if (!(flags&FOPEN_KEEP_CACHE)) {
        ++n->changes;
        if (n->snapshot) discard(v,n->snapshot);
    }
    uint64_t changes=n->changes;
    pthread_mutex_unlock(&v->lock); return changes;
}
int md_fuse_snapshot_get(struct fuse_view *v,struct fuse_node *n,const struct fuse_attr *attr,uint64_t changes) {
    pthread_mutex_lock(&v->lock);
    int result=-ENOENT;
    struct fuse_snapshot *p=n->snapshot;
    if (changes!=n->changes) result=-EAGAIN;
    else if (p) {
        if (p->changes!=changes || !md_fuse_image_same(attr,&p->attr)) discard(v,p);
        else {
            result=fcntl(p->fd,F_DUPFD_CLOEXEC,3);
            if (result<0) result=-errno;
            unlink_image(v,p); recent(v,p);
        }
    }
    pthread_mutex_unlock(&v->lock); return result;
}
int md_fuse_snapshot_store(struct fuse_view *v,struct fuse_node *n,const struct fuse_attr *attr,uint64_t changes,int fd) {
    pthread_mutex_lock(&v->lock);
    int error=changes==n->changes ? 0 : -EAGAIN;
    if (!error && attr->size<=image_bytes) {
        if (n->snapshot) discard(v,n->snapshot);
        while (v->images_count>=IMAGE_COUNT || v->images_bytes>image_bytes-attr->size)
            discard(v,v->images_last);
        struct fuse_snapshot *p=malloc(sizeof(*p));
        if (p) {
            p->fd=fcntl(fd,F_DUPFD_CLOEXEC,3);
            if (p->fd<0) free(p);
            else {
                p->node=n; p->attr=*attr; p->changes=changes; n->snapshot=p;
                v->images_bytes+=attr->size; ++v->images_count; recent(v,p);
            }
        }
    }
    pthread_mutex_unlock(&v->lock); return error;
}
