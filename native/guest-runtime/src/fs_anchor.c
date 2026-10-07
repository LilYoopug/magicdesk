#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_lifetime.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct md_fs_anchor *md_fs_anchor_retain(struct md_fs_anchor *p) {
    if (p) atomic_fetch_add_explicit(&p->refs,1,memory_order_relaxed);
    return p;
}
void md_fs_anchor_release(struct md_fs_anchor *p) {
    if (!p || atomic_fetch_sub_explicit(&p->refs,1,memory_order_acq_rel)!=1) return;
    close(p->fd); md_mount_namespace_release(p->view);
    md_inode_lifetime_release(p->lifetime); free(p);
}
int md_fs_anchor_fd(const struct md_fs_anchor *p) { return p ? p->fd : -1; }
int md_fs_anchor_check_fd(const struct md_fs_anchor *p, int fd) {
    if (!p || fd<0) return -EINVAL;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    return st.st_dev==p->device && st.st_ino==p->inode ? 0 : -ESTALE;
}
struct md_fs_anchor *md_view_anchor_new(struct md_inode_lifetime *lifetime,
        struct md_mount_namespace *view, struct md_view_mount *mount, int fd, dev_t device, ino_t inode) {
    struct md_fs_anchor *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    atomic_init(&p->refs,1);
    p->lifetime=md_inode_lifetime_retain(lifetime); p->view=md_mount_namespace_retain(view);
    p->mount=mount; p->fd=fd; p->device=device; p->inode=inode;
    return p;
}
int md_view_anchor_check(struct md_filesystem *fs, int fd, const struct md_fs_anchor *p) {
    if (!md_inode_lifetime_same(md_inode_store_lifetime(fs->store),p->lifetime)) return -ESTALE;
    return md_fs_anchor_check_fd(p,fd);
}
void md_view_capture(struct md_filesystem *fs, struct md_mount_namespace *view,
        struct md_view_mount *mount, struct md_fs_result *out, const struct md_fs_output *output) {
    if (out->error || out->fd<0 || !output || !output->origin) return;
    int r=0;
    if (!view) r=-ENOTSUP;
    struct stat st;
    if (!r && fstat(out->fd,&st)) r=-errno;
    int fd=-1;
    if (!r) {
        char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",out->fd);
        fd=open(proc,O_PATH|O_CLOEXEC);
        if (fd<0) r=-errno;
    }
    struct md_fs_anchor *p=r ? NULL : md_view_anchor_new(md_inode_store_lifetime(fs->store),
        view,mount,fd,st.st_dev,st.st_ino);
    if (!r && !p) r=-ENOMEM;
    if (r) {
        if (fd>=0) close(fd);
        close(out->fd); out->fd=-1; out->error=r;
        if (out->open_completion.kind==MD_OPEN_PIPE) close(out->open_completion.control);
        out->open_completion=(struct md_open_completion){0};
        return;
    }
    *output->origin=p;
}
