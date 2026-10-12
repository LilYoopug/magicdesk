#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_lifetime.h"
#include "mount_graph.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void destroy(struct md_fd_object *object) {
    struct md_fs_anchor *p=(void *)object;
    close(p->fd);
    if (p->mount_pin>=0) close(p->mount_pin);
    if (p->mount) atomic_fetch_sub_explicit(&p->mount->anchors,1,memory_order_relaxed);
    md_mount_namespace_release(p->view);
    md_inode_lifetime_release(p->lifetime); free(p);
}
static const struct md_fd_object_type type={.destroy=destroy};
struct md_fd_object *md_fs_anchor_object(struct md_fs_anchor *p) { return p ? &p->object : NULL; }
struct md_fs_anchor *md_fs_anchor_from_object(struct md_fd_object *p) {
    return p && p->type==&type ? (void *)p : NULL;
}
struct md_fs_anchor *md_fs_anchor_retain(struct md_fs_anchor *p) {
    md_fd_object_retain(md_fs_anchor_object(p)); return p;
}
void md_fs_anchor_release(struct md_fs_anchor *p) { md_fd_object_release(md_fs_anchor_object(p)); }
int md_fs_anchor_fd(const struct md_fs_anchor *p) { return p ? p->fd : -1; }
unsigned md_fs_anchor_policy(const struct md_fs_anchor *p) {
    return !p || !p->view ? 0 : md_mount_policy_flags(p->mount ? &p->mount->policy : &p->view->base.policy);
}
void md_fs_anchor_mount_info(const struct md_fs_anchor *p,struct md_fs_info *info) {
    if (!p || !p->mount) return;
    md_fs_info_mount(info,p->mount->id,
        p->device==p->mount->native.st_dev && p->inode==p->mount->native.st_ino);
}
int md_fs_anchor_same(const struct md_fs_anchor *a, const struct md_fs_anchor *b) {
    return a && b && a->view==b->view && a->mount==b->mount
        && a->device==b->device && a->inode==b->inode
        && md_inode_lifetime_same(a->lifetime,b->lifetime);
}
int md_fs_anchor_check_fd(const struct md_fs_anchor *p, int fd) {
    if (!p || fd<0) return -EINVAL;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    return st.st_dev==p->device && st.st_ino==p->inode ? 0 : -ESTALE;
}
static struct md_fs_anchor *create(struct md_inode_lifetime *lifetime,
        struct md_mount_namespace *view, struct md_view_mount *mount, int fd, int pin, dev_t device, ino_t inode) {
    if (!mount && view) mount=&view->base;
    struct md_fs_anchor *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    md_fd_object_init(&p->object,&type);
    p->lifetime=md_inode_lifetime_retain(lifetime); p->view=md_mount_namespace_retain(view);
    p->mount=mount; p->fd=fd; p->mount_pin=pin; p->device=device; p->inode=inode;
    if (mount) atomic_fetch_add_explicit(&mount->anchors,1,memory_order_relaxed);
    return p;
}
struct md_fs_anchor *md_view_anchor_new(struct md_inode_lifetime *lifetime,
        struct md_mount_namespace *view, struct md_view_mount *mount, int fd, dev_t device, ino_t inode) {
    if (!mount && view) mount=&view->base;
    int pin=-1;
    if (mount && md_mount_graph_foreign(view)) {
        pin=md_mount_graph_acquire_pin(view,mount);
        if (pin<0) { errno=-pin; return NULL; }
    }
    struct md_fs_anchor *p=create(lifetime,view,mount,fd,pin,device,inode);
    if (!p && pin>=0) { int error=errno; close(pin); errno=error; }
    return p;
}
struct md_fs_anchor *md_view_anchor_import(struct md_inode_lifetime *lifetime,
        struct md_mount_namespace *view, struct md_view_mount *mount, int fd, int pin,
        dev_t device, ino_t inode) {
    int r=md_mount_graph_check_pin(view,pin);
    if (r) { errno=-r; return NULL; }
    return create(lifetime,view,mount,fd,pin,device,inode);
}
int md_view_anchor_check(struct md_filesystem *fs, int fd, const struct md_fs_anchor *p) {
    if (!md_inode_lifetime_same(md_inode_store_lifetime(fs->store),p->lifetime)) return -ESTALE;
    return md_fs_anchor_check_fd(p,fd);
}
int md_view_anchor_duplicate(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,struct md_fs_anchor **out) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    int copy=fcntl(fd,F_DUPFD_CLOEXEC,3);
    if (copy<0) return -errno;
    struct md_fs_anchor *origin=md_view_anchor_new(md_inode_store_lifetime(fs->store),
        view,mount,copy,st.st_dev,st.st_ino);
    if (!origin) { int error=-errno; close(copy); return error; }
    *out=origin; return 0;
}
void md_view_capture(struct md_filesystem *fs, struct md_mount_namespace *view,
        struct md_view_mount *mount, struct md_fs_result *out, const struct md_fs_output *output) {
    if (out->error || out->fd<0 || !output || !output->origin) return;
    int r=0;
    if (!view && mount) r=-EINVAL;
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
    if (!r && !p) r=-errno;
    if (r) {
        if (fd>=0) close(fd);
        close(out->fd); out->fd=-1; out->error=r;
        if (out->open_completion.kind==MD_OPEN_PIPE) close(out->open_completion.control);
        out->open_completion=(struct md_open_completion){0};
        return;
    }
    *output->origin=p;
}
