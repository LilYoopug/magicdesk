#include "mount_copy_service.h"
#include "fs_mounts.h"
#include "fs_worker.h"
#include "fs_engine.h"
#include <errno.h>
#include <stdlib.h>

struct md_mount_copy_service {
    struct md_fs_worker *worker;
    void (*complete)(struct md_mount_copy_request *, int, int);
    struct md_mount_copy_request *requests;
};
struct md_mount_copy_request {
    struct md_fs_work work;
    struct md_mount_copy_service *service;
    struct md_mount_copy_request *next, **previous;
    struct md_mount_namespace *source, *copy;
    struct md_guest_domain *fs;
    struct md_user_namespace *owner;
    int actor, cancelled, error, copy_mounts, check_root, joining;
};
static void dispose(struct md_mount_copy_request *r) {
    if (r->previous) {
        *r->previous=r->next;
        if (r->next) r->next->previous=r->previous;
    }
    md_mount_namespace_release(r->source);
    md_mount_namespace_release(r->copy);
    md_domain_release(r->fs);
    md_user_namespace_release(r->owner);
    free(r);
}
static void run(struct md_fs_work *work, struct md_filesystem *fs, int error) {
    struct md_mount_copy_request *r=(void *)work;
    if (error) { r->error=error; return; }
    if (r->joining) {
        struct md_filesystem target=*fs;
        target.mounts=r->source;
        if (!error) error=md_fs_mounts_join_context(&target,r->fs);
        if (!error) r->copy=md_mount_namespace_retain(r->source);
        r->error=error; return;
    }
    struct md_fs_location root, copied;
    struct md_fs_anchor *cwd=NULL, *next=NULL;
    md_domain_paths(r->fs,&root,&cwd);
    struct md_filesystem owner=*fs;
    owner.mounts=r->source;
    if (!error && r->check_root) {
        int initial=md_fs_root_is_mount_root(&owner,&root);
        if (initial<=0) error=initial ? initial : -EPERM;
    }
    if (!error && r->copy_mounts) {
        error=md_fs_mounts_copy(&owner,&root,&r->copy,&copied);
        if (!error && md_mount_namespace_owner(r->source)!=r->owner)
            error=md_mount_namespace_lock_inherited(r->copy);
        if (!error) md_mount_namespace_set_owner(r->copy,r->owner);
    }
    if (!error && r->copy_mounts) error=md_fs_mounts_copy_cwd(r->source,r->copy,cwd,&next);
    if (!error && r->copy_mounts) error=md_domain_set_root(r->fs,&copied);
    if (!error && r->copy_mounts) error=md_domain_set_cwd(r->fs,next);
    if (!error && r->copy_mounts) md_domain_bind_mounts(r->fs,r->copy);
    md_fs_anchor_release(next); md_fs_anchor_release(cwd);
    r->error=error;
}
static int complete(struct md_fs_work *work) {
    struct md_mount_copy_request *r=(void *)work;
    if (!r->cancelled) r->service->complete(r,r->actor,r->error);
    dispose(r); return 0;
}
static int submit(struct md_mount_copy_request *r,struct md_mount_copy_request **out) {
    struct md_mount_copy_service *s=r->service;
    r->work=(struct md_fs_work){.run=run,.complete=complete};
    int error=r->fs ? md_fs_worker_submit(s->worker,&r->work) : -ENOMEM;
    if (error) { dispose(r); return error; }
    r->next=s->requests; r->previous=&s->requests;
    if (r->next) r->next->previous=&r->next;
    s->requests=r; *out=r; return 0;
}
int md_mount_copy_service_create(struct md_fs_worker *worker,
        void (*callback)(struct md_mount_copy_request *, int, int), struct md_mount_copy_service **out) {
    if (!worker || !callback || !out || *out) return -EINVAL;
    struct md_mount_copy_service *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->worker=worker; s->complete=callback; *out=s; return 0;
}
int md_mount_copy_submit(struct md_mount_copy_service *s, int actor,
        struct md_mount_namespace *source, struct md_guest_domain *fs, struct md_user_namespace *owner,
        int copy_mounts, int check_root, struct md_mount_copy_request **out) {
    if (!s || !source || !fs || !out || *out) return -EINVAL;
    if (md_domain_restricted(fs)) return -ENOTSUP;
    struct md_mount_copy_request *r=calloc(1,sizeof(*r));
    if (!r) return -ENOMEM;
    r->service=s; r->actor=actor; r->source=md_mount_namespace_retain(source);
    r->owner=md_user_namespace_retain(owner); r->copy_mounts=!!copy_mounts; r->check_root=!!check_root;
    r->fs=md_domain_fork(fs,0);
    return submit(r,out);
}
void md_mount_copy_cancel(struct md_mount_copy_request **owner) {
    if (owner && *owner) { (*owner)->cancelled=1; *owner=NULL; }
}
int md_mount_join_submit(struct md_mount_copy_service *s, int actor,
        struct md_mount_namespace *target, struct md_mount_copy_request **out) {
    if (!s || !target || !out || *out) return -EINVAL;
    struct md_mount_copy_request *r=calloc(1,sizeof(*r));
    if (!r) return -ENOMEM;
    r->service=s; r->actor=actor; r->source=md_mount_namespace_retain(target); r->joining=1;
    r->fs=md_domain_new();
    return submit(r,out);
}
int md_mount_copy_take(struct md_mount_copy_request *r,
        struct md_mount_namespace **view, struct md_guest_domain **fs) {
    if (!r || r->error || r->cancelled || ((r->copy_mounts || r->joining) && !r->copy) || !view || *view || !fs || *fs) return -EINVAL;
    *view=r->copy; r->copy=NULL; *fs=r->fs; r->fs=NULL; return 0;
}
void md_mount_copy_service_destroy(struct md_mount_copy_service *s) {
    if (s) { while (s->requests) dispose(s->requests); free(s); }
}
