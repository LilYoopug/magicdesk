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
    struct md_mount_copy_request *next;
    struct md_mount_namespace *source, *copy;
    struct md_guest_domain *fs;
    int actor, cancelled, error;
};
static void dispose(struct md_mount_copy_request *r) {
    struct md_mount_copy_request **at=&r->service->requests;
    while (*at && *at!=r) at=&(*at)->next;
    if (*at) *at=r->next;
    md_mount_namespace_release(r->source);
    md_mount_namespace_release(r->copy);
    md_domain_release(r->fs);
    free(r);
}
static void run(struct md_fs_work *work, struct md_filesystem *fs, int error) {
    struct md_mount_copy_request *r=(void *)work;
    struct md_fs_location root, copied;
    struct md_fs_anchor *cwd=NULL, *next=NULL;
    md_domain_paths(r->fs,&root,&cwd);
    if (!error) {
        struct md_filesystem owner=*fs;
        owner.mounts=r->source;
        error=md_fs_mounts_copy(&owner,&root,&r->copy,&copied);
    }
    if (!error) error=md_fs_mounts_copy_cwd(r->source,r->copy,cwd,&next);
    if (!error) error=md_domain_set_root(r->fs,&copied);
    if (!error) error=md_domain_set_cwd(r->fs,next);
    if (!error) md_domain_bind_mounts(r->fs,r->copy);
    md_fs_anchor_release(next); md_fs_anchor_release(cwd);
    r->error=error;
}
static int complete(struct md_fs_work *work) {
    struct md_mount_copy_request *r=(void *)work;
    if (!r->cancelled) r->service->complete(r,r->actor,r->error);
    dispose(r); return 0;
}
int md_mount_copy_service_create(struct md_fs_worker *worker,
        void (*callback)(struct md_mount_copy_request *, int, int), struct md_mount_copy_service **out) {
    if (!worker || !callback || !out || *out) return -EINVAL;
    struct md_mount_copy_service *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->worker=worker; s->complete=callback; *out=s; return 0;
}
int md_mount_copy_submit(struct md_mount_copy_service *s, int actor,
        struct md_mount_namespace *source, struct md_guest_domain *fs, struct md_mount_copy_request **out) {
    if (!s || !source || !fs || !out || *out) return -EINVAL;
    if (md_domain_restricted(fs)) return -ENOTSUP;
    struct md_mount_copy_request *r=calloc(1,sizeof(*r));
    if (!r) return -ENOMEM;
    r->service=s; r->actor=actor; r->source=md_mount_namespace_retain(source);
    r->fs=md_domain_fork(fs,0);
    r->work=(struct md_fs_work){.run=run,.complete=complete};
    int error=r->fs ? 0 : -ENOMEM;
    if (!error) error=md_fs_worker_submit(s->worker,&r->work);
    if (error) { dispose(r); return error; }
    r->next=s->requests; s->requests=r; *out=r; return 0;
}
void md_mount_copy_cancel(struct md_mount_copy_request **owner) {
    if (owner && *owner) { (*owner)->cancelled=1; *owner=NULL; }
}
int md_mount_copy_take(struct md_mount_copy_request *r,
        struct md_mount_namespace **view, struct md_guest_domain **fs) {
    if (!r || r->error || r->cancelled || !r->copy || !view || *view || !fs || *fs) return -EINVAL;
    *view=r->copy; r->copy=NULL; *fs=r->fs; r->fs=NULL; return 0;
}
void md_mount_copy_service_destroy(struct md_mount_copy_service *s) {
    if (s) { while (s->requests) dispose(s->requests); free(s); }
}
