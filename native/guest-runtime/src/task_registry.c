#include "task_registry.h"
#include "task_resources.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { BUCKETS = 127 };
struct entry {
    struct entry *next;
    pid_t tid, tgid;
    struct md_identity value;
    struct md_guest_domain *fs;
    struct md_mount_namespace *mounts;
    struct md_fd_origins *files;
    struct md_pid_identity *pid;
    struct md_pid_identity *pid_group;
    struct md_cgroup_member *cgroup;
    struct md_cgroup_namespace *cgroup_namespace;
};
struct md_task_registry { pthread_mutex_t lock; pid_t owner; struct entry *entries[BUCKETS]; };
struct md_task_registry *md_task_registry_create(void) {
    struct md_task_registry *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    if (pthread_mutex_init(&r->lock, NULL)) { free(r); return NULL; }
    r->owner = getpid(); return r;
}
void md_task_registry_destroy(struct md_task_registry *r) {
    if (!r) return;
    for (unsigned i = 0; i < BUCKETS; i++) while (r->entries[i]) {
        struct entry *e = r->entries[i]; r->entries[i] = e->next;
        md_identity_release(&e->value); md_domain_unpin(e->fs);
        md_mount_namespace_release(e->mounts); md_fd_origins_unpin(e->files);
        md_pid_identity_release(e->pid); md_pid_identity_release(e->pid_group);
        md_cgroup_member_depart(e->cgroup,e->tid); md_cgroup_member_release(e->cgroup);
        md_cgroup_namespace_release(e->cgroup_namespace); free(e);
    }
    pthread_mutex_destroy(&r->lock); free(r);
}
int md_task_registry_publish(struct md_task_registry *r, pid_t tid, pid_t tgid,
        const struct md_identity *v, const struct md_task_resources *resources) {
    if (!r) return 0;
    if (tid <= 0 || tgid <= 0) return -EINVAL;
    struct md_guest_domain *fs=resources ? resources->fs : NULL;
    struct md_mount_namespace *mounts=resources ? resources->mounts : NULL, *old_mounts=NULL;
    struct md_guest_domain *old_fs=NULL;
    struct md_fd_origins *files=resources ? resources->files : NULL, *old_files=NULL;
    struct md_pid_identity *pid=resources ? resources->pid : NULL, *old_pid=NULL;
    struct md_pid_identity *group=resources ? resources->pid_group : NULL, *old_group=NULL;
    struct md_cgroup_member *cgroup=resources ? resources->cgroup : NULL, *old_cgroup=NULL;
    struct md_cgroup_namespace *cgroup_ns=resources ? resources->cgroup_namespace : NULL, *old_cgroup_ns=NULL;
    unsigned bucket = (unsigned)tid % BUCKETS;
    pthread_mutex_lock(&r->lock);
    struct entry *e = r->entries[bucket];
    while (e && e->tid != tid) e = e->next;
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e) { pthread_mutex_unlock(&r->lock); return -ENOMEM; }
        e->tid = tid; e->next = r->entries[bucket]; r->entries[bucket] = e;
    }
    if (e->fs != fs) { md_domain_pin(fs); old_fs=e->fs; e->fs=fs; }
    if (e->mounts != mounts) {
        old_mounts=e->mounts; e->mounts=md_mount_namespace_retain(mounts);
    }
    if (e->files!=files) { old_files=e->files; e->files=md_fd_origins_pin(files); }
    if (e->pid!=pid) { old_pid=e->pid; e->pid=md_pid_identity_retain(pid); }
    if (e->pid_group!=group) { old_group=e->pid_group; e->pid_group=md_pid_identity_retain(group); }
    if (e->cgroup!=cgroup) { old_cgroup=e->cgroup; e->cgroup=md_cgroup_member_retain(cgroup); }
    if (e->cgroup_namespace!=cgroup_ns) {
        old_cgroup_ns=e->cgroup_namespace; e->cgroup_namespace=md_cgroup_namespace_retain(cgroup_ns);
    }
    md_cgroup_member_publish(cgroup,tid,tgid,pid,group);
    if (e->tgid == tgid && !memcmp(&e->value.uid, &v->uid, sizeof(v->uid))
            && !memcmp(&e->value.gid, &v->gid, sizeof(v->gid))
            && !memcmp(&e->value.caps, &v->caps, sizeof(v->caps))
            && e->value.no_new_privs == v->no_new_privs && e->value.groups == v->groups
            && e->value.user_namespace == v->user_namespace) {
        goto published;
    }
    struct md_identity next = md_identity_copy(v);
    md_identity_release(&e->value); e->value = next; e->tgid = tgid;
published:
    pthread_mutex_unlock(&r->lock);
    md_domain_unpin(old_fs); md_mount_namespace_release(old_mounts);
    md_fd_origins_unpin(old_files);
    md_pid_identity_release(old_pid);
    md_pid_identity_release(old_group);
    md_cgroup_member_depart(old_cgroup,tid); md_cgroup_member_release(old_cgroup);
    md_cgroup_namespace_release(old_cgroup_ns);
    return 0;
}
void md_task_registry_forget(struct md_task_registry *r, pid_t tid) {
    if (!r || tid <= 0) return;
    pthread_mutex_lock(&r->lock);
    struct entry **slot = &r->entries[(unsigned)tid % BUCKETS];
    while (*slot && (*slot)->tid != tid) slot = &(*slot)->next;
    struct entry *e = *slot;
    if (e) *slot = e->next;
    pthread_mutex_unlock(&r->lock);
    if (e) {
        md_identity_release(&e->value); md_domain_unpin(e->fs);
        md_mount_namespace_release(e->mounts); md_fd_origins_unpin(e->files);
        md_pid_identity_release(e->pid); md_pid_identity_release(e->pid_group);
        md_cgroup_member_depart(e->cgroup,e->tid); md_cgroup_member_release(e->cgroup);
        md_cgroup_namespace_release(e->cgroup_namespace); free(e);
    }
}
int md_task_registry_read(struct md_task_registry *r, pid_t tid, pid_t peer,
        struct md_task_snapshot *out) {
    *out=(struct md_task_snapshot){0};
    if (!r || tid <= 0) return -ESRCH;
    pthread_mutex_lock(&r->lock);
    struct entry *e = r->entries[(unsigned)tid % BUCKETS];
    while (e && e->tid != tid) e = e->next;
    int error = !e ? -ESRCH : peer && peer != r->owner && peer != e->tgid ? -EPERM : 0;
    if (!error) {
        out->tid=e->tid; out->tgid=e->tgid;
        out->identity=md_identity_copy(&e->value);
        out->fs=e->fs; md_domain_pin(out->fs);
        md_domain_paths(e->fs,&out->root,&out->cwd);
        out->mounts=md_mount_namespace_retain(e->mounts);
        out->files=md_fd_origins_pin(e->files);
        out->pid=md_pid_identity_retain(e->pid);
        out->pid_group=md_pid_identity_retain(e->pid_group);
        out->cgroup=md_cgroup_member_retain(e->cgroup);
        out->cgroup_namespace=md_cgroup_namespace_retain(e->cgroup_namespace);
    }
    pthread_mutex_unlock(&r->lock); return error;
}
void md_task_snapshot_release(struct md_task_snapshot *snapshot) {
    md_identity_release(&snapshot->identity);
    md_domain_unpin(snapshot->fs);
    md_mount_namespace_release(snapshot->mounts);
    md_fd_origins_unpin(snapshot->files);
    md_fs_anchor_release(snapshot->cwd);
    md_pid_identity_release(snapshot->pid);
    md_pid_identity_release(snapshot->pid_group);
    md_cgroup_member_release(snapshot->cgroup);
    md_cgroup_namespace_release(snapshot->cgroup_namespace);
    *snapshot=(struct md_task_snapshot){0};
}
