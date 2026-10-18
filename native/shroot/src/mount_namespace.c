#include "fs_mount_internal.h"
#include "mount_graph.h"
#include "mount_topology.h"
#include "inode_lifetime.h"
#include "user_namespace.h"
#include "namespace_identity.h"
#include "native_mounts.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/* IDs belong to mount instances, not array positions or native inode numbers.
 * Never recycle an ID while retained locations may still name an older view. */
static atomic_uint next_mount_id = 1;
int md_mount_topology_order(unsigned count, const unsigned *parents, unsigned *order) {
    if (count>MD_FS_MOUNTS_MAX+1 || (count && (!parents || !order))) return -EINVAL;
    unsigned done[MD_FS_MOUNTS_MAX+1]={0}, used=0;
    for (unsigned i=0;i<count;++i) if (parents[i]>count || parents[i]==i+1) return -EINVAL;
    while (used<count) {
        unsigned before=used;
        for (unsigned i=0;i<count;++i) if (!done[i] && (!parents[i] || done[parents[i]-1])) {
            done[i]=1; order[used++]=i;
        }
        if (used==before) return -ELOOP;
    }
    return 0;
}
int md_view_topology_order(const struct md_mount_namespace *view, unsigned *order) {
    const struct md_fs_mounts *tree=view ? view->tree : NULL;
    if (!view || !order) return -EINVAL;
    unsigned count=tree ? tree->count : 0;
    if (count>MD_FS_MOUNTS_MAX) return -EINVAL;
    unsigned parents[MD_FS_MOUNTS_MAX+1]={0};
    for (unsigned i=0;i<=count;++i) {
        const struct md_view_mount *m=i ? &tree->mounts[i-1] : &view->base;
        if (!m->id) continue;
        if (!m->parent) { if (m!=view->root && !m->detached) return -EINVAL; continue; }
        if (m==view->root) return -EINVAL;
        if (m->parent==&view->base) { parents[i]=1; continue; }
        unsigned j=0;
        while (j<count && m->parent!=&tree->mounts[j]) ++j;
        if (j==count || !tree->mounts[j].id) return -EINVAL;
        parents[i]=j+2;
    }
    return md_mount_topology_order(count+1,parents,order);
}
int md_mount_id_allocate(unsigned *out) {
    unsigned next=atomic_load_explicit(&next_mount_id,memory_order_relaxed);
    do {
        if (next==UINT_MAX) return -EOVERFLOW;
    } while (!atomic_compare_exchange_weak_explicit(&next_mount_id,&next,next+1,
        memory_order_relaxed,memory_order_relaxed));
    *out=next; return 0;
}
struct md_mount_namespace *md_mount_namespace_new(void) {
    struct md_mount_namespace *n=calloc(1,sizeof(*n));
    if (n) {
        n->base=(struct md_view_mount){.source=-1,.target=-1,.backing=MD_MOUNT_INODE,.generation=1};
        n->root=&n->base;
        int r=md_mount_id_allocate(&n->base.id);
        if (!r) r=md_mount_id_allocate(&n->shm_id);
        if (!r) r=md_namespace_identity_new(&n->inode);
        if (!r) r=-pthread_mutex_init(&n->domains_lock,NULL);
        if (r) { free(n); errno=-r; return NULL; }
        r=-pthread_mutex_init(&n->tables_lock,NULL);
        if (r) { pthread_mutex_destroy(&n->domains_lock); free(n); errno=-r; return NULL; }
        atomic_init(&n->refs,1);
        atomic_init(&n->managed_paths,0);
        atomic_init(&n->detached_mounts,0);
        r=md_mount_family_new(n);
        if (r) { md_mount_namespace_release(n); errno=-r; return NULL; }
    }
    return n;
}
struct md_mount_namespace *md_mount_namespace_retain(struct md_mount_namespace *n) {
    if (n) atomic_fetch_add_explicit(&n->refs,1,memory_order_relaxed);
    return n;
}
uint64_t md_mount_namespace_inode(const struct md_mount_namespace *n) { return n->inode; }
struct md_user_namespace *md_mount_namespace_owner(const struct md_mount_namespace *n) { return n ? n->owner : NULL; }
void md_mount_namespace_set_owner(struct md_mount_namespace *n, struct md_user_namespace *owner) {
    struct md_user_namespace *old=n->owner;
    n->owner=md_user_namespace_retain(owner); md_user_namespace_release(old);
}
int md_mount_namespace_lock_inherited(struct md_mount_namespace *n) {
    struct md_mount_members members={0};
    int error=md_mount_family_capture(n,&members);
    unsigned count=n->tree ? n->tree->count : 0;
    for (unsigned i=0;!error && i<=count;++i) {
        struct md_view_mount *m=md_view_mount_node(n,i);
        if (!m->id) continue;
        m->locked=1; error=md_mount_policy_lock(&m->policy);
        if (!error && m->links.shared) {
            struct md_mount_links links={0};
            error=md_mount_links_change(&members,&m->links,MS_SLAVE,&links);
            if (!error) { md_mount_links_release(&m->links); m->links=links; }
        }
    }
    md_mount_members_release(&members);
    return error;
}
void md_view_mount_close(struct md_view_mount *mount) {
    md_mount_links_release(&mount->links);
    md_mount_policy_close(&mount->policy);
    md_inode_lifetime_release(mount->storage);
    md_pid_namespace_release(mount->pid_namespace);
    md_devpts_release(mount->devpts);
    md_cgroup_release(mount->cgroup);
    md_sysfs_release(mount->sysfs);
    md_provider_tree_release(mount->provider);
    md_ipc_namespace_release(mount->ipc_namespace);
    md_control_file_release(mount->file);
    if (mount->source>=0) close(mount->source);
    if (mount->target>=0) close(mount->target);
    *mount=(struct md_view_mount){.source=-1,.target=-1,.detached=1,.generation=mount->generation};
}
int md_view_mount_clone(struct md_view_mount *out,const struct md_view_mount *source,int target,
        struct md_view_mount *parent) {
    uint64_t generation=out->generation;
    *out=(struct md_view_mount){.source=-1,.target=-1,.generation=generation+1,
        .parent=parent,.backing=source->backing,.locked=source->locked,
        .root_providers=source->root_providers,
        .links=md_mount_links_copy(&source->links),
        .storage=md_inode_lifetime_retain(source->storage),
        .pid_namespace=md_pid_namespace_retain(source->pid_namespace),
        .devpts=md_devpts_retain(source->devpts),.cgroup=md_cgroup_retain(source->cgroup),
        .sysfs=md_sysfs_retain(source->sysfs),.provider=md_provider_tree_retain(source->provider),
        .ipc_namespace=md_ipc_namespace_retain(source->ipc_namespace),
        .file=md_control_file_retain(source->file),
        .policy={.local=md_mount_policy_flags(&source->policy)}};
    atomic_init(&out->anchors,0);
    int r=generation==UINT64_MAX ? -EOVERFLOW : md_mount_id_allocate(&out->id);
    if (!r && (out->source=fcntl(source->source,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    if (!r && (out->target=fcntl(target,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    if (!r && (fstat(out->source,&out->native) || fstat(out->target,&out->guest))) r=-errno;
    return r;
}
void md_view_mount_forget(struct md_fs_mounts *tree, struct md_view_mount *mount) {
    for (unsigned i=0;i<MD_VIEW_BUCKETS;++i) {
        struct md_view_object **p=&tree->by_id[i];
        while (*p) {
            if ((*p)->mount==mount) *p=(*p)->id_next;
            else p=&(*p)->id_next;
        }
    }
    for (unsigned i=0;i<MD_VIEW_BUCKETS;++i) {
        struct md_view_object **p=&tree->table[i];
        while (*p) {
            if ((*p)->mount!=mount) { p=&(*p)->next; continue; }
            struct md_view_object *old=*p; *p=old->next;
            close(old->fd); free(old); --tree->objects;
        }
    }
    md_view_mount_close(mount);
}
void md_mount_namespace_release(struct md_mount_namespace *n) {
    if (!n || atomic_fetch_sub_explicit(&n->refs,1,memory_order_acq_rel)!=1) return;
    md_mount_family_leave(n);
    struct md_fs_mounts *m=n->tree;
    if (m) {
        for (unsigned i=0;i<MD_VIEW_BUCKETS;++i) {
            struct md_view_object *p=m->table[i];
            while (p) { struct md_view_object *next=p->next; close(p->fd); free(p); p=next; }
        }
        for (unsigned i=0;i<m->count;++i) md_view_mount_close(&m->mounts[i]);
        free(m);
    }
    md_mount_graph_close(n->graph);
    md_user_namespace_release(n->owner);
    md_view_mount_close(&n->base);
    pthread_mutex_destroy(&n->domains_lock);
    pthread_mutex_destroy(&n->tables_lock);
    md_native_mounts_release(n->native_mounts);
    free(n->native_ids); free(n);
}
int md_mount_namespace_attached(const struct md_mount_namespace *n) {
    return n && n->tree && n->tree->count;
}
int md_mount_namespace_managed_paths(const struct md_mount_namespace *n) {
    return n && atomic_load_explicit(&n->managed_paths,memory_order_acquire);
}
const struct md_inode_mount_boundaries *md_mount_namespace_initial_boundary(const struct md_mount_namespace *n) {
    if (!n || !n->initial_boundary.count || n->root!=&n->base || n->base.source>=0
            || !n->tree || n->tree->count!=n->initial_boundary.count) return NULL;
    for (unsigned i=0;i<n->initial_boundary.count;++i) {
        const struct md_view_mount *m=&n->tree->mounts[i];
        if (m->id!=n->initial_boundary.mounts[i].id || m->detached
                || m->parent!=n->initial_boundary.mounts[i].parent
                || m->guest.st_dev!=n->initial_boundary.mounts[i].device
                || m->guest.st_ino!=n->initial_boundary.mounts[i].inode) return NULL;
    }
    return &n->initial_boundary.boundaries;
}
