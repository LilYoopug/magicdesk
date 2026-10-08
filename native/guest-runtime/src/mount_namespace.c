#include "fs_mount_internal.h"
#include "mount_graph.h"
#include "mount_topology.h"
#include "inode_lifetime.h"
#include "user_namespace.h"
#include "namespace_identity.h"
#include <errno.h>
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
        if (!m->parent) { if (m!=view->root) return -EINVAL; continue; }
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
        atomic_init(&n->refs,1);
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
    int error=md_mount_policy_lock(&n->base.policy);
    n->base.locked=1;
    for (unsigned i=0;!error && n->tree && i<n->tree->count;++i)
        if (n->tree->mounts[i].id) {
            n->tree->mounts[i].locked=1;
            error=md_mount_policy_lock(&n->tree->mounts[i].policy);
        }
    return error;
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
    md_mount_policy_close(&mount->policy);
    md_inode_lifetime_release(mount->storage);
    if (mount->source>=0) close(mount->source);
    if (mount->target>=0) close(mount->target);
    *mount=(struct md_view_mount){.source=-1,.target=-1,.detached=1,.generation=mount->generation};
}
void md_mount_namespace_release(struct md_mount_namespace *n) {
    if (!n || atomic_fetch_sub_explicit(&n->refs,1,memory_order_acq_rel)!=1) return;
    struct md_fs_mounts *m=n->tree;
    if (m) {
        for (unsigned i=0;i<MD_VIEW_BUCKETS;++i) {
            struct md_view_object *p=m->table[i];
            while (p) { struct md_view_object *next=p->next; close(p->fd); free(p); p=next; }
        }
        for (unsigned i=0;i<m->count;++i) {
            md_mount_policy_close(&m->mounts[i].policy);
            md_inode_lifetime_release(m->mounts[i].storage);
            if (m->mounts[i].source>=0) close(m->mounts[i].source);
            if (m->mounts[i].target>=0) close(m->mounts[i].target);
        }
        free(m);
    }
    md_mount_graph_close(n->graph);
    md_user_namespace_release(n->owner);
    if (n->base.source>=0) close(n->base.source);
    if (n->base.target>=0) close(n->base.target);
    md_mount_policy_close(&n->base.policy);
    pthread_mutex_destroy(&n->domains_lock);
    free(n->native_ids); free(n);
}
int md_mount_namespace_attached(const struct md_mount_namespace *n) {
    return n && n->tree && n->tree->count;
}
