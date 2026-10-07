#include "fs_mount_internal.h"
#include "mount_graph.h"
#include "mount_topology.h"
#include "inode_lifetime.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/* IDs belong to mount instances, not array positions or native inode numbers.
 * Never recycle an ID while retained locations may still name an older view. */
static atomic_uint next_mount_id = 1;
int md_mount_topology_order(unsigned count, const unsigned *parents, unsigned *order) {
    if (count>MD_FS_MOUNTS_MAX || (count && (!parents || !order))) return -EINVAL;
    unsigned done[MD_FS_MOUNTS_MAX]={0}, used=0;
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
int md_view_topology_order(const struct md_fs_mounts *tree, unsigned *order) {
    if (!tree) return 0;
    if (tree->count>MD_FS_MOUNTS_MAX) return -EINVAL;
    unsigned parents[MD_FS_MOUNTS_MAX]={0};
    for (unsigned i=0;i<tree->count;++i) if (tree->mounts[i].parent) {
        unsigned j=0;
        while (j<tree->count && tree->mounts[i].parent!=&tree->mounts[j]) ++j;
        if (j==tree->count) return -EINVAL;
        parents[i]=j+1;
    }
    return md_mount_topology_order(tree->count,parents,order);
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
        int r=md_mount_id_allocate(&n->root_id);
        if (!r) r=md_mount_id_allocate(&n->shm_id);
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
    md_mount_policy_close(&n->root_policy);
    pthread_mutex_destroy(&n->domains_lock);
    free(n->native_ids); free(n);
}
int md_mount_namespace_attached(const struct md_mount_namespace *n) {
    return n && n->tree && n->tree->count;
}
