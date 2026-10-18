#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_storage.h"
#include "mount_graph.h"
#include "mount_topology.h"
#include <errno.h>
#include <string.h>

static unsigned node_index(const struct md_mount_namespace *view, const struct md_view_mount *mount) {
    return mount==&view->base ? 0 : (unsigned)(mount-view->tree->mounts)+1;
}

static int detach(struct md_filesystem *fs, const unsigned *removed) {
    struct md_mount_namespace *view=fs->mounts;
    struct md_fs_mounts *tree=view->tree;
    struct md_view_mount base=view->base, next[MD_FS_MOUNTS_MAX];
    unsigned count=tree ? tree->count : 0;
    if (count) memcpy(next,tree->mounts,count*sizeof(*next));
    if (removed[0]) { base.detached=1; base.links=(struct md_mount_links){0}; }
    for (unsigned i=0;i<count;++i) if (removed[i+1]) {
        next[i].detached=1; next[i].links=(struct md_mount_links){0};
    }
    struct md_mount_layout layout={.base=&base,.root=view->root,.entries=next,.count=count};
    /* Foreign readers can derive deletion from the same retained store. They
     * cannot publish topology, and never gain authority over the owner graph. */
    int r=md_mount_graph_foreign(view) ? 0 : md_mount_graph_update(view,&layout);
    if (!r) {
        atomic_store_explicit(&view->detached_mounts,1,memory_order_release);
        view->base.detached=base.detached;
        if (removed[0]) md_mount_links_release(&view->base.links);
        for (unsigned i=0;i<count;++i) {
            tree->mounts[i].detached=next[i].detached;
            if (removed[i+1]) md_mount_links_release(&tree->mounts[i].links);
        }
        md_mount_family_retire(view);
    }
    return r;
}

int md_view_mount_detach(struct md_filesystem *fs, const struct md_view_mount *root) {
    if (md_mount_graph_foreign(fs->mounts)) return -EPERM;
    unsigned removed[MD_FS_MOUNTS_MAX+1]={0}, order[MD_FS_MOUNTS_MAX+1];
    int r=md_view_topology_order(fs->mounts,order);
    if (r) return r;
    unsigned count=fs->mounts->tree ? fs->mounts->tree->count : 0;
    for (unsigned n=0;n<=count;++n) {
        unsigned i=order[n];
        const struct md_view_mount *m=md_view_mount_node(fs->mounts,i);
        removed[i]=m==root || (m->parent && removed[node_index(fs->mounts,m->parent)]);
    }
    return detach(fs,removed);
}

int md_view_mount_reconcile(struct md_filesystem *fs) {
    struct md_mount_namespace *view=fs->mounts;
    if (!view || !view->tree) return 0;
    unsigned removed[MD_FS_MOUNTS_MAX+1]={0}, order[MD_FS_MOUNTS_MAX+1], changed=0;
    int r=md_view_topology_order(view,order);
    for (unsigned n=0;!r && n<=view->tree->count;++n) {
        unsigned i=order[n];
        const struct md_view_mount *m=md_view_mount_node(view,i);
        if (!m->id || m->detached || !m->parent) continue;
        if (removed[node_index(view,m->parent)]) removed[i]=1;
        else {
            struct stat st;
            if (md_view_inode(m->parent)) {
                struct md_inode_store *store;
                r=md_fs_storage_get(fs,m->parent,&store);
                if (!r) r=md_inode_fstat(store,m->target,&st);
            } else r=fstat(m->target,&st) ? -errno : 0;
            if (!r) removed[i]=!st.st_nlink;
        }
        changed|=removed[i];
    }
    return r ? r : changed ? detach(fs,removed) : 0;
}
