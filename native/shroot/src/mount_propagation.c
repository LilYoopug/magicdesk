#include "mount_propagation.h"
#include "fs_mount_internal.h"
#include "resource_order.h"
#include "mount_graph.h"
#include <errno.h>
#include <stdlib.h>

struct md_mount_family {
    pthread_mutex_t lock;
    unsigned count;
    struct md_mount_namespace *first;
    struct md_resource_wakeup *wakeup;
    atomic_int collect;
};
struct md_mount_group {
    atomic_uint references;
    unsigned id, foreign;
    struct md_mount_group *parent;
};
int md_mount_family_new(struct md_mount_namespace *view) {
    struct md_mount_family *f=calloc(1,sizeof(*f));
    if (!f) return -ENOMEM;
    int error=pthread_mutex_init(&f->lock,NULL);
    if (error) { free(f); return -error; }
    atomic_init(&f->collect,0);
    f->first=view; f->count=1; view->family=f; return 0;
}
void md_mount_family_leave(struct md_mount_namespace *view) {
    struct md_mount_family *f=view->family;
    if (!f) return;
    pthread_mutex_lock(&f->lock);
    struct md_mount_namespace **at=&f->first;
    while (*at && *at!=view) at=&(*at)->family_next;
    if (*at) { *at=view->family_next; --f->count; }
    int empty=!f->count;
    view->family=NULL; view->family_next=NULL;
    pthread_mutex_unlock(&f->lock);
    if (empty) { md_resource_wakeup_release(f->wakeup); pthread_mutex_destroy(&f->lock); free(f); }
}
void md_mount_family_join(struct md_mount_namespace *view,struct md_mount_namespace *source) {
    if (view->family==source->family) return;
    md_mount_family_leave(view);
    struct md_mount_family *f=source->family;
    pthread_mutex_lock(&f->lock);
    view->family=f; view->family_next=f->first; f->first=view; ++f->count;
    pthread_mutex_unlock(&f->lock);
}
int md_mount_family_capture(struct md_mount_namespace *view,struct md_mount_members *out) {
    if (!view || !view->family || !out || out->views || out->count) return -EINVAL;
    struct md_mount_family *f=view->family;
    pthread_mutex_lock(&f->lock);
    struct md_mount_namespace **views=calloc(f->count,sizeof(*views));
    unsigned count=0;
    if (views) for (struct md_mount_namespace *n=f->first;n;n=n->family_next) {
        unsigned refs=atomic_load_explicit(&n->refs,memory_order_relaxed);
        while (refs && !atomic_compare_exchange_weak_explicit(&n->refs,&refs,refs+1,
                memory_order_acquire,memory_order_relaxed)) {}
        if (refs) views[count++]=n;
    }
    pthread_mutex_unlock(&f->lock);
    if (!views) return -ENOMEM;
    *out=(struct md_mount_members){views,count}; return 0;
}
void md_mount_members_release(struct md_mount_members *members) {
    for (unsigned i=0;i<members->count;++i) md_mount_namespace_release(members->views[i]);
    free(members->views); *members=(struct md_mount_members){0};
}
void md_mount_family_wakeup(struct md_mount_namespace *view,struct md_resource_wakeup *wake) {
    if (!view || !view->family) return;
    struct md_mount_family *f=view->family;
    pthread_mutex_lock(&f->lock);
    struct md_resource_wakeup *old=f->wakeup;
    f->wakeup=md_resource_wakeup_retain(wake);
    pthread_mutex_unlock(&f->lock);
    md_resource_wakeup_release(old);
}
void md_mount_family_retire(struct md_mount_namespace *view) {
    if (!view || !view->family || !atomic_load_explicit(&view->detached_mounts,memory_order_acquire)) return;
    struct md_mount_family *f=view->family;
    if (atomic_exchange_explicit(&f->collect,1,memory_order_acq_rel)) return;
    pthread_mutex_lock(&f->lock);
    md_resource_wakeup_signal(f->wakeup);
    pthread_mutex_unlock(&f->lock);
}
int md_mount_family_collect(struct md_filesystem *fs) {
    if (!fs->mounts || !fs->mounts->family) return 0;
    struct md_mount_family *f=fs->mounts->family;
    if (!atomic_load_explicit(&f->collect,memory_order_acquire)
            || !atomic_exchange_explicit(&f->collect,0,memory_order_acq_rel)) return 0;
    struct md_mount_members members={0};
    int error=md_mount_family_capture(fs->mounts,&members);
    for (unsigned i=0;!error && i<members.count;++i) {
        struct md_mount_namespace *view=members.views[i];
        if (!atomic_load_explicit(&view->detached_mounts,memory_order_acquire)
                || md_mount_graph_foreign(view)) continue;
        struct md_filesystem selected=*fs; selected.mounts=view;
        if (view!=fs->mounts) selected.native_root=NULL;
        error=md_view_mount_collect(&selected);
    }
    md_mount_members_release(&members); return error;
}
struct md_mount_group *md_mount_group_retain(struct md_mount_group *g) {
    if (g) atomic_fetch_add_explicit(&g->references,1,memory_order_relaxed);
    return g;
}
void md_mount_group_release(struct md_mount_group *g) {
    while (g && atomic_fetch_sub_explicit(&g->references,1,memory_order_acq_rel)==1) {
        struct md_mount_group *parent=g->parent; free(g); g=parent;
    }
}
struct md_mount_group *md_mount_group_new(struct md_mount_group *master) {
    struct md_mount_group *g=calloc(1,sizeof(*g));
    if (!g) return NULL;
    int error=md_mount_id_allocate(&g->id);
    if (error) { free(g); errno=-error; return NULL; }
    atomic_init(&g->references,1); g->parent=md_mount_group_retain(master); return g;
}
static struct md_mount_group *observe(unsigned id,struct md_mount_group *master) {
    if (!id) return NULL;
    struct md_mount_group *g=calloc(1,sizeof(*g));
    if (g) {
        atomic_init(&g->references,1); g->id=id; g->foreign=1;
        g->parent=md_mount_group_retain(master);
    }
    return g;
}
int md_mount_links_observe(unsigned shared,unsigned master,unsigned unbindable,struct md_mount_links *out) {
    if ((unbindable && (shared || master)) || (shared && shared==master) || unbindable>1) return -EPROTO;
    struct md_mount_links links={.unbindable=unbindable};
    links.master=observe(master,NULL);
    if (master && !links.master) return -ENOMEM;
    links.shared=observe(shared,links.master);
    if (shared && !links.shared) { md_mount_links_release(&links); return -ENOMEM; }
    *out=links; return 0;
}
int md_mount_links_foreign(const struct md_mount_links *links) {
    return (links->shared && links->shared->foreign) || (links->master && links->master->foreign);
}
unsigned md_mount_group_id(const struct md_mount_group *g) { return g ? g->id : 0; }
struct md_mount_group *md_mount_group_parent(const struct md_mount_group *g) { return g ? g->parent : NULL; }
int md_mount_group_contains(const struct md_mount_group *g,const struct md_mount_group *ancestor) {
    if (!ancestor) return 0;
    for (;g;g=g->parent) if (g==ancestor) return 1;
    return 0;
}
struct md_mount_links md_mount_links_copy(const struct md_mount_links *links) {
    return (struct md_mount_links){md_mount_group_retain(links->shared),
        md_mount_group_retain(links->master),links->unbindable};
}
void md_mount_links_release(struct md_mount_links *links) {
    md_mount_group_release(links->shared); md_mount_group_release(links->master);
    *links=(struct md_mount_links){0};
}
struct md_mount_group *md_mount_group_live(const struct md_mount_members *members,struct md_mount_group *g,
        const struct md_mount_links *excluded) {
    for (;g;g=g->parent) for (unsigned i=0;i<members->count;++i) {
        struct md_mount_namespace *view=members->views[i];
        unsigned count=view->tree ? view->tree->count : 0;
        for (unsigned j=0;j<=count;++j) {
            const struct md_view_mount *m=md_view_mount_node(view,j);
            if (m->id && !m->detached && &m->links!=excluded && m->links.shared==g) return g;
        }
    }
    return NULL;
}
int md_mount_links_change(const struct md_mount_members *members,const struct md_mount_links *old,
        unsigned propagation,struct md_mount_links *out) {
    struct md_mount_links next={0};
    switch (propagation) {
    case MS_PRIVATE: break;
    case MS_UNBINDABLE: next.unbindable=1; break;
    case MS_SHARED:
        next=md_mount_links_copy(old); next.unbindable=0;
        if (!next.shared) {
            struct md_mount_group *master=md_mount_group_live(members,next.master,NULL);
            next.shared=md_mount_group_new(master);
            if (!next.shared) { int error=-errno; md_mount_links_release(&next); return error; }
            md_mount_group_release(next.master); next.master=md_mount_group_retain(master);
        }
        break;
    case MS_SLAVE:
        if (!old->shared) next=md_mount_links_copy(old);
        else next.master=md_mount_group_retain(md_mount_group_live(members,old->shared,old));
        break;
    default: return -EINVAL;
    }
    *out=next; return 0;
}
