#define _GNU_SOURCE
#include "fs_mount_propagation.h"
#include "fs_mount_internal.h"
#include "mount_graph.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct draft {
    struct md_mount_namespace *view;
    struct md_view_mount *base;
    struct md_view_mount *entries;
    unsigned count;
    unsigned char created[MD_FS_MOUNTS_MAX];
};
static struct md_view_mount *node(struct md_view_mount *base,struct md_view_mount *entries,unsigned n) {
    return n ? &entries[n-1] : base;
}
struct mapping {
    struct md_mount_group *parent,*child;
    unsigned source;
    struct mapping *next;
};
static int vacant(struct draft *d) {
    for (unsigned i=0;i<d->count;++i)
        if (!d->entries[i].id && d->entries[i].generation<UINT64_MAX) return (int)i;
    if (d->count==MD_FS_MOUNTS_MAX) return -ENOSPC;
    unsigned n=d->count++;
    d->entries[n]=(struct md_view_mount){.source=-1,.target=-1}; return (int)n;
}
static int group(struct mapping **map,struct md_mount_group *parent,unsigned source,
        struct md_mount_group **out) {
    for (struct mapping *m=*map;m;m=m->next)
        if (m->parent==parent && m->source==source) { *out=m->child; return 0; }
    if (!parent) return -EXDEV;
    struct md_mount_group *upstream=NULL;
    int r=group(map,md_mount_group_parent(parent),source,&upstream);
    if (r) return r;
    struct mapping *m=calloc(1,sizeof(*m));
    if (!m) return -ENOMEM;
    m->child=md_mount_group_new(upstream);
    if (!m->child) { r=-errno; free(m); return r; }
    m->parent=parent; m->source=source; m->next=*map; *map=m; *out=m->child; return 0;
}
static int covered(struct md_filesystem *fs,const struct md_view_mount *parent,int target) {
    if (parent->source<0) return 1;
    char root[PATH_MAX],path[PATH_MAX];
    int r=md_view_backing_path(fs,parent->source,parent,root,sizeof(root));
    if (!r) r=md_view_backing_path(fs,target,parent,path,sizeof(path));
    if (r) return r;
    size_t n=strlen(root);
    return !strncmp(root,path,n) && (n==1 || !path[n] || path[n]=='/');
}
static int replica(struct md_filesystem *fs,struct draft *d,struct md_view_mount *parent,
        struct md_mount_namespace *source_view,const struct md_view_mount *entries,
        const struct md_view_mount *base,const unsigned *slots,unsigned created,unsigned root,struct mapping **map) {
    unsigned copied[MD_FS_MOUNTS_MAX+1];
    for (unsigned i=0;i<created;++i) {
        unsigned source=slots[i];
        const struct md_view_mount *a=source ? &entries[source-1] : base;
        struct md_view_mount *owner=parent;
        if (source!=root) {
            unsigned j=0;
            while (j<i && a->parent!=md_view_mount_node(source_view,slots[j])) ++j;
            if (j==i) return -EINVAL;
            owner=&d->view->tree->mounts[copied[j]];
        }
        int index=vacant(d);
        if (index<0) return index;
        copied[i]=(unsigned)index; d->created[index]=1;
        struct md_view_mount *b=&d->entries[index];
        int r=md_view_mount_clone(b,a,a->target,owner);
        if (r) return r;
        if (md_view_file_cycle(b->file,d->view)) return -EINVAL;
        struct md_mount_group *g=NULL;
        r=group(map,parent->links.shared ? parent->links.shared : parent->links.master,source,&g);
        if (r) return r;
        md_mount_links_release(&b->links);
        b->links=parent->links.shared
            ? (struct md_mount_links){md_mount_group_retain(g),md_mount_group_retain(md_mount_group_parent(g)),0}
            : (struct md_mount_links){NULL,md_mount_group_retain(g),0};
        if (md_mount_namespace_owner(d->view)!=md_mount_namespace_owner(source_view)) b->locked=1;
        (void)fs;
    }
    return 0;
}
static int attach(struct md_filesystem *fs,struct md_view_mount *base,struct md_view_mount *entries,unsigned count,
        const unsigned *slots,unsigned created,unsigned root,int replacing) {
    struct md_view_mount *source=node(base,entries,root),*parent=source->parent;
    struct md_mount_group *shared=parent ? parent->links.shared : NULL;
    struct md_mount_members members={0};
    int r=shared ? md_mount_family_capture(fs->mounts,&members) : 0;
    unsigned capacity=members.count+1,used=1;
    struct draft *drafts=calloc(capacity,sizeof(*drafts));
    struct md_mount_graph_change *changes=calloc(capacity,sizeof(*changes));
    if (!drafts || !changes) { free(drafts); free(changes); md_mount_members_release(&members); return -ENOMEM; }
    drafts[0]=(struct draft){fs->mounts,base,entries,count,{0}};
    struct mapping *map=NULL;
    for (unsigned i=0;!r && shared && i<created;++i) {
        struct md_view_mount *m=node(base,entries,slots[i]);
        if (m->links.unbindable) { r=-EINVAL; break; }
        if (!m->links.shared) {
            m->links.shared=md_mount_group_new(m->links.master);
            if (!m->links.shared) { r=-errno; break; }
        }
        struct mapping *item=calloc(1,sizeof(*item));
        if (!item) { r=-ENOMEM; break; }
        *item=(struct mapping){shared,md_mount_group_retain(m->links.shared),slots[i],map}; map=item;
    }
    for (unsigned v=0;!r && shared && v<members.count;++v) {
        struct md_mount_namespace *view=members.views[v];
        unsigned original=view->tree ? view->tree->count : 0;
        for (unsigned n=0;!r && n<=original;++n) {
            struct md_view_mount *p=md_view_mount_node(view,n);
            if (!p->id || p->detached || p==parent || (p->links.shared!=shared
                    && !md_mount_group_contains(p->links.master,shared))) continue;
            int inside=covered(fs,p,source->target);
            if (inside<0) { r=inside; break; }
            if (!inside) continue;
            if (md_mount_graph_foreign(view)) { r=-EXDEV; break; }
            unsigned d=0; while (d<used && drafts[d].view!=view) ++d;
            if (d==used) {
                if (!view->tree) {
                    view->tree=calloc(1,sizeof(*view->tree));
                    if (!view->tree) { r=-ENOMEM; break; }
                }
                struct md_view_mount *copy=calloc(MD_FS_MOUNTS_MAX,sizeof(*copy));
                if (!copy) { r=-ENOMEM; break; }
                memcpy(copy,view->tree->mounts,original*sizeof(*copy));
                drafts[used++]=(struct draft){view,&view->base,copy,original,{0}};
            }
            r=replica(fs,&drafts[d],p,fs->mounts,entries,base,slots,created,root,&map);
        }
    }
    for (unsigned i=0;!r && i<used;++i) {
        struct draft *d=&drafts[i];
        if (d->view->graph) for (unsigned j=0;!r && j<d->count;++j)
            if (d->entries[j].id) {
                int fd=md_mount_policy_share(&d->entries[j].policy);
                if (fd<0) r=fd;
            }
        changes[i]=(struct md_mount_graph_change){d->view,
            {d->base,d->entries,d->view->root,d->count}};
    }
    if (!r) r=md_mount_graph_update_many(changes,used);
    for (unsigned i=0;i<used;++i) {
        struct draft *d=&drafts[i];
        if (!r) {
            for (unsigned j=0;j<d->count;++j)
                if (d->created[j]) d->view->tree->mounts[j]=d->entries[j];
            if (!i) for (unsigned j=0;j<created;++j) {
                struct md_view_mount *old=md_view_mount_node(d->view,slots[j]),*next=node(d->base,d->entries,slots[j]);
                if (!replacing) *old=*next;
                else {
                    if (old->target!=next->target) close(old->target);
                    old->target=next->target; old->parent=next->parent;
                    old->guest=next->guest; old->detached=next->detached;
                    md_mount_links_release(&old->links); old->links=next->links;
                }
            }
            d->view->tree->count=d->count;
            atomic_store_explicit(&d->view->managed_paths,1,memory_order_release);
        } else for (unsigned j=0;j<d->count;++j) if (d->created[j]) md_view_mount_close(&d->entries[j]);
    }
    if (!r) for (unsigned i=1;i<used;++i) {
        struct md_filesystem selected=*fs; selected.mounts=drafts[i].view;
        md_fs_mount_table_changed(&selected);
    }
    while (map) { struct mapping *next=map->next; md_mount_group_release(map->child); free(map); map=next; }
    for (unsigned i=1;i<used;++i) free(drafts[i].entries);
    free(changes); free(drafts); md_mount_members_release(&members); return r;
}
int md_view_mount_attach(struct md_filesystem *fs,struct md_view_mount *entries,unsigned count,
        const unsigned *slots,unsigned created,unsigned root) {
    unsigned nodes[MD_FS_MOUNTS_MAX];
    if (created>MD_FS_MOUNTS_MAX) return -EINVAL;
    for (unsigned i=0;i<created;++i) nodes[i]=slots[i]+1;
    return attach(fs,&fs->mounts->base,entries,count,nodes,created,root+1,0);
}
int md_view_mount_place(struct md_filesystem *fs,struct md_view_mount *base,struct md_view_mount *entries,unsigned count,
        const unsigned *slots,unsigned placed,unsigned root) {
    return attach(fs,base,entries,count,slots,placed,root,1);
}

int md_view_mount_propagation(struct md_filesystem *fs,struct md_view_mount *root,unsigned kind,int recursive) {
    struct md_mount_namespace *view=fs->mounts;
    if (md_mount_graph_foreign(view)) return -EPERM;
    struct md_mount_members members={0};
    int r=md_mount_family_capture(view,&members);
    struct md_view_mount base=view->base,entries[MD_FS_MOUNTS_MAX];
    unsigned count=view->tree ? view->tree->count : 0;
    if (count) memcpy(entries,view->tree->mounts,count*sizeof(*entries));
    unsigned char changed[MD_FS_MOUNTS_MAX+1]={0};
    for (unsigned i=0;!r && i<=count;++i) {
        struct md_view_mount *m=md_view_mount_node(view,i),*next=i ? &entries[i-1] : &base;
        if (!m->id || (m->detached && m!=root)) continue;
        const struct md_view_mount *p=m;
        if (recursive) while (p && p!=root) p=p->parent;
        if (p!=root) continue;
        struct md_mount_links links={0};
        r=md_mount_links_change(&members,&m->links,kind,&links);
        if (!r) { next->links=links; changed[i]=1; }
    }
    if (!r) r=md_mount_graph_update(view,&(struct md_mount_layout){&base,entries,view->root,count});
    for (unsigned i=0;i<=count;++i) if (changed[i]) {
        struct md_mount_links *links=i ? &entries[i-1].links : &base.links;
        if (!r) {
            struct md_view_mount *m=md_view_mount_node(view,i);
            md_mount_links_release(&m->links); m->links=*links;
        } else md_mount_links_release(links);
    }
    md_mount_members_release(&members); return r;
}

struct removal {
    struct md_view_mount base,*entries;
    unsigned char removed[MD_FS_MOUNTS_MAX+1];
};
static int beneath_mount(const struct md_view_mount *mount,const struct md_view_mount *root) {
    for (;mount;mount=mount->parent) if (mount==root) return 1;
    return 0;
}
int md_view_mount_propagate_detach(struct md_filesystem *fs,struct md_view_mount *root,int lazy) {
    struct md_mount_group *source=root->links.shared;
    if (!root->parent || !root->parent->links.shared || !source) return md_view_mount_detach(fs,root);
    struct md_mount_members members={0};
    int r=md_mount_family_capture(fs->mounts,&members);
    if (r) return r;
    struct removal *pending=calloc(members.count,sizeof(*pending));
    struct md_mount_graph_change *changes=calloc(members.count,sizeof(*changes));
    int *leases=calloc((size_t)members.count*(MD_FS_MOUNTS_MAX+1),sizeof(*leases));
    unsigned retained=0,changed=0;
    if (!pending || !changes || !leases) r=-ENOMEM;
    for (unsigned v=0;!r && v<members.count;++v) {
        struct md_mount_namespace *view=members.views[v];
        unsigned count=view->tree ? view->tree->count : 0;
        struct removal *p=&pending[v]; p->base=view->base;
        for (unsigned i=0;!r && i<=count;++i) {
            struct md_view_mount *m=md_view_mount_node(view,i);
            if (!m->id || m->detached || !m->parent || (m!=root
                    && ((m->parent->links.shared!=root->parent->links.shared
                            && !md_mount_group_contains(m->parent->links.master,root->parent->links.shared))
                        || (m->links.shared!=source && !md_mount_group_contains(m->links.master,source))
                        || !md_view_same(&m->guest,&root->guest)))) continue;
            if (!lazy) {
                int children=0;
                for (unsigned j=0;j<=count;++j) {
                    struct md_view_mount *child=md_view_mount_node(view,j);
                    if (child->id && !child->detached && child->parent==m) { children=1; break; }
                }
                if (children && m!=root) continue;
                if (children || atomic_load_explicit(&m->anchors,memory_order_relaxed)
                        || md_domain_mount_root_used(view,m->id)) { r=-EBUSY; break; }
                int lease=-1;
                r=md_mount_graph_exclude(view,m,&lease);
                if (r) break;
                if (lease>=0) leases[retained++]=lease;
            }
            for (unsigned j=0;j<=count;++j)
                if (beneath_mount(md_view_mount_node(view,j),m)) p->removed[j]=1;
        }
        int any=0;
        for (unsigned i=0;i<=count;++i) any|=p->removed[i];
        if (r || !any) continue;
        if (count) {
            p->entries=calloc(count,sizeof(*p->entries));
            if (!p->entries) { r=-ENOMEM; break; }
            memcpy(p->entries,view->tree->mounts,count*sizeof(*p->entries));
        }
        for (unsigned i=0;i<=count;++i) if (p->removed[i]) {
            struct md_view_mount *m=i ? &p->entries[i-1] : &p->base;
            m->detached=1; m->links=(struct md_mount_links){0};
        }
        changes[changed++]=(struct md_mount_graph_change){view,{&p->base,p->entries,view->root,count}};
    }
    if (!r) r=md_mount_graph_update_many(changes,changed);
    if (!r) for (unsigned v=0;v<members.count;++v) {
        struct md_mount_namespace *view=members.views[v];
        unsigned count=view->tree ? view->tree->count : 0;
        int any=0;
        for (unsigned i=0;i<=count;++i) if (pending[v].removed[i]) {
            struct md_view_mount *m=md_view_mount_node(view,i);
            m->detached=1; md_mount_links_release(&m->links); any=1;
        }
        if (any) {
            atomic_store_explicit(&view->detached_mounts,1,memory_order_release);
            md_mount_family_retire(view);
        }
        if (any && view!=fs->mounts) {
            struct md_filesystem selected=*fs; selected.mounts=view;
            md_fs_mount_table_changed(&selected);
        }
    }
    while (retained) close(leases[--retained]);
    for (unsigned v=0;pending && v<members.count;++v) free(pending[v].entries);
    free(pending); free(changes); free(leases); md_mount_members_release(&members); return r;
}
