#define _GNU_SOURCE
#include "mount_graph.h"
#include "fs_mount_internal.h"
#include "mount_topology.h"
#include "sealed_manifest.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { MAGIC=0x4d444d47U, VERSION=3 };
enum { INODE=1, DETACHED=2 };
struct entry { uint32_t parent, flags; struct md_fd_identity source, target, policy;
    uint32_t storage, reserved; };
struct storage { struct md_fd_identity root; uint32_t start, count; };
struct manifest {
    uint32_t magic, version, count, storages;
    struct md_fd_identity root_policy;
    struct entry entries[MD_FS_MOUNTS_MAX];
    struct storage storage[MD_FS_MOUNTS_MAX];
};
struct md_mount_graph { int fd; struct md_fd_identity identity; };
_Static_assert(sizeof(struct entry)==64 && sizeof(struct storage)==24,"mount graph entry layout");
_Static_assert(sizeof(struct manifest)==32+88*MD_FS_MOUNTS_MAX,"mount graph layout");

static size_t manifest_size(const struct manifest *m) {
    return 32+m->count*sizeof(struct entry)+m->storages*sizeof(struct storage);
}
static size_t manifest_bytes(const struct manifest *m, unsigned char *bytes) {
    size_t n=32+m->count*sizeof(struct entry);
    memcpy(bytes,m,n); memcpy(bytes+n,m->storage,m->storages*sizeof(struct storage));
    return manifest_size(m);
}
static int manifest_same(const struct manifest *a, const struct manifest *b) {
    return a->count==b->count && a->storages==b->storages
        && !memcmp(a,b,32+a->count*sizeof(struct entry))
        && !memcmp(a->storage,b->storage,a->storages*sizeof(struct storage));
}
static unsigned stores(const struct md_mount_namespace *view, struct md_inode_lifetime **owners) {
    unsigned count=0;
    for (unsigned i=0;view->tree && i<view->tree->count;++i) {
        struct md_inode_lifetime *owner=view->tree->mounts[i].storage;
        if (!owner) continue;
        unsigned j=0; while (j<count && !md_inode_lifetime_same(owner,owners[j])) ++j;
        if (j==count) owners[count++]=owner;
    }
    return count;
}
unsigned md_mount_graph_rights(const struct md_mount_namespace *view) {
    if (!view || (view->tree && view->tree->count>MD_FS_MOUNTS_MAX)) return 0;
    struct md_inode_lifetime *owners[MD_FS_MOUNTS_MAX];
    unsigned count=stores(view,owners), rights=2+3*(view->tree ? view->tree->count : 0);
    for (unsigned i=0;i<count;++i) rights+=md_inode_custody_rights(owners[i]);
    return rights;
}
void md_mount_graph_close(struct md_mount_graph *graph) {
    if (graph) { close(graph->fd); free(graph); }
}
static int compare_fd(const void *a, const void *b) {
    int x=*(const int *)a, y=*(const int *)b; return (x>y)-(x<y);
}
void md_mount_graph_parcel_close(struct md_mount_graph_parcel *p) {
    if (!p) return;
    unsigned count=p->count>MD_MOUNT_GRAPH_FDS ? MD_MOUNT_GRAPH_FDS : p->count;
    if (p->fd) qsort(p->fd,count,sizeof(int),compare_fd);
    for (unsigned i=0;p->fd && i<count;++i)
        if (p->fd[i]>=0 && (!i || p->fd[i]!=p->fd[i-1])) close(p->fd[i]);
    free(p->fd); *p=(struct md_mount_graph_parcel){0};
}
static int cloexec(int fd) {
    int flags=fcntl(fd,F_GETFD);
    return flags<0 ? -errno : flags&FD_CLOEXEC ? 0 : -EINVAL;
}
static int validate_rights(const struct md_mount_graph_parcel *p) {
    int *sorted=calloc(p->count,sizeof(int));
    if (!sorted) return -ENOMEM;
    memcpy(sorted,p->fd,p->count*sizeof(int)); qsort(sorted,p->count,sizeof(int),compare_fd);
    int r=0;
    for (unsigned i=0;!r && i<p->count;++i)
        r=i && sorted[i]==sorted[i-1] ? -EPROTO : cloexec(sorted[i]);
    free(sorted); return r;
}
static int directory(int fd, struct md_fd_identity expected, struct stat *st) {
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if (!(flags&O_PATH)) return -EPROTO;
    if (fstat(fd,st)) return -errno;
    return md_fd_identity_same(md_fd_identity(st),expected) ? 0 : -EPROTO;
}
static int read_manifest(int fd, struct manifest *out, struct md_fd_identity *id) {
    size_t n; unsigned char bytes[sizeof(*out)];
    int r=md_sealed_manifest_read(fd,bytes,sizeof(bytes),&n,id);
    if (r) return r;
    if (n<32) return -EPROTO;
    memset(out,0,sizeof(*out)); memcpy(out,bytes,32);
    if (out->magic!=MAGIC || out->version!=VERSION || out->storages>out->count
            || out->count>MD_FS_MOUNTS_MAX || manifest_size(out)!=n) return -EPROTO;
    memcpy(out->entries,bytes+32,out->count*sizeof(struct entry));
    memcpy(out->storage,bytes+32+out->count*sizeof(struct entry),out->storages*sizeof(struct storage));
    unsigned parents[MD_FS_MOUNTS_MAX], order[MD_FS_MOUNTS_MAX];
    unsigned owners=0, next=2+3*out->count;
    for (unsigned i=0;i<out->count;++i) {
        const struct entry *e=&out->entries[i];
        if (e->reserved || e->flags&~(INODE|DETACHED) || e->storage>out->storages
                || e->storage>owners+1 || (e->storage && !(e->flags&INODE))) return -EPROTO;
        if (e->storage==owners+1) ++owners;
        parents[i]=e->parent;
        for (unsigned j=0;j<i;++j) if (!(e->flags&DETACHED) && !(out->entries[j].flags&DETACHED)
                && e->parent==out->entries[j].parent
                && md_fd_identity_same(e->target,out->entries[j].target)) return -EPROTO;
    }
    if (owners!=out->storages) return -EPROTO;
    for (unsigned i=0;i<owners;++i) {
        const struct storage *s=&out->storage[i];
        if (s->start!=next || s->count<2 || s->count>MD_INODE_CUSTODY_FDS || s->count%2) return -EPROTO;
        next+=s->count;
        for (unsigned j=0;j<i;++j)
            if (md_fd_identity_same(s->root,out->storage[j].root)) return -EPROTO;
    }
    return md_mount_topology_order(out->count,parents,order) ? -EPROTO : 0;
}
static int describe(struct md_mount_namespace *view, struct manifest *out,
        int fds[MD_MOUNT_GRAPH_PLACEMENT_FDS], struct md_inode_lifetime **owners) {
    *out=(struct manifest){.magic=MAGIC,.version=VERSION};
    int root=md_mount_policy_share(&view->root_policy);
    if (root<0) return root;
    struct stat root_stat;
    if (fstat(root,&root_stat)) return -errno;
    out->root_policy=md_fd_identity(&root_stat); fds[1]=root;
    struct md_fs_mounts *tree=view->tree;
    if (!tree) return 0;
    unsigned order[MD_FS_MOUNTS_MAX];
    int valid=md_view_topology_order(tree,order);
    if (valid) return valid;
    out->count=tree->count;
    out->storages=stores(view,owners);
    unsigned next=2+3*tree->count;
    for (unsigned i=0;i<out->storages;++i) {
        out->storage[i]=(struct storage){.root={owners[i]->device,owners[i]->inode},
            .start=next,.count=md_inode_custody_rights(owners[i])};
        next+=out->storage[i].count;
    }
    for (unsigned i=0;i<tree->count;++i) {
        struct md_view_mount *m=&tree->mounts[i]; struct entry *e=&out->entries[i];
        if (m->storage) {
            if (!md_view_inode(m)) return -EINVAL;
            unsigned j=0; while (j<out->storages && !md_inode_lifetime_same(m->storage,owners[j])) ++j;
            if (j==out->storages) return -ESTALE;
            e->storage=j+1;
        }
        e->flags=(md_view_inode(m) ? INODE : 0) | (m->detached ? DETACHED : 0);
        if (m->parent) {
            unsigned j=0;
            while (j<tree->count && m->parent!=&tree->mounts[j]) ++j;
            if (j==tree->count) return -EINVAL;
            e->parent=j+1;
        }
        int r=directory(m->source,md_fd_identity(&m->native),&(struct stat){0});
        if (!r) r=directory(m->target,md_fd_identity(&m->guest),&(struct stat){0});
        if (r) return r;
        e->source=md_fd_identity(&m->native); e->target=md_fd_identity(&m->guest);
        for (unsigned j=0;j<i;++j) if (!(e->flags&DETACHED) && !(out->entries[j].flags&DETACHED)
                && e->parent==out->entries[j].parent
                && md_fd_identity_same(e->target,out->entries[j].target)) return -EINVAL;
        int policy=md_mount_policy_share(&m->policy);
        if (policy<0) return policy;
        struct stat st; if (fstat(policy,&st)) return -errno;
        e->policy=md_fd_identity(&st);
        fds[2+3*i]=m->source; fds[3+3*i]=m->target; fds[4+3*i]=policy;
    }
    return 0;
}
static int publish(struct md_mount_namespace *view, const struct manifest *data) {
    if (view->graph) {
        struct manifest old; struct md_fd_identity id;
        int r=read_manifest(view->graph->fd,&old,&id);
        if (!r && !manifest_same(&old,data)) r=-ESTALE;
        return r;
    }
    struct md_mount_graph *g=calloc(1,sizeof(*g));
    if (!g) return -ENOMEM;
    unsigned char bytes[sizeof(*data)]; size_t size=manifest_bytes(data,bytes);
    g->fd=md_sealed_manifest_create("shroot-mount-graph",bytes,size,&g->identity);
    if (g->fd<0) { int r=g->fd; free(g); return r; }
    view->graph=g; return 0;
}
int md_mount_graph_export(struct md_mount_namespace *view, struct md_mount_graph_parcel *out) {
    if (!view || !out || out->count || out->fd) return -EINVAL;
    struct manifest data; int fds[MD_MOUNT_GRAPH_PLACEMENT_FDS];
    struct md_inode_lifetime *owners[MD_FS_MOUNTS_MAX];
    int r=describe(view,&data,fds,owners);
    if (!r) r=publish(view,&data);
    if (r) return r;
    fds[0]=view->graph->fd;
    unsigned rights=md_mount_graph_rights(view);
    struct md_mount_graph_parcel candidate={.fd=calloc(rights,sizeof(int))};
    if (!candidate.fd) return -ENOMEM;
    for (unsigned i=0;i<2+3*data.count;++i) {
        int fd=fcntl(fds[i],F_DUPFD_CLOEXEC,3);
        if (fd<0) { r=-errno; break; }
        candidate.fd[candidate.count++]=fd;
    }
    for (unsigned i=0;!r && i<data.storages;++i) {
        struct md_inode_custody_parcel p={0};
        r=md_inode_custody_export(owners[i],&p);
        if (!r && (p.count!=data.storage[i].count || candidate.count!=data.storage[i].start
                || p.count>rights-candidate.count)) r=-ESTALE;
        if (!r) { memcpy(candidate.fd+candidate.count,p.fd,p.count*sizeof(int)); candidate.count+=p.count; p.count=0; }
        md_inode_custody_parcel_close(&p);
    }
    if (r) md_mount_graph_parcel_close(&candidate);
    else *out=candidate;
    return r;
}
static int take(struct md_mount_graph_parcel *p, unsigned index) {
    int fd=p->fd[index]; p->fd[index]=-1; return fd;
}
static int import(struct md_mount_graph_parcel *p, struct md_mount_namespace **out) {
    if (!out || !p->fd || !p->count || p->count>MD_MOUNT_GRAPH_FDS) return -EINVAL;
    int r=validate_rights(p); if (r) return r;
    struct manifest data; struct md_fd_identity id;
    r=read_manifest(p->fd[0],&data,&id);
    if (r) return r;
    unsigned rights=2+3*data.count;
    for (unsigned i=0;i<data.storages;++i) rights+=data.storage[i].count;
    if (p->count!=rights) return -EPROTO;
    struct stat root_stat;
    if (fstat(p->fd[1],&root_stat)) return -errno;
    if (!md_fd_identity_same(md_fd_identity(&root_stat),data.root_policy)) return -EPROTO;
    if (*out && (!(*out)->graph || !md_fd_identity_same((*out)->graph->identity,id))) return -ESTALE;
    /* Validate even an interned graph's rights; identity never excuses swapped
     * or truncated descriptors. A known view retains its original caches/IDs. */
    for (unsigned i=0;i<data.count;++i) {
        struct entry *e=&data.entries[i]; struct stat st;
        r=directory(p->fd[2+3*i],e->source,&st);
        if (!r) r=directory(p->fd[3+3*i],e->target,&st);
        if (!r && fstat(p->fd[4+3*i],&st)) r=-errno;
        if (!r && !md_fd_identity_same(md_fd_identity(&st),e->policy)) r=-EPROTO;
        if (r) return r;
    }
    struct md_inode_lifetime *owners[MD_FS_MOUNTS_MAX]={0};
    for (unsigned i=0;!r && i<data.storages;++i) {
        const struct storage *s=&data.storage[i]; struct stat st;
        if (fstat(p->fd[s->start+1],&st)) { r=-errno; break; }
        if (!md_fd_identity_same(md_fd_identity(&st),s->root)) { r=-EPROTO; break; }
        struct md_inode_custody_parcel custody={.count=s->count};
        for (unsigned j=0;j<s->count;++j) custody.fd[j]=take(p,s->start+j);
        r=md_inode_custody_import(&custody,custody.fd[1],&owners[i]);
    }
    if (!r && *out) {
        struct manifest known; int borrowed[MD_MOUNT_GRAPH_PLACEMENT_FDS];
        struct md_inode_lifetime *existing[MD_FS_MOUNTS_MAX];
        r=describe(*out,&known,borrowed,existing);
        if (!r && !manifest_same(&known,&data)) r=-ESTALE;
    }
    if (r || *out) goto done;
    struct md_mount_namespace *view=md_mount_namespace_new();
    if (!view) { r=-errno; goto done; }
    view->graph=calloc(1,sizeof(*view->graph));
    if (!view->graph) { md_mount_namespace_release(view); r=-ENOMEM; goto done; }
    view->graph->fd=take(p,0); view->graph->identity=id;
    r=md_mount_policy_import(&view->root_policy,p->fd[1]);
    if (!r) take(p,1);
    if (data.count) {
        view->tree=calloc(1,sizeof(*view->tree));
        if (!view->tree) r=-ENOMEM;
    }
    for (unsigned i=0;!r && i<data.count;++i) {
        struct md_view_mount *m=&view->tree->mounts[i];
        struct entry *e=&data.entries[i];
        m->backing=(e->flags&INODE) ? MD_MOUNT_INODE : MD_MOUNT_NATIVE;
        m->storage=e->storage ? md_inode_lifetime_retain(owners[e->storage-1]) : NULL;
        atomic_init(&m->anchors,0);
        m->detached=!!(e->flags&DETACHED);
        m->source=take(p,2+3*i); m->target=take(p,3+3*i);
        ++view->tree->count;
        if (fstat(m->source,&m->native) || fstat(m->target,&m->guest)) r=-errno;
        if (!r) r=md_mount_policy_import(&m->policy,p->fd[4+3*i]);
        if (!r) { take(p,4+3*i); r=md_mount_id_allocate(&m->id); }
        if (e->parent) m->parent=&view->tree->mounts[e->parent-1];
    }
    if (r) md_mount_namespace_release(view);
    else *out=view;
done:
    for (unsigned i=0;i<data.storages;++i) md_inode_lifetime_release(owners[i]);
    return r;
}
int md_mount_graph_import(struct md_mount_graph_parcel *p, struct md_mount_namespace **out) {
    if (!p) return -EINVAL;
    int r=import(p,out); md_mount_graph_parcel_close(p); return r;
}
