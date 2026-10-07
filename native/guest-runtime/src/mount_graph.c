#define _GNU_SOURCE
#include "mount_graph.h"
#include "fs_mount_internal.h"
#include "sealed_manifest.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { MAGIC=0x4d444d47U, VERSION=1 };
struct entry { uint32_t parent, reserved; struct md_fd_identity source, target, policy; };
struct manifest {
    uint32_t magic, version, count, reserved;
    struct entry entries[MD_FS_MOUNTS_MAX];
};
struct md_mount_graph { int fd; struct md_fd_identity identity; };
_Static_assert(sizeof(struct entry)==56,"mount graph entry layout");
_Static_assert(sizeof(struct manifest)==16+56*MD_FS_MOUNTS_MAX,"mount graph layout");

static size_t manifest_size(unsigned count) { return 16+count*sizeof(struct entry); }
void md_mount_graph_close(struct md_mount_graph *graph) {
    if (graph) { close(graph->fd); free(graph); }
}
void md_mount_graph_parcel_close(struct md_mount_graph_parcel *p) {
    if (!p) return;
    unsigned count=p->count>MD_MOUNT_GRAPH_FDS ? MD_MOUNT_GRAPH_FDS : p->count;
    for (unsigned i=0;i<count;++i) {
        if (p->fd[i]<0) continue;
        /* Invalid duplicate slot numbers still own only one kernel descriptor. */
        for (unsigned j=i+1;j<count;++j) if (p->fd[j]==p->fd[i]) p->fd[j]=-1;
        close(p->fd[i]); p->fd[i]=-1;
    }
    p->count=0;
}
static int cloexec(int fd) {
    int flags=fcntl(fd,F_GETFD);
    return flags<0 ? -errno : flags&FD_CLOEXEC ? 0 : -EINVAL;
}
static int directory(int fd, struct md_fd_identity expected, struct stat *st) {
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if (!(flags&O_PATH)) return -EPROTO;
    if (fstat(fd,st)) return -errno;
    return S_ISDIR(st->st_mode) && md_fd_identity_same(md_fd_identity(st),expected) ? 0 : -EPROTO;
}
static int read_manifest(int fd, struct manifest *out, struct md_fd_identity *id) {
    size_t n;
    int r=md_sealed_manifest_read(fd,out,sizeof(*out),&n,id);
    if (r) return r;
    if (n<16 || out->magic!=MAGIC || out->version!=VERSION || out->reserved
            || out->count>MD_FS_MOUNTS_MAX || manifest_size(out->count)!=n) return -EPROTO;
    for (unsigned i=0;i<out->count;++i) {
        const struct entry *e=&out->entries[i];
        /* Parents precede children, making cycles and detached indices invalid. */
        if (e->reserved || e->parent>i) return -EPROTO;
        for (unsigned j=0;j<i;++j) if (e->parent==out->entries[j].parent
                && md_fd_identity_same(e->target,out->entries[j].target)) return -EPROTO;
    }
    return 0;
}
static int describe(struct md_mount_namespace *view, struct manifest *out,
        int fds[MD_MOUNT_GRAPH_FDS]) {
    *out=(struct manifest){.magic=MAGIC,.version=VERSION};
    struct md_fs_mounts *tree=view->tree;
    if (!tree) return 0;
    if (tree->count>MD_FS_MOUNTS_MAX) return -EINVAL;
    out->count=tree->count;
    for (unsigned i=0;i<tree->count;++i) {
        struct md_view_mount *m=&tree->mounts[i]; struct entry *e=&out->entries[i];
        if (m->parent) {
            unsigned j=0;
            while (j<i && m->parent!=&tree->mounts[j]) ++j;
            if (j==i) return -EINVAL;
            e->parent=j+1;
        }
        int r=directory(m->source,md_fd_identity(&m->native),&(struct stat){0});
        if (!r) r=directory(m->target,md_fd_identity(&m->guest),&(struct stat){0});
        if (r) return r;
        e->source=md_fd_identity(&m->native); e->target=md_fd_identity(&m->guest);
        for (unsigned j=0;j<i;++j) if (e->parent==out->entries[j].parent
                && md_fd_identity_same(e->target,out->entries[j].target)) return -EINVAL;
        int policy=md_mount_policy_share(&m->policy);
        if (policy<0) return policy;
        struct stat st; if (fstat(policy,&st)) return -errno;
        e->policy=md_fd_identity(&st);
        fds[1+3*i]=m->source; fds[2+3*i]=m->target; fds[3+3*i]=policy;
    }
    return 0;
}
static int publish(struct md_mount_namespace *view, const struct manifest *data) {
    if (view->graph) {
        struct manifest old; struct md_fd_identity id;
        int r=read_manifest(view->graph->fd,&old,&id);
        if (!r && (old.count!=data->count || memcmp(&old,data,manifest_size(data->count)))) r=-ESTALE;
        return r;
    }
    struct md_mount_graph *g=calloc(1,sizeof(*g));
    if (!g) return -ENOMEM;
    g->fd=md_sealed_manifest_create("shroot-mount-graph",data,manifest_size(data->count),&g->identity);
    if (g->fd<0) { int r=g->fd; free(g); return r; }
    view->graph=g; return 0;
}
int md_mount_graph_export(struct md_mount_namespace *view, struct md_mount_graph_parcel *out) {
    if (!view || !out || out->count) return -EINVAL;
    struct manifest data; int fds[MD_MOUNT_GRAPH_FDS];
    int r=describe(view,&data,fds);
    if (!r) r=publish(view,&data);
    if (r) return r;
    fds[0]=view->graph->fd;
    struct md_mount_graph_parcel candidate={0};
    for (unsigned i=0;i<1+3*data.count;++i) {
        int fd=fcntl(fds[i],F_DUPFD_CLOEXEC,3);
        if (fd<0) { r=-errno; break; }
        candidate.fd[candidate.count++]=fd;
    }
    if (r) md_mount_graph_parcel_close(&candidate);
    else *out=candidate;
    return r;
}
static int take(struct md_mount_graph_parcel *p, unsigned index) {
    int fd=p->fd[index]; p->fd[index]=-1; return fd;
}
static int import(struct md_mount_graph_parcel *p, struct md_mount_namespace **out) {
    if (!out || !p->count || p->count>MD_MOUNT_GRAPH_FDS) return -EINVAL;
    for (unsigned i=0;i<p->count;++i) {
        int r=cloexec(p->fd[i]); if (r) return r;
        for (unsigned j=0;j<i;++j) if (p->fd[i]==p->fd[j]) return -EPROTO;
    }
    struct manifest data; struct md_fd_identity id;
    int r=read_manifest(p->fd[0],&data,&id);
    if (r) return r;
    if (p->count!=1+3*data.count) return -EPROTO;
    if (*out && (!(*out)->graph || !md_fd_identity_same((*out)->graph->identity,id))) return -ESTALE;
    /* Validate even an interned graph's rights; identity never excuses swapped
     * or truncated descriptors. A known view retains its original caches/IDs. */
    for (unsigned i=0;i<data.count;++i) {
        struct entry *e=&data.entries[i]; struct stat st;
        r=directory(p->fd[1+3*i],e->source,&st);
        if (!r) r=directory(p->fd[2+3*i],e->target,&st);
        if (!r && fstat(p->fd[3+3*i],&st)) r=-errno;
        if (!r && !md_fd_identity_same(md_fd_identity(&st),e->policy)) r=-EPROTO;
        if (r) return r;
    }
    if (*out) {
        struct manifest known; int borrowed[MD_MOUNT_GRAPH_FDS];
        r=describe(*out,&known,borrowed);
        if (!r && (known.count!=data.count || memcmp(&known,&data,manifest_size(data.count)))) r=-ESTALE;
        return r;
    }
    struct md_mount_namespace *view=md_mount_namespace_new();
    if (!view) return -errno;
    view->graph=calloc(1,sizeof(*view->graph));
    if (!view->graph) { md_mount_namespace_release(view); return -ENOMEM; }
    view->graph->fd=take(p,0); view->graph->identity=id;
    if (data.count) {
        view->tree=calloc(1,sizeof(*view->tree));
        if (!view->tree) r=-ENOMEM;
    }
    for (unsigned i=0;!r && i<data.count;++i) {
        struct md_view_mount *m=&view->tree->mounts[i];
        struct entry *e=&data.entries[i];
        m->source=take(p,1+3*i); m->target=take(p,2+3*i);
        ++view->tree->count;
        if (fstat(m->source,&m->native) || fstat(m->target,&m->guest)) r=-errno;
        if (!r) r=md_mount_policy_import(&m->policy,p->fd[3+3*i]);
        if (!r) { take(p,3+3*i); r=md_mount_id_allocate(&m->id); }
        if (e->parent) m->parent=&view->tree->mounts[e->parent-1];
    }
    if (r) md_mount_namespace_release(view);
    else *out=view;
    return r;
}
int md_mount_graph_import(struct md_mount_graph_parcel *p, struct md_mount_namespace **out) {
    if (!p) return -EINVAL;
    int r=import(p,out); md_mount_graph_parcel_close(p); return r;
}
