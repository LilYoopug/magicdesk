#define _GNU_SOURCE
#include "fs_origin_transfer.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "inode_custody.h"
#include "inode_fifo.h"
#include "mount_graph.h"
#include "sealed_manifest.h"
#include "fd_receipt.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { MAGIC=0x4d444f56U, VERSION=6, MAX=MD_FD_RECEIPT_MAX };
struct span { uint32_t start, count; struct md_fd_identity identity; };
struct origin { uint32_t view, owner, mount, descriptor; struct md_fd_identity identity; uint64_t generation;
    struct md_fd_identity endpoint; char fifo_channel[32]; };
struct manifest {
    uint32_t magic, version, count, origins, views, owners, rights, reserved;
    struct md_fd_message_route route;
    struct md_fd_identity store;
    uint32_t index[MAX];
    struct origin origin[MAX];
    struct span view[MAX], owner[MAX];
};
_Static_assert(sizeof(struct span)==24 && sizeof(struct origin)==88, "origin wire records");
_Static_assert(offsetof(struct manifest,index)==136, "origin wire header");
struct cached_view {
    struct cached_view *next;
    struct md_fd_identity identity;
    struct md_mount_namespace *view;
};
struct md_fs_origin_imports { int root; struct md_fd_identity store; struct cached_view *views; };
struct md_fs_origin_vector { unsigned count; struct md_fs_anchor *entries[]; };

int md_fs_anchor_portable(const struct md_fs_anchor *a) {
    return !a || md_mount_graph_portable(a->view);
}

static size_t manifest_size(const struct manifest *m) {
    return offsetof(struct manifest,index)+m->count*sizeof(*m->index)
        +m->origins*sizeof(*m->origin)+(m->owners+m->views)*sizeof(struct span);
}
static int manifest_write(const struct manifest *m) {
    unsigned char bytes[sizeof(*m)]; size_t next=offsetof(struct manifest,index);
    memcpy(bytes,m,next);
    memcpy(bytes+next,m->index,m->count*sizeof(*m->index)); next+=m->count*sizeof(*m->index);
    memcpy(bytes+next,m->origin,m->origins*sizeof(*m->origin)); next+=m->origins*sizeof(*m->origin);
    memcpy(bytes+next,m->owner,m->owners*sizeof(*m->owner)); next+=m->owners*sizeof(*m->owner);
    memcpy(bytes+next,m->view,m->views*sizeof(*m->view)); next+=m->views*sizeof(*m->view);
    struct md_fd_identity id;
    return md_sealed_manifest_create("shroot-message-origins",bytes,next,&id);
}
static int manifest_read(int fd, struct manifest *m) {
    unsigned char bytes[sizeof(*m)]; size_t size, next=offsetof(struct manifest,index);
    struct md_fd_identity id;
    int r=md_sealed_manifest_read(fd,bytes,sizeof(bytes),&size,&id);
    if (r) return r;
    if (size<next) return -EPROTO;
    memcpy(m,bytes,next);
    if (m->magic!=MAGIC || m->version!=VERSION || m->reserved || !m->count || m->count>MAX
            || m->origins>m->count || m->owners>m->origins || m->views>m->origins
            || size!=manifest_size(m)) return -EPROTO;
    memcpy(m->index,bytes+next,m->count*sizeof(*m->index)); next+=m->count*sizeof(*m->index);
    memcpy(m->origin,bytes+next,m->origins*sizeof(*m->origin)); next+=m->origins*sizeof(*m->origin);
    memcpy(m->owner,bytes+next,m->owners*sizeof(*m->owner)); next+=m->owners*sizeof(*m->owner);
    memcpy(m->view,bytes+next,m->views*sizeof(*m->view)); return 0;
}
static int compare_fd(const void *a, const void *b) {
    int x=*(const int *)a, y=*(const int *)b; return (x>y)-(x<y);
}
void md_fs_origin_parcel_close(struct md_fs_origin_parcel *p) {
    if (!p) return;
    if (p->fd) {
        qsort(p->fd,p->count,sizeof(*p->fd),compare_fd);
        for (unsigned i=0;i<p->count;++i)
            if (p->fd[i]>=0 && (!i || p->fd[i]!=p->fd[i-1])) close(p->fd[i]);
        free(p->fd);
    }
    *p=(struct md_fs_origin_parcel){0};
}
static int identity(int fd, struct md_fd_identity *out) {
    struct stat st; if (fstat(fd,&st)) return -errno;
    *out=md_fd_identity(&st); return 0;
}
static int path_identity(int fd, struct md_fd_identity *out) {
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if (!(flags&O_PATH)) return -EPROTO;
    return identity(fd,out);
}
static int fifo_channel(const struct md_fs_anchor *a,char channel[32]) {
    struct stat st;
    if (fstat(a->fd,&st)) return -errno;
    if (!S_ISFIFO(st.st_mode)) return 0;
    struct md_inode_store *store=NULL;
    int r=md_inode_store_reconnect(a->lifetime,&store);
    char id[33]={0};
    if (!r) r=md_inode_fifo_channel(store,a->fd,id);
    if (!r) memcpy(channel,id,32);
    md_inode_store_close(store); return r;
}
static unsigned view_slot(const struct md_fs_anchor *a) {
    if (md_view_base(a->view,a->mount)) return 0;
    if (a->view->tree) for (unsigned i=0;i<a->view->tree->count;++i)
        if (a->mount==&a->view->tree->mounts[i]) return i+1;
    return UINT_MAX;
}
static int add_span(struct span *s, struct md_fs_origin_parcel *p, int *fd, unsigned n) {
    int r=identity(fd[0],&s->identity);
    if (r) return r;
    s->start=p->count; s->count=n;
    memcpy(p->fd+p->count,fd,n*sizeof(*fd)); p->count+=n; return 0;
}
int md_fs_origin_export_entries(const struct md_fd_message *message, struct md_fd_object *const *entries,
        struct md_fs_origin_parcel *out) {
    if (!entries || !out || out->fd || out->count) return -EINVAL;
    struct manifest data={.magic=MAGIC,.version=VERSION};
    int r=md_fd_message_route(message,&data.route);
    if (r) return r;
    data.count=md_fd_message_count(message);
    if (!data.count || data.count>MAX || data.route.count!=data.count) return -EINVAL;
    r=identity(md_fd_message_store_root(message),&data.store);
    if (r) return r;
    struct md_fs_anchor *anchors[MAX];
    struct md_mount_namespace *views[MAX];
    struct md_inode_lifetime *owners[MAX];
    unsigned rights=1;
    for (unsigned i=0;i<data.count;++i) {
        struct md_fs_anchor *a=md_fs_anchor_from_object(entries[i]);
        if (!a) {
            if (entries[i] && !(entries[i]==md_fd_message_origins(message)[i]
                    && md_fd_message_exports_native(message,i))) return -EOPNOTSUPP;
            continue;
        }
        /* Native provider anchors carry no namespace semantics. The receiver
         * gets the native description, subject to the kernel's FD checks. */
        if (a->child) return -EOPNOTSUPP;
        if (!a->view) continue;
        unsigned n=0; while (n<data.origins && anchors[n]!=a) ++n;
        data.index[i]=n+1;
        if (n<data.origins) continue;
        if (!a->view || !a->lifetime || a->lifetime->device!=data.store.device
                || a->lifetime->inode!=data.store.inode) return -EXDEV;
        anchors[data.origins++]=a; rights+=2;
        struct origin *o=&data.origin[n];
        o->identity=(struct md_fd_identity){a->device,a->inode}; o->mount=view_slot(a);
        o->endpoint=a->endpoint;
        r=fifo_channel(a,o->fifo_channel);
        if (r) return r;
        o->generation=a->mount->generation;
        if (o->mount==UINT_MAX) return -ESTALE;
        unsigned v=0; while (v<data.views && views[v]!=a->view) ++v;
        if (v==data.views) {
            unsigned graph_rights=md_mount_graph_rights(a->view);
            if (!graph_rights) return -EINVAL;
            views[data.views++]=a->view; rights+=graph_rights;
        }
        o->view=v;
        unsigned s=0; while (s<data.owners && owners[s]!=a->lifetime) ++s;
        if (s==data.owners) {
            owners[data.owners++]=a->lifetime; rights+=md_inode_custody_rights(a->lifetime);
        }
        o->owner=s;
    }
    struct md_fs_origin_parcel candidate={.fd=calloc(rights,sizeof(int)),.count=1};
    if (!candidate.fd) return -ENOMEM;
    candidate.fd[0]=-1;
    for (unsigned i=0;!r && i<data.owners;++i) {
        struct md_inode_custody_parcel p={0};
        r=md_inode_custody_export(owners[i],&p);
        if (!r && p.count>rights-candidate.count) r=-EOVERFLOW;
        if (!r) r=add_span(&data.owner[i],&candidate,p.fd,p.count);
        if (!r) p.count=0;
        md_inode_custody_parcel_close(&p);
    }
    for (unsigned i=0;!r && i<data.views;++i) {
        struct md_mount_graph_parcel p={0};
        r=md_mount_graph_export(views[i],md_fd_message_store_root(message),&p);
        if (!r && p.count>rights-candidate.count) r=-EOVERFLOW;
        struct md_fd_identity stream;
        if (!r) r=identity(p.fd[p.count-1],&stream);
        if (!r) r=add_span(&data.view[i],&candidate,p.fd,p.count);
        if (!r) data.view[i].identity=stream;
        if (!r) p.count=0;
        md_mount_graph_parcel_close(&p);
    }
    for (unsigned i=0;!r && i<data.origins;++i) {
        struct md_fd_identity actual;
        if (candidate.count>=rights) { r=-ESTALE; break; }
        r=path_identity(anchors[i]->fd,&actual);
        if (!r && !md_fd_identity_same(actual,data.origin[i].identity)) r=-ESTALE;
        int fd=r ? -1 : fcntl(anchors[i]->fd,F_DUPFD_CLOEXEC,3);
        if (!r && fd<0) r=-errno;
        if (!r) { data.origin[i].descriptor=candidate.count; candidate.fd[candidate.count++]=fd; }
        if (!r) {
            int pin=md_mount_graph_acquire_pin(anchors[i]->view,anchors[i]->mount);
            if (pin<0) r=pin; else candidate.fd[candidate.count++]=pin;
        }
    }
    data.rights=candidate.count;
    if (!r && candidate.count!=rights) r=-ESTALE;
    if (!r) {
        int fd=manifest_write(&data);
        if (fd<0) r=fd;
        else candidate.fd[0]=fd;
    }
    if (r) md_fs_origin_parcel_close(&candidate);
    else *out=candidate;
    return r;
}
int md_fs_origin_export(const struct md_fd_message *message, struct md_fs_origin_parcel *out) {
    return md_fs_origin_export_entries(message,md_fd_message_origins(message),out);
}
int md_fs_origin_imports_new(int root, struct md_fs_origin_imports **out) {
    if (!out || *out) return -EINVAL;
    struct stat st;
    int r=fstat(root,&st) ? -errno : 0;
    if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
    if (r) return r;
    struct md_fs_origin_imports *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->root=openat(root,".",O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (s->root<0) { r=-errno; free(s); return r; }
    s->store=md_fd_identity(&st); *out=s; return 0;
}
static void views_free(struct cached_view *p) {
    while (p) { struct cached_view *next=p->next; md_mount_namespace_release(p->view); free(p); p=next; }
}
void md_fs_origin_imports_collect(struct md_fs_origin_imports *s) {
    if (!s) return;
    struct cached_view **p=&s->views;
    while (*p) {
        struct cached_view *v=*p;
        /* Only this worker accesses the cache. Every external owner already
         * retains its view, so one reference means the cache is sole owner. */
        if (atomic_load_explicit(&v->view->refs,memory_order_acquire)==1) {
            *p=v->next; v->next=NULL; views_free(v);
        } else p=&v->next;
    }
}
void md_fs_origin_imports_free(struct md_fs_origin_imports *s) {
    if (s) { views_free(s->views); close(s->root); free(s); }
}
void md_fs_origin_vector_free(struct md_fs_origin_vector *v) {
    if (v) { for (unsigned i=0;i<v->count;++i) md_fs_anchor_release(v->entries[i]); free(v); }
}
unsigned md_fs_origin_vector_count(const struct md_fs_origin_vector *v) { return v ? v->count : 0; }
struct md_fs_anchor *const *md_fs_origin_vector_entries(const struct md_fs_origin_vector *v) {
    return v ? v->entries : NULL;
}
static struct cached_view *find(struct cached_view *p, struct md_fd_identity id) {
    for (;p;p=p->next) if (md_fd_identity_same(p->identity,id)) return p;
    return NULL;
}
static int check_span(const struct span *s, unsigned max, unsigned *next, struct md_fs_origin_parcel *p, int graph) {
    if (s->start!=*next || !s->count || s->count>max || s->count>p->count-*next) return -EPROTO;
    struct md_fd_identity actual;
    int r=identity(p->fd[*next+(graph ? s->count-1 : 0)],&actual);
    if (!r && !md_fd_identity_same(actual,s->identity)) r=-EPROTO;
    *next+=s->count; return r;
}
static int validate(struct md_fs_origin_imports *s, const struct md_fd_message_route *route,
        struct md_fs_origin_parcel *p, struct manifest *m) {
    if (!p->fd || !p->count || p->count>MD_FS_ORIGIN_MAX_RIGHTS) return -EINVAL;
    int *sorted=calloc(p->count,sizeof(int));
    if (!sorted) return -ENOMEM;
    memcpy(sorted,p->fd,p->count*sizeof(int)); qsort(sorted,p->count,sizeof(int),compare_fd);
    int r=0;
    for (unsigned i=0;!r && i<p->count;++i) {
        int flags=fcntl(sorted[i],F_GETFD);
        if (flags<0) r=-errno;
        else if (!(flags&FD_CLOEXEC) || (i && sorted[i]==sorted[i-1])) r=-EPROTO;
    }
    free(sorted);
    if (r) return r;
    r=manifest_read(p->fd[0],m);
    if (r) return r;
    if (m->rights!=p->count || m->route.count!=m->count) return -EPROTO;
    if (memcmp(route,&m->route,sizeof(*route))) return -ESTALE;
    if (!md_fd_identity_same(m->store,s->store)) return -EXDEV;
    unsigned next=1;
    for (unsigned i=0;!r && i<m->owners;++i) r=check_span(&m->owner[i],MD_INODE_CUSTODY_FDS,&next,p,0);
    for (unsigned i=0;!r && i<m->views;++i) r=check_span(&m->view[i],MD_MOUNT_GRAPH_FDS,&next,p,1);
    for (unsigned i=0;!r && i<m->origins;++i) {
        struct origin *o=&m->origin[i]; struct md_fd_identity actual;
        if (o->view>=m->views || o->owner>=m->owners || o->descriptor!=next || next>=p->count) return -EPROTO;
        r=path_identity(p->fd[next++],&actual);
        if (!r && !md_fd_identity_same(actual,o->identity)) r=-EPROTO;
        if (!r) {
            if (next>=p->count) r=-EPROTO; else ++next;
        }
    }
    if (!r && next!=p->count) r=-EPROTO;
    /* Canonical first-use indices forbid unused owner records and gaps. Zero
     * vector entries are unknown; graph/owner indices inside origins are zero-based. */
    unsigned origins=0, views=0, owners=0;
    for (unsigned i=0;!r && i<m->count;++i) {
        unsigned n=m->index[i];
        if (n>m->origins || n>origins+1) return -EPROTO;
        if (n!=origins+1) continue;
        ++origins; struct origin *o=&m->origin[n-1];
        if (o->view>views || o->owner>owners) return -EPROTO;
        if (o->view==views) ++views;
        if (o->owner==owners) ++owners;
    }
    if (!r && (origins!=m->origins || views!=m->views || owners!=m->owners)) r=-EPROTO;
    return r;
}
static int take(struct md_fs_origin_parcel *p, unsigned slot) { int fd=p->fd[slot]; p->fd[slot]=-1; return fd; }
static int import(struct md_fs_origin_imports *s, const struct md_fd_message_route *route,
        struct md_fs_origin_parcel *p, struct md_fs_origin_vector **out) {
    if (!s || !route || !out || *out) return -EINVAL;
    struct manifest m;
    int r=validate(s,route,p,&m);
    if (r) return r;
    struct md_inode_lifetime *owners[MAX]={0};
    struct md_mount_namespace *views[MAX]={0};
    struct md_fs_anchor *anchors[MAX]={0};
    struct cached_view *pending=NULL;
    struct md_fs_origin_vector *v=calloc(1,sizeof(*v)+m.count*sizeof(*v->entries));
    if (!v) return -ENOMEM;
    v->count=m.count;
    for (unsigned i=0;!r && i<m.owners;++i) {
        struct span *b=&m.owner[i]; struct md_inode_custody_parcel parcel={.count=b->count};
        for (unsigned j=0;j<b->count;++j) parcel.fd[j]=take(p,b->start+j);
        r=md_inode_custody_import(&parcel,s->root,&owners[i]);
    }
    for (unsigned i=0;!r && i<m.views;++i) {
        struct span *b=&m.view[i];
        struct md_mount_graph_parcel parcel={.count=b->count,.fd=calloc(b->count,sizeof(int))};
        if (!parcel.fd) { r=-ENOMEM; break; }
        for (unsigned j=0;j<b->count;++j) parcel.fd[j]=take(p,b->start+j);
        struct cached_view *known=find(s->views,b->identity);
        if (!known) known=find(pending,b->identity);
        struct md_mount_namespace *view=known ? known->view : NULL;
        r=md_mount_graph_import(&parcel,&view);
        if (!r && !known) {
            struct cached_view *entry=calloc(1,sizeof(*entry));
            if (!entry) { md_mount_namespace_release(view); r=-ENOMEM; }
            else { entry->identity=b->identity; entry->view=view; entry->next=pending; pending=entry; }
        }
        if (!r) views[i]=view;
    }
    for (unsigned i=0;!r && i<m.origins;++i) {
        struct origin *o=&m.origin[i]; struct md_mount_namespace *view=views[o->view];
        if (o->mount && (!view->tree || o->mount>view->tree->count)) { r=-EPROTO; break; }
        struct md_view_mount *mount=o->mount ? &view->tree->mounts[o->mount-1] : &view->base;
        if (!mount->id || o->generation!=mount->generation) {
            r=-ESTALE; break;
        }
        struct md_fs_anchor *a=md_view_anchor_import(owners[o->owner],view,
            mount,p->fd[o->descriptor],p->fd[o->descriptor+1],
            o->identity.device,o->identity.inode);
        if (!a) { r=-errno; break; }
        a->endpoint=o->endpoint;
        take(p,o->descriptor);
        take(p,o->descriptor+1);
        anchors[i]=a;
        if (o->fifo_channel[0]) {
            char channel[33]={0}; memcpy(channel,o->fifo_channel,32);
            r=md_inode_fifo_adopt(a->lifetime,channel,a->fd,&a->fifo_custody);
        } else {
            for (unsigned j=1;j<sizeof(o->fifo_channel);++j)
                if (o->fifo_channel[j]) { r=-EPROTO; break; }
        }
    }
    if (!r) {
        for (unsigned i=0;i<m.count;++i) if (m.index[i]) v->entries[i]=md_fs_anchor_retain(anchors[m.index[i]-1]);
        while (pending) { struct cached_view *next=pending->next; pending->next=s->views; s->views=pending; pending=next; }
        *out=v;
    } else md_fs_origin_vector_free(v);
    for (unsigned i=0;i<m.origins;++i) md_fs_anchor_release(anchors[i]);
    for (unsigned i=0;i<m.owners;++i) md_inode_lifetime_release(owners[i]);
    views_free(pending);
    if (!r) md_fs_origin_imports_collect(s);
    return r;
}
int md_fs_origin_import(struct md_fs_origin_imports *s, const struct md_fd_message_route *route,
        struct md_fs_origin_parcel *p, struct md_fs_origin_vector **out) {
    if (!p) return -EINVAL;
    int r=import(s,route,p,out); md_fs_origin_parcel_close(p); return r;
}
