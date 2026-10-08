#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "mount_topology.h"
#include "mount_graph.h"
#include "fs_storage.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <unistd.h>

static int is_root(const struct md_view_location *p) {
    struct stat st;
    return p->mount && !fstat(p->fd,&st) && md_view_same(&st,&p->mount->native);
}
static int operand(struct md_filesystem *fs, const struct md_fs_request *q, unsigned index,
        struct md_view_location *out) {
    int r=*q->path[index]
        ? md_view_walk(fs,q->directory[index],q->origin[index],q->path[index],1,0,MD_VIEW_TASK_PATH,out)
        : md_view_descriptor(fs,q->directory[index],q->origin[index],out);
    if (r==-EREMOTE && fs->store->boundary) fs->store->boundary->operand=index;
    return r;
}
static int descendant(const struct md_view_mount *child, const struct md_view_mount *parent) {
    for (;child;child=child->parent) if (child==parent) return 1;
    return 0;
}
static int beneath(struct md_filesystem *fs, int fd, const struct md_view_location *source) {
    char path[PATH_MAX], root[PATH_MAX];
    int r=md_view_backing_path(fs,source->fd,source->mount,root,sizeof(root));
    if (!r) r=md_view_backing_path(fs,fd,source->mount,path,sizeof(path));
    if (r) return r;
    size_t length=strlen(root);
    return !strncmp(root,path,length) && (length==1 || !path[length] || path[length]=='/');
}
static void discard(struct md_view_mount *m) {
    if (m->source>=0) close(m->source);
    if (m->target>=0) close(m->target);
    md_mount_policy_close(&m->policy);
    md_inode_lifetime_release(m->storage);
}
static int publish(struct md_filesystem *fs, unsigned first,
        struct md_view_mount *entries, unsigned count) {
    if (!fs->mounts->graph) return 0;
    struct md_fs_mounts *tree=fs->mounts->tree;
    if (first+count>MD_FS_MOUNTS_MAX) return -ENOSPC;
    for (unsigned i=0;i<count;++i) {
        if (!entries[i].id) continue;
        int r=md_mount_policy_share(&entries[i].policy);
        if (r<0) return r;
    }
    unsigned size=tree ? tree->count : 0;
    struct md_mount_layout layout={.base=&fs->mounts->base,.root=fs->mounts->root,
        .entries=entries,.count=count};
    if (!first && count>=size) return md_mount_graph_update(fs->mounts,&layout);
    struct md_view_mount candidate[MD_FS_MOUNTS_MAX];
    if (tree) memcpy(candidate,tree->mounts,size*sizeof(*candidate));
    memcpy(candidate+first,entries,count*sizeof(*entries));
    if (first+count>size) size=first+count;
    layout.entries=candidate; layout.count=size;
    return md_mount_graph_update(fs->mounts,&layout);
}
static int collect(struct md_filesystem *fs) {
    struct md_fs_mounts *tree=fs->mounts->tree;
    if (!tree) return 0;
    if (md_mount_graph_foreign(fs->mounts)) return -EPERM;
    unsigned retire[MD_FS_MOUNTS_MAX+1]={0}, order[MD_FS_MOUNTS_MAX+1];
    int leases[MD_FS_MOUNTS_MAX];
    for (unsigned i=0;i<MD_FS_MOUNTS_MAX;++i) leases[i]=-1;
    int r=md_view_topology_order(fs->mounts,order);
    if (r) return r;
    for (unsigned i=0;i<tree->count;++i) {
        struct md_view_mount *m=&tree->mounts[i];
        if (!m->id || !m->detached || atomic_load_explicit(&m->anchors,memory_order_relaxed)
                || (fs->native_root && fs->native_root->mount==m)
                || md_domain_mount_root_used(fs->mounts,m->id)) continue;
        r=md_mount_graph_exclude(fs->mounts,m,&leases[i]);
        if (r==-EBUSY) { r=0; continue; }
        if (r) break;
        retire[i+1]=1;
    }
    /* A retained child keeps its ancestors, including a detached subtree.
     * Independent OFD leases exclude new foreign origins until publication. */
    for (unsigned n=tree->count+1;n;--n) {
        unsigned i=order[n-1];
        struct md_view_mount *m=md_view_mount_node(fs->mounts,i);
        if (!retire[i] && m->parent) {
            unsigned parent=md_view_base(fs->mounts,m->parent) ? 0
                : (unsigned)(m->parent-tree->mounts)+1;
            retire[parent]=0;
        }
    }
    struct md_view_mount next[MD_FS_MOUNTS_MAX];
    memcpy(next,tree->mounts,tree->count*sizeof(*next));
    unsigned count=0;
    for (unsigned i=0;i<tree->count;++i) if (retire[i+1]) {
        next[i]=(struct md_view_mount){.source=-1,.target=-1,.detached=1,.generation=next[i].generation};
        ++count;
    }
    if (!r && count) r=publish(fs,0,next,tree->count);
    if (!r) for (unsigned i=0;i<tree->count;++i)
        if (retire[i+1]) md_view_mount_forget(tree,&tree->mounts[i]);
    for (unsigned i=0;i<tree->count;++i) if (leases[i]>=0) close(leases[i]);
    if (!r) md_fs_storage_prune(fs->storage);
    return r;
}
static int vacant(struct md_view_mount *entries, unsigned *count) {
    for (unsigned i=0;i<*count;++i)
        if (!entries[i].id && entries[i].generation<UINT64_MAX) return (int)i;
    if (*count==MD_FS_MOUNTS_MAX) return -ENOSPC;
    unsigned i=(*count)++;
    entries[i]=(struct md_view_mount){.source=-1,.target=-1}; return (int)i;
}
static int prepare(struct md_view_mount *out, int source, int target,
        struct md_view_mount *parent, enum md_mount_backing backing,
        struct md_inode_lifetime *storage, unsigned policy) {
    *out=(struct md_view_mount){.source=-1,.target=-1,.parent=parent,.backing=backing,
        .generation=out->generation+1,
        .storage=md_inode_lifetime_retain(storage)};
    atomic_init(&out->anchors,0);
    int r=md_mount_policy_set(&out->policy,policy);
    if (!r) r=md_mount_id_allocate(&out->id);
    if (!r && (out->source=fcntl(source,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    if (!r && (out->target=fcntl(target,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    if (!r && (fstat(out->source,&out->native) || fstat(out->target,&out->guest))) r=-errno;
    return r;
}
static int bind(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_view_location *target) {
    if (q->flags&~(MS_BIND|MS_REC)) return -ENOTSUP;
    struct md_view_location source={.fd=-1,.parent=-1};
    int r=collect(fs);
    int native_source=0;
    unsigned policy=0;
    if (!r && q->path[1] && !*q->path[1] && !q->origin[1]) {
        struct md_view_object *object=NULL;
        int found=md_view_identity(fs,q->directory[1],&object);
        char inode[33];
        if (found==-EXDEV) found=md_inode_object_id(fs->store,q->directory[1],inode);
        if (found==-EXDEV) {
            source.fd=fcntl(q->directory[1],F_DUPFD_CLOEXEC,3);
            if (source.fd<0) r=-errno;
            else native_source=1;
            struct statvfs info;
            if (!r && fstatvfs(source.fd,&info)) r=-errno;
            if (!r) policy=((info.f_flag&ST_RDONLY) ? MD_MOUNT_READONLY : 0)
                | ((info.f_flag&ST_NOSUID) ? MD_MOUNT_NOSUID : 0)
                | ((info.f_flag&ST_NODEV) ? MD_MOUNT_NODEV : 0)
                | ((info.f_flag&ST_NOEXEC) ? MD_MOUNT_NOEXEC : 0);
        } else if (found) r=found;
    }
    if (!r && !native_source) {
        r=operand(fs,q,1,&source);
        if (!r) policy=md_mount_policy_flags(source.mount ? &source.mount->policy : &source.view->base.policy);
    }
    struct md_view_mount next={.source=-1,.target=-1};
    if (!r && (fstat(source.fd,&next.native) || fstat(target->fd,&next.guest))) r=-errno;
    if (!r && !!S_ISDIR(next.native.st_mode)!=!!S_ISDIR(next.guest.st_mode)) r=-ENOTDIR;
    if (!r && !fs->mounts->tree) {
        fs->mounts->tree=calloc(1,sizeof(*fs->mounts->tree));
        if (!fs->mounts->tree) r=-ENOMEM;
    }
    struct md_fs_mounts *tree=fs->mounts->tree;
    struct md_view_mount pending[MD_FS_MOUNTS_MAX];
    unsigned count=tree ? tree->count : 0, prepared=0, slots[MD_FS_MOUNTS_MAX];
    if (tree) memcpy(pending,tree->mounts,count*sizeof(*pending));
    int root_slot=-1;
    if (!r) {
        root_slot=vacant(pending,&count);
        if (root_slot<0) r=root_slot;
    }
    if (!r) {
        slots[prepared++]=(unsigned)root_slot;
        r=prepare(&pending[root_slot],source.fd,target->fd,target->mount,
            !native_source && md_view_inode(source.mount) ? MD_MOUNT_INODE : MD_MOUNT_NATIVE,
            source.mount ? source.mount->storage : NULL,
            policy);
    }
    struct md_fs_mounts *original=source.view ? source.view->tree : NULL;
    if (!(q->flags&MS_REC)) for (unsigned i=0;!r && original && i<original->count;++i) {
        const struct md_view_mount *m=&original->mounts[i];
        if (!m->id || m->detached || !m->locked || m->parent!=source.mount) continue;
        int found=beneath(fs,m->target,&source);
        if (found) r=found<0 ? found : -EINVAL;
    }
    unsigned included[MD_FS_MOUNTS_MAX+1]={0};
    unsigned order[MD_FS_MOUNTS_MAX+1];
    if (!r && !native_source && (q->flags&MS_REC)) r=md_view_topology_order(source.view,order);
    unsigned nodes=native_source ? 0 : original ? original->count+1 : 1;
    if (q->flags&MS_REC) for (unsigned n=0;!r && n<nodes;++n) {
        unsigned i=order[n];
        struct md_view_mount *m=md_view_mount_node(source.view,i);
        if (!m->id || m->source<0 || m->detached || m==source.mount) continue;
        unsigned parent=(unsigned)root_slot;
        if (m->parent==source.mount) {
            int found=beneath(fs,m->target,&source);
            if (found<0) { r=found; break; }
            if (!found) continue;
        } else {
            parent=0;
            for (unsigned j=0;j<nodes;++j)
                if (m->parent==md_view_mount_node(source.view,j)) parent=included[j];
            if (!parent) continue;
            --parent;
        }
        int slot=vacant(pending,&count);
        if (slot<0) { r=slot; break; }
        included[i]=(unsigned)slot+1; slots[prepared++]=(unsigned)slot;
        r=prepare(&pending[slot],m->source,m->target,&tree->mounts[parent],
            m->backing,m->storage,md_mount_policy_flags(&m->policy));
        pending[slot].locked=m->locked;
    }
    /* No tree entry is visible until the complete recursive copy owns all its
     * descriptors. Failed preparation retires only the unpublished candidates. */
    if (!r) r=publish(fs,0,pending,count);
    if (!r) {
        for (unsigned i=0;i<prepared;++i) tree->mounts[slots[i]]=pending[slots[i]];
        tree->count=count;
    } else for (unsigned i=0;i<prepared;++i) discard(&pending[slots[i]]);
    md_view_location_close(&source); return r;
}
int md_view_attach_storage(struct md_filesystem *fs, struct md_inode_store *store, int source,
        const struct md_view_location *target, unsigned policy) {
    if (!fs || !fs->mounts || !fs->storage || !store || !target || target->view!=fs->mounts)
        return -EINVAL;
    struct stat st;
    int r=collect(fs);
    if (!r) r=md_inode_fstat(store,source,&st);
    if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
    if (!r && fstat(target->fd,&st)) r=-errno;
    if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
    if (r) return r;
    if (!r && !fs->mounts->tree) {
        fs->mounts->tree=calloc(1,sizeof(*fs->mounts->tree));
        if (!fs->mounts->tree) r=-ENOMEM;
    }
    if (r) return r;
    struct md_fs_mounts *tree=fs->mounts->tree;
    struct md_view_mount pending[MD_FS_MOUNTS_MAX];
    unsigned count=tree->count;
    memcpy(pending,tree->mounts,count*sizeof(*pending));
    int slot=vacant(pending,&count);
    if (slot<0) return slot;
    r=prepare(&pending[slot],source,target->fd,target->mount,MD_MOUNT_INODE,
        md_inode_store_lifetime(store),policy);
    if (!r) r=publish(fs,0,pending,count);
    if (!r) { tree->mounts[slot]=pending[slot]; tree->count=count; }
    else discard(&pending[slot]);
    return r;
}
static int unmount(struct md_filesystem *fs, const struct md_fs_request *q,
        const struct md_view_location *target) {
    if (q->flags&~MNT_DETACH) return -ENOTSUP;
    if (!is_root(target) || target->mount->detached) return -EINVAL;
    if (target->mount->locked) return -EINVAL;
    if (target->mount==fs->mounts->root) return -EBUSY;
    struct md_fs_mounts *tree=fs->mounts->tree;
    int lease=-1;
    if (!(q->flags&MNT_DETACH)) {
        if (atomic_load_explicit(&target->mount->anchors,memory_order_relaxed)) return -EBUSY;
        if ((fs->native_root && fs->native_root->mount==target->mount)
                || md_domain_mount_root_used(fs->mounts,target->mount->id)) return -EBUSY;
        if (!fs->mounts->base.detached && fs->mounts->base.parent==target->mount) return -EBUSY;
        for (unsigned i=0;i<tree->count;++i)
            if (!tree->mounts[i].detached && tree->mounts[i].parent==target->mount) return -EBUSY;
        int r=md_mount_graph_exclude(fs->mounts,target->mount,&lease);
        if (r) return r;
    }
    struct md_view_mount next[MD_FS_MOUNTS_MAX];
    memcpy(next,tree->mounts,tree->count*sizeof(*next));
    for (unsigned i=0;i<tree->count;++i)
        if (descendant(&tree->mounts[i],target->mount)) next[i].detached=1;
    struct md_view_mount base=fs->mounts->base;
    if (descendant(&base,target->mount) || target->mount==&fs->mounts->base) base.detached=1;
    struct md_mount_layout l={.base=&base,.entries=next,.count=tree->count,.root=fs->mounts->root};
    int r=md_mount_graph_update(fs->mounts,&l);
    if (!r) fs->mounts->base.detached=base.detached;
    if (!r) for (unsigned i=0;i<tree->count;++i)
        if (descendant(&tree->mounts[i],target->mount)) tree->mounts[i].detached=1;
    if (lease>=0) close(lease);
    return r;
}
static int move(struct md_filesystem *fs, const struct md_fs_request *q,
        const struct md_view_location *target) {
    if (q->flags!=MS_MOVE) return -ENOTSUP;
    struct md_view_location source={.fd=-1,.parent=-1};
    int r=operand(fs,q,1,&source);
    if (!r && (source.view!=fs->mounts || !is_root(&source) || source.mount->detached)) r=-EINVAL;
    if (!r && source.mount->locked) r=-EINVAL;
    if (!r && source.mount==fs->mounts->root) r=-EBUSY;
    if (!r && descendant(target->mount,source.mount)) r=-EINVAL;
    struct stat st;
    if (!r && fstat(target->fd,&st)) r=-errno;
    if (!r && !!S_ISDIR(st.st_mode)!=!!S_ISDIR(source.mount->native.st_mode)) r=-ENOTDIR;
    int covered=-1;
    if (!r && (covered=fcntl(target->fd,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    if (!r) {
        struct md_view_mount *m=source.mount;
        struct md_view_mount next=*m;
        next.target=covered; next.guest=st; next.parent=target->mount;
        if (m==&fs->mounts->base) {
            struct md_mount_layout l={.base=&next,.root=fs->mounts->root,
                .entries=fs->mounts->tree->mounts,.count=fs->mounts->tree->count};
            r=md_mount_graph_update(fs->mounts,&l);
        } else r=publish(fs,(unsigned)(m-fs->mounts->tree->mounts),&next,1);
    }
    if (!r) {
        struct md_view_mount *m=source.mount;
        int old=m->target;
        m->target=covered; m->guest=st; m->parent=target->mount;
        close(old);
    } else if (covered>=0) close(covered);
    md_view_location_close(&source); return r;
}
static int anchor(struct md_filesystem *fs, int fd, struct md_view_mount *mount,
        struct md_fs_anchor **out) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    int copy=fcntl(fd,F_DUPFD_CLOEXEC,3);
    if (copy<0) return -errno;
    *out=md_view_anchor_new(md_inode_store_lifetime(fs->store),fs->mounts,mount,copy,st.st_dev,st.st_ino);
    if (!*out) { int r=-errno; close(copy); return r; }
    return 0;
}
static int pivot(struct md_filesystem *fs, struct md_guest_domain *context,
        const struct md_fs_request *q, const struct md_view_location *next) {
    if (q->flags) return -EINVAL;
    if (!context) return -EINVAL;
    struct md_view_mount *old=md_view_root_mount(fs);
    if (!is_root(next)) return -EINVAL;
    if (old->detached || next->mount->detached) return -EINVAL;
    if (next->mount->locked) return -EINVAL;
    if (old==next->mount) return -EBUSY;
    if (!descendant(next->mount,old)) return -EINVAL;
    int root_fd=md_view_root_fd(fs);
    if (root_fd<0) return root_fd;
    struct md_view_mount base=fs->mounts->base;
    int initialized=0, r=0;
    if (old==&fs->mounts->base && base.source<0) {
        const char *selected=fs->store->root_id; fs->store->root_id=NULL;
        base.source=md_inode_open(fs->store,MD_INODE_ROOT,"/",O_PATH|O_DIRECTORY|O_CLOEXEC,0);
        fs->store->root_id=selected;
        if (base.source<0) r=base.source;
        else {
            initialized=1;
            base.target=fcntl(base.source,F_DUPFD_CLOEXEC,3);
            if (base.target<0) r=-errno;
            if (!r && fstat(base.source,&base.native)) r=-errno;
            base.guest=base.native;
        }
    }
    const struct md_view_mount *previous=old==&fs->mounts->base ? &base : old;
    struct stat current;
    if (!r && fstat(root_fd,&current)) r=-errno;
    if (!r && !md_view_same(&current,&previous->native)) r=-EINVAL;
    struct md_view_location put={.fd=-1,.parent=-1};
    if (!r) r=operand(fs,q,1,&put);
    if (!r && put.view!=fs->mounts) r=-EINVAL;
    if (!r && put.mount==old) r=-EBUSY;
    if (!r && !descendant(put.mount,next->mount)) r=-EINVAL;
    struct stat st;
    if (!r && fstat(put.fd,&st)) r=-errno;
    if (!r && (!S_ISDIR(st.st_mode) || !S_ISDIR(next->mount->native.st_mode))) r=-ENOTDIR;
    if (!r && !st.st_nlink) r=-ENOENT;
    struct md_fs_anchor *from=NULL, *to=NULL;
    struct md_fs_location before, after;
    if (!r) r=anchor(fs,root_fd,old,&from);
    if (!r) r=anchor(fs,next->fd,next->mount,&to);
    if (!r) r=md_fs_root_capture(fs,root_fd,from,&before);
    if (!r) r=md_fs_root_capture(fs,next->fd,to,&after);
    int covered=-1;
    if (!r && (covered=fcntl(put.fd,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    int inherited_target=previous->target;
    struct stat inherited_guest=previous->guest;
    struct md_view_mount *inherited_parent=previous->parent;
    if (!r) {
        struct md_fs_mounts *tree=fs->mounts->tree;
        struct md_view_mount pending[MD_FS_MOUNTS_MAX];
        memcpy(pending,tree->mounts,tree->count*sizeof(*pending));
        struct md_view_mount *a=old==&fs->mounts->base ? &base : &pending[old-tree->mounts];
        struct md_view_mount *b=next->mount==&fs->mounts->base ? &base : &pending[next->mount-tree->mounts];
        b->target=inherited_target; b->guest=inherited_guest; b->parent=inherited_parent;
        a->target=covered; a->guest=st; a->parent=put.mount;
        if (a->locked) { b->locked=1; a->locked=0; }
        struct md_mount_layout l={.base=&base,.entries=pending,.count=tree->count,
            .root=old==fs->mounts->root ? next->mount : fs->mounts->root};
        r=md_mount_graph_update(fs->mounts,&l);
    }
    if (!r) {
        /* Both mount placements and all process-location replacements are
         * prepared before publication. Stable mount objects keep old FD
         * provenance; only root/cwd references exactly at the old root move. */
        struct md_view_mount *new=next->mount;
        close(new->target); new->target=inherited_target; new->guest=inherited_guest; new->parent=inherited_parent;
        if (initialized) { old->source=base.source; old->native=base.native; }
        old->target=covered; old->guest=st; old->parent=put.mount;
        if (old->locked) { new->locked=1; old->locked=0; }
        if (fs->mounts->root==old) fs->mounts->root=new;
        md_domain_relocate_roots(fs->mounts,&before,&after,from,to);
        md_domain_relocate_root(context,&before,&after,from,to);
    } else {
        if (covered>=0) close(covered);
        if (initialized) {
            close(base.source);
            if (inherited_target>=0) close(inherited_target);
        }
    }
    close(root_fd);
    md_fs_anchor_release(from); md_fs_anchor_release(to);
    md_view_location_close(&put); return r;
}
int md_fs_mount_change(struct md_filesystem *fs, struct md_guest_domain *context,
        const struct md_fs_request *q) {
    if (!fs->mounts) return -ENOTSUP;
    if (!fs->store->identity || !md_identity_capable_in(fs->store->identity,
            md_mount_namespace_owner(fs->mounts),CAP_SYS_ADMIN)) return -EPERM;
    /* Release unused detached storage before a filesystem reserves shared
     * resources such as overlay upper/work directories. Live origins retain
     * their mount pins; collection never infers closure from a pathname. */
    int r=(q->mode==MD_FS_MOUNT_BIND || q->mode==MD_FS_MOUNT_TMPFS || q->mode==MD_FS_MOUNT_OVERLAY)
        ? collect(fs) : 0;
    struct md_view_location target={.fd=-1,.parent=-1};
    if (!r) r=operand(fs,q,0,&target);
    if (!r && target.view!=fs->mounts) r=-EINVAL;
    if (!r) switch (q->mode) {
    case MD_FS_MOUNT_BIND:
        r=bind(fs,q,&target); break;
    case MD_FS_MOUNT_UMOUNT:
        r=unmount(fs,q,&target); break;
    case MD_FS_MOUNT_MOVE:
        r=move(fs,q,&target); break;
    case MD_FS_MOUNT_PIVOT:
        r=pivot(fs,context,q,&target); break;
    case MD_FS_MOUNT_REMOUNT:
        if (q->flags&~(MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC)) r=-ENOTSUP;
        else {
            struct md_view_mount *mount=target.mount;
            if (!is_root(&target)) {
                if (md_view_base(fs->mounts,mount) && !strcmp(q->path[0],"/"))
                    mount=&fs->mounts->base;
                else r=-EINVAL;
            }
            if (!r && !(q->flags&MS_RDONLY) && md_view_inode(mount)) {
                struct md_inode_store *store=NULL;
                r=md_fs_storage_get(fs,mount,&store);
                if (!r && store->readonly) r=-EROFS;
            }
            if (!r) r=md_mount_policy_set(&mount->policy,md_fs_mount_flags(q->flags));
        }
        break;
    case MD_FS_MOUNT_PROPAGATION: {
        unsigned kind=q->flags&~MS_REC;
        if (!kind || (kind&(kind-1)) || (kind&~(MS_PRIVATE|MS_SLAVE|MS_SHARED|MS_UNBINDABLE))) r=-EINVAL;
        else if (!is_root(&target) && strcmp(q->path[0],"/")) r=-EINVAL;
        /* Every admitted mount is private: SLAVE without a peer/master stays
         * private, including recursively. Never pretend to create a peer group. */
        else if (kind!=MS_PRIVATE && kind!=MS_SLAVE) r=-ENOTSUP;
        break;
    }
    case MD_FS_MOUNT_TMPFS:
        r=md_fs_mount_temporary(fs,q,&target); break;
    case MD_FS_MOUNT_OVERLAY:
        r=md_fs_mount_overlay(fs,q,&target); break;
    default: r=-ENOTSUP; break;
    }
    md_view_location_close(&target); return r;
}
