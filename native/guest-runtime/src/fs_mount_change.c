#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "mount_topology.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int is_root(const struct md_view_location *p) {
    struct stat st;
    return p->mount && !fstat(p->fd,&st) && md_view_same(&st,&p->mount->native);
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
static int prepare(struct md_view_mount *out, int source, int target,
        struct md_view_mount *parent, enum md_mount_backing backing,
        struct md_inode_lifetime *storage, unsigned policy) {
    *out=(struct md_view_mount){.source=-1,.target=-1,.parent=parent,.backing=backing,
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
    int r=md_view_walk(fs,q->directory[1],q->origin[1],q->path[1],1,0,0,&source);
    struct md_view_mount next={.source=-1,.target=-1};
    if (!r && (fstat(source.fd,&next.native) || fstat(target->fd,&next.guest))) r=-errno;
    if (!r && !!S_ISDIR(next.native.st_mode)!=!!S_ISDIR(next.guest.st_mode)) r=-ENOTDIR;
    if (!r && !fs->mounts->tree) {
        fs->mounts->tree=calloc(1,sizeof(*fs->mounts->tree));
        if (!fs->mounts->tree) r=-ENOMEM;
    }
    struct md_fs_mounts *tree=fs->mounts->tree;
    if (!r && tree->count==MD_FS_MOUNTS_MAX) r=-ENOSPC;
    struct md_view_mount pending[MD_FS_MOUNTS_MAX];
    unsigned count=0;
    if (!r) {
        r=prepare(&pending[count++],source.fd,target->fd,target->mount,
            md_view_inode(source.mount) ? MD_MOUNT_INODE : MD_MOUNT_NATIVE,
            source.mount ? source.mount->storage : NULL,
            md_mount_policy_flags(source.mount ? &source.mount->policy : &source.view->root_policy));
    }
    struct md_fs_mounts *original=source.view ? source.view->tree : NULL;
    unsigned included[MD_FS_MOUNTS_MAX]={0};
    unsigned order[MD_FS_MOUNTS_MAX];
    if (!r && (q->flags&MS_REC)) r=md_view_topology_order(original,order);
    if (q->flags&MS_REC) for (unsigned n=0;!r && original && n<original->count;++n) {
        unsigned i=order[n];
        struct md_view_mount *m=&original->mounts[i];
        if (m->detached || m==source.mount) continue;
        unsigned parent=0;
        if (m->parent==source.mount) {
            int found=beneath(fs,m->target,&source);
            if (found<0) { r=found; break; }
            if (!found) continue;
        } else {
            for (unsigned j=0;j<original->count;++j) if (m->parent==&original->mounts[j]) parent=included[j];
            if (!parent) continue;
            --parent;
        }
        if (tree->count+count==MD_FS_MOUNTS_MAX) { r=-ENOSPC; break; }
        included[i]=count+1;
        r=prepare(&pending[count++],m->source,m->target,&tree->mounts[tree->count+parent],
            m->backing,m->storage,md_mount_policy_flags(&m->policy));
    }
    /* No tree entry is visible until the complete recursive copy owns all its
     * descriptors. Failed preparation retires only the unpublished candidates. */
    if (!r) { memcpy(tree->mounts+tree->count,pending,count*sizeof(*pending)); tree->count+=count; }
    else for (unsigned i=0;i<count;++i) discard(&pending[i]);
    md_view_location_close(&source); return r;
}
int md_view_attach_storage(struct md_filesystem *fs, struct md_inode_store *store, int source,
        const struct md_view_location *target, unsigned policy) {
    if (!fs || !fs->mounts || !fs->storage || !store || !target || target->view!=fs->mounts)
        return -EINVAL;
    if (fs->mounts->graph) return -ENOTSUP;
    if (fs->mounts->tree && fs->mounts->tree->count==MD_FS_MOUNTS_MAX) return -ENOSPC;
    struct stat st;
    int r=md_inode_fstat(store,source,&st);
    if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
    if (!r && fstat(target->fd,&st)) r=-errno;
    if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
    if (r) return r;
    struct md_view_mount next;
    r=prepare(&next,source,target->fd,target->mount,MD_MOUNT_INODE,
        md_inode_store_lifetime(store),policy);
    if (!r && !fs->mounts->tree) {
        fs->mounts->tree=calloc(1,sizeof(*fs->mounts->tree));
        if (!fs->mounts->tree) r=-ENOMEM;
    }
    if (!r) fs->mounts->tree->mounts[fs->mounts->tree->count++]=next;
    else discard(&next);
    return r;
}
static int unmount(struct md_filesystem *fs, const struct md_fs_request *q,
        const struct md_view_location *target) {
    if (q->flags&~MNT_DETACH) return -ENOTSUP;
    if (!is_root(target) || target->mount->detached) return -EINVAL;
    struct md_fs_mounts *tree=fs->mounts->tree;
    if (!(q->flags&MNT_DETACH)) {
        if (atomic_load_explicit(&target->mount->anchors,memory_order_relaxed)) return -EBUSY;
        if ((fs->native_root && fs->native_root->mount==target->mount)
                || md_domain_mount_root_used(fs->mounts,target->mount->id)) return -EBUSY;
        for (unsigned i=0;i<tree->count;++i)
            if (!tree->mounts[i].detached && tree->mounts[i].parent==target->mount) return -EBUSY;
    }
    for (unsigned i=0;i<tree->count;++i)
        if (descendant(&tree->mounts[i],target->mount)) tree->mounts[i].detached=1;
    return 0;
}
static int move(struct md_filesystem *fs, const struct md_fs_request *q,
        const struct md_view_location *target) {
    if (q->flags!=MS_MOVE) return -ENOTSUP;
    struct md_view_location source={.fd=-1,.parent=-1};
    int r=md_view_walk(fs,q->directory[1],q->origin[1],q->path[1],1,0,0,&source);
    if (!r && (source.view!=fs->mounts || !is_root(&source) || source.mount->detached)) r=-EINVAL;
    if (!r && descendant(target->mount,source.mount)) r=-EINVAL;
    struct stat st;
    if (!r && fstat(target->fd,&st)) r=-errno;
    if (!r && !!S_ISDIR(st.st_mode)!=!!S_ISDIR(source.mount->native.st_mode)) r=-ENOTDIR;
    int covered=-1;
    if (!r && (covered=fcntl(target->fd,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    if (!r) {
        struct md_view_mount *m=source.mount;
        int old=m->target;
        m->target=covered; m->guest=st; m->parent=target->mount;
        close(old);
    }
    md_view_location_close(&source); return r;
}
static int anchor(struct md_filesystem *fs, int fd, struct md_view_mount *mount,
        struct md_fs_anchor **out) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    int copy=fcntl(fd,F_DUPFD_CLOEXEC,3);
    if (copy<0) return -errno;
    *out=md_view_anchor_new(md_inode_store_lifetime(fs->store),fs->mounts,mount,copy,st.st_dev,st.st_ino);
    if (!*out) { close(copy); return -ENOMEM; }
    return 0;
}
static int pivot(struct md_filesystem *fs, struct md_guest_domain *context,
        const struct md_fs_request *q, const struct md_view_location *next) {
    if (q->flags) return -EINVAL;
    if (!context || !fs->native_root) return -EINVAL;
    struct md_view_object *root=fs->native_root;
    struct md_view_mount *old=root->mount;
    if (!is_root(next) || !md_view_same(&root->identity,&old->native)) return -EINVAL;
    if (old->detached || next->mount->detached) return -EINVAL;
    if (old==next->mount) return -EBUSY;
    if (!descendant(next->mount,old)) return -EINVAL;
    struct md_view_location put={.fd=-1,.parent=-1};
    int r=md_view_walk(fs,q->directory[1],q->origin[1],q->path[1],1,0,0,&put);
    if (!r && put.view!=fs->mounts) r=-EINVAL;
    if (!r && put.mount==old) r=-EBUSY;
    if (!r && !descendant(put.mount,next->mount)) r=-EINVAL;
    struct stat st;
    if (!r && fstat(put.fd,&st)) r=-errno;
    if (!r && (!S_ISDIR(st.st_mode) || !S_ISDIR(next->mount->native.st_mode))) r=-ENOTDIR;
    if (!r && !st.st_nlink) r=-ENOENT;
    struct md_fs_anchor *from=NULL, *to=NULL;
    struct md_fs_location before, after;
    if (!r) r=anchor(fs,root->fd,old,&from);
    if (!r) r=anchor(fs,next->fd,next->mount,&to);
    if (!r) r=md_fs_root_capture(fs,root->fd,from,&before);
    if (!r) r=md_fs_root_capture(fs,next->fd,to,&after);
    int covered=-1;
    if (!r && (covered=fcntl(put.fd,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    if (!r) {
        /* Both mount placements and all process-location replacements are
         * prepared before publication. Stable mount objects keep old FD
         * provenance; only root/cwd references exactly at the old root move. */
        struct md_view_mount *new=next->mount;
        close(new->target); new->target=old->target; new->guest=old->guest; new->parent=old->parent;
        old->target=covered; old->guest=st; old->parent=put.mount;
        md_domain_relocate_roots(fs->mounts,&before,&after,from,to);
        md_domain_relocate_root(context,&before,&after,from,to);
    }
    md_fs_anchor_release(from); md_fs_anchor_release(to);
    md_view_location_close(&put); return r;
}
int md_fs_mount_change(struct md_filesystem *fs, struct md_guest_domain *context,
        const struct md_fs_request *q) {
    if (!fs->mounts) return -ENOTSUP;
    if (!fs->store->identity || !md_identity_capable(fs->store->identity,CAP_SYS_ADMIN)) return -EPERM;
    struct md_view_location target={.fd=-1,.parent=-1};
    int r=md_view_walk(fs,q->directory[0],q->origin[0],q->path[0],1,0,0,&target);
    if (!r && target.view!=fs->mounts) r=-EINVAL;
    if (!r) switch (q->mode) {
    case MD_FS_MOUNT_BIND:
        r=fs->mounts->graph ? -ENOTSUP : bind(fs,q,&target); break;
    case MD_FS_MOUNT_UMOUNT:
        r=fs->mounts->graph ? -ENOTSUP : unmount(fs,q,&target); break;
    case MD_FS_MOUNT_MOVE:
        r=fs->mounts->graph ? -ENOTSUP : move(fs,q,&target); break;
    case MD_FS_MOUNT_PIVOT:
        r=fs->mounts->graph ? -ENOTSUP : pivot(fs,context,q,&target); break;
    case MD_FS_MOUNT_REMOUNT:
        if (q->flags&~(MS_REMOUNT|MS_BIND|MS_RDONLY)) r=-ENOTSUP;
        else if (target.mount && is_root(&target))
            r=md_mount_policy_set(&target.mount->policy,(q->flags&MS_RDONLY) ? MD_MOUNT_READONLY : 0);
        else if (!target.mount && !strcmp(q->path[0],"/"))
            r=md_mount_policy_set(&fs->mounts->root_policy,(q->flags&MS_RDONLY) ? MD_MOUNT_READONLY : 0);
        else r=-EINVAL;
        break;
    case MD_FS_MOUNT_PRIVATE:
        if (q->flags&~(MS_PRIVATE|MS_REC)) r=-ENOTSUP;
        else if (!is_root(&target) && strcmp(q->path[0],"/")) r=-EINVAL;
        break;
    default: r=-ENOTSUP; break;
    }
    md_view_location_close(&target); return r;
}
