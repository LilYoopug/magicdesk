#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "linux_abi.h"
#include "mount_topology.h"
#include "fs_storage.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

int md_view_same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
struct md_view_mount *md_view_root_mount(struct md_filesystem *fs) {
    return fs->native_root ? fs->native_root->mount : !fs->mounts ? NULL
        : fs->store->root_id ? &fs->mounts->base : fs->mounts->root;
}
int md_view_root_fd(struct md_filesystem *fs) {
    struct md_view_mount *mount=md_view_root_mount(fs);
    int source=fs->native_root ? fs->native_root->fd
        : !md_view_base(fs->mounts,mount) ? mount->source : -1;
    if (source<0) return md_inode_open(fs->store,MD_INODE_ROOT,"/",O_PATH|O_DIRECTORY|O_CLOEXEC,0);
    int fd=fcntl(source,F_DUPFD_CLOEXEC,3); return fd<0 ? -errno : fd;
}
int md_view_fdpath(int fd, char *out, size_t capacity) {
    char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, out, capacity);
    if (n < 0) return -errno;
    if ((size_t)n >= capacity) return -ENAMETOOLONG;
    out[n] = 0; return 0;
}
static int beneath(const char *path, const char *parent) {
    size_t n = strlen(parent);
    if (n == 1 && parent[0] == '/') return path[0] == '/';
    return !strncmp(path, parent, n) && (!path[n] || path[n] == '/');
}
static unsigned bucket(const struct stat *st) {
    return (unsigned)(st->st_ino ^ (st->st_dev * 2654435761U)) % MD_VIEW_BUCKETS;
}
static unsigned id_bucket(const char *id) {
    unsigned hash = 2166136261U;
    for (unsigned i=0; id[i]; ++i) hash = (hash ^ (unsigned char)id[i]) * 16777619U;
    return hash % MD_VIEW_BUCKETS;
}
struct md_view_object *md_view_object(struct md_filesystem *fs, const char *id) {
    if (!md_mount_namespace_attached(fs->mounts) || !id) return NULL;
    for (struct md_view_object *p=fs->mounts->tree->by_id[id_bucket(id)]; p; p=p->id_next)
        if (!strcmp(p->id,id)) return p;
    return NULL;
}
static struct md_view_object *find(struct md_fs_mounts *m, const struct stat *st, struct md_view_mount *mount) {
    for (struct md_view_object *p = m->table[bucket(st)]; p; p = p->next)
        if (p->mount==mount && md_view_same(&p->identity, st)) return p;
    return NULL;
}
int md_view_record(struct md_filesystem *fs, int fd, struct md_view_mount *mount, struct md_view_object **out) {
    struct stat st;
    if (fstat(fd, &st)) return -errno;
    struct md_fs_mounts *m = fs->mounts->tree;
    struct md_view_object *p = find(m, &st, mount);
    if (p) { *out = p; return 0; }
    if (m->objects == MD_VIEW_OBJECT_LIMIT) return -ENFILE;
    p = calloc(1, sizeof(*p));
    if (!p) return -ENOMEM;
    char proc[64]; snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    p->fd = open(proc, O_PATH | O_CLOEXEC);
    if (p->fd < 0) { int r = -errno; free(p); return r; }
    if (md_view_inode(mount)) {
        struct md_inode_store *store;
        int r=md_fs_storage_get(fs,mount,&store);
        if (!r) r=md_inode_object_id(store,fd,p->inode);
        if (r) { close(p->fd); free(p); return r; }
    }
    unsigned char bytes[16];
    if (getrandom(bytes, sizeof(bytes), 0) != sizeof(bytes)) {
        int r = errno ? -errno : -EIO; close(p->fd); free(p); return r;
    }
    for (unsigned i = 0; i < sizeof(bytes); ++i) {
        p->id[2*i] = "0123456789abcdef"[bytes[i] >> 4];
        p->id[2*i+1] = "0123456789abcdef"[bytes[i] & 15];
    }
    p->identity = st; p->mount = mount;
    unsigned b = bucket(&st); p->next = m->table[b]; m->table[b] = p; ++m->objects;
    b = id_bucket(p->id); p->id_next = m->by_id[b]; m->by_id[b] = p;
    *out = p; return 0;
}
int md_view_identity(struct md_filesystem *fs, int fd, struct md_view_object **out) {
    *out = NULL;
    if (fd < 0 || !md_mount_namespace_attached(fs->mounts)) return -EXDEV;
    struct stat st;
    if (fstat(fd, &st)) return -errno;
    struct md_fs_mounts *m = fs->mounts->tree;
    struct md_view_object *p = NULL;
    for (struct md_view_object *entry=m->table[bucket(&st)]; entry; entry=entry->next) {
        if (!md_view_same(&entry->identity,&st)) continue;
        /* An unannotated FD cannot choose between identical native objects
         * reached through different mounts, even if their policies agree. */
        if (p) return -ENOTSUP;
        p=entry;
    }
    if (p) { *out = p; return 0; }
    /* Admit inherited/native descriptors only when their current dentry is in
     * an explicitly attached tree. Registered identities survive unlink/rename. */
    char path[PATH_MAX], root[PATH_MAX];
    int r = md_view_fdpath(fd, path, sizeof(path));
    if (r) return r;
    struct md_view_mount *mount=NULL;
    for (unsigned i = 0; i < m->count; ++i) {
        if (m->mounts[i].backing!=MD_MOUNT_NATIVE || m->mounts[i].detached) continue;
        r = md_view_fdpath(m->mounts[i].source, root, sizeof(root));
        if (r) return r;
        if (!beneath(path, root)) continue;
        if (mount) return -ENOTSUP;
        mount=&m->mounts[i];
    }
    return mount ? md_view_record(fs,fd,mount,out) : -EXDEV;
}
int md_view_backing_path(struct md_filesystem *fs, int fd, const struct md_view_mount *mount,
        char *out, size_t size) {
    if (mount && mount->devpts) {
        char name[32]; int r=md_devpts_name(mount->devpts,fd,name,sizeof(name));
        if (r) return r;
        int n=snprintf(out,size,"/%s",!strcmp(name,".") ? "" : name);
        return n<0 || (size_t)n>=size ? -ERANGE : 0;
    }
    if (!md_view_inode(mount)) return md_view_fdpath(fd,out,size);
    struct md_fs_storage_scope scope;
    int r=md_fs_storage_enter(fs,mount,&scope);
    if (r) return r;
    scope.store->root_id=NULL;
    r=md_inode_path(scope.store,fd,out,size);
    md_fs_storage_leave(&scope); return r;
}
static int location_path(struct md_filesystem *fs, int fd, struct md_view_mount *m, char *out, size_t size) {
    if (!m) m=&fs->mounts->base;
    if (m==&fs->mounts->base && m->source<0) return md_view_backing_path(fs,fd,m,out,size);
    if (m->detached) return -ENOENT;
    char root[PATH_MAX], path[PATH_MAX], target[PATH_MAX];
    struct stat st;
    if (fstat(fd, &st)) return -errno;
    if (!st.st_nlink) return -ENOENT;
    /* A mount root is named by its covered dentry, not by the backing
     * inode's aliases. File binds need no source-name reconstruction. */
    if (md_view_same(&st,&m->native)) {
        if (m->parent) return location_path(fs,m->target,m->parent,out,size);
        if (size<2) return -ERANGE;
        strcpy(out,"/"); return 0;
    }
    int r=md_view_backing_path(fs,m->source,m,root,sizeof(root));
    if (!r) r=md_view_backing_path(fs,fd,m,path,sizeof(path));
    if (!r && !beneath(path, root)) r = -EXDEV;
    if (!r) {
        if (m->parent) r=location_path(fs,m->target,m->parent,target,sizeof(target));
        else strcpy(target,"/");
    }
    if (!r) {
        const char *suffix = !strcmp(path,root) ? "" : path + (strlen(root) == 1 ? 0 : strlen(root));
        if (!strcmp(target,"/") && *suffix=='/') ++suffix;
        if (snprintf(out, size, "%s%s", target, suffix) >= (int)size) r = -ERANGE;
    }
    return r;
}
int md_view_path(struct md_filesystem *fs, int fd, struct md_view_mount *m, char *out, size_t size) {
    if (!fs->native_root && !fs->store->root_id) return location_path(fs,fd,m,out,size);
    if (fs->native_root) {
        struct md_view_mount *ancestor=m;
        while (ancestor && ancestor!=fs->native_root->mount) ancestor=ancestor->parent;
        if (!ancestor) return -ENOENT;
    }
    int root_fd=fs->native_root ? fs->native_root->fd
        : md_inode_open(fs->store,MD_INODE_ROOT,"/",O_PATH|O_DIRECTORY|O_CLOEXEC,0);
    if (root_fd<0) return root_fd;
    const char *selected=fs->store->root_id;
    /* Source and covered dentries belong to their backing filesystem. Apply
     * the process root only after composing the complete mount-tree path. */
    fs->store->root_id=NULL;
    char root[PATH_MAX], path[PATH_MAX];
    int r = location_path(fs,root_fd,fs->native_root ? fs->native_root->mount : NULL,root,sizeof(root));
    if (!r) r = location_path(fs,fd,m,path,sizeof(path));
    fs->store->root_id=selected;
    if (!fs->native_root) close(root_fd);
    if (!r && !beneath(path,root)) r = -ENOENT;
    if (!r) {
        const char *relative = !strcmp(path,root) ? "/" : path+(strlen(root)==1 ? 0 : strlen(root));
        if (strlen(relative)>=size) r=-ERANGE;
        else strcpy(out,relative);
    }
    return r;
}
int md_fs_root_capture(struct md_filesystem *fs, int fd, const struct md_fs_anchor *origin,
        struct md_fs_location *out) {
    *out = (struct md_fs_location){0};
    if (origin) {
        int error=md_view_anchor_check(fs,fd,origin);
        if (error) return error;
        if (origin->view!=fs->mounts) return -ESTALE;
    }
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
    struct md_view_object *p = NULL;
    /* Once materialized, the base keeps explicit location identities even if
     * it becomes root again. Empty initial roots must not depend on cache hits. */
    int r = origin ? (!md_view_base(fs->mounts,origin->mount) || fs->mounts->base.source>=0
        ? md_view_record(fs,fd,origin->mount,&p) : -EXDEV)
        : fs->mounts ? md_view_identity(fs,fd,&p) : -EXDEV;
    if (!r && md_view_base(fs->mounts,p->mount) && fs->mounts->base.source<0) r=-EXDEV;
    if (!r) {
        if (md_view_inode(p->mount)) {
            struct md_fs_request access={.operation=MD_FS_ACCESS,.directory={fd,-1},.mode=X_OK,.flags=MD_AT_EACCESS};
            struct md_fs_storage_scope scope;
            r=md_fs_storage_enter(fs,p->mount,&scope);
            if (!r) { r=md_inode_metadata(scope.store,&access); md_fs_storage_leave(&scope); }
            if (r) return r;
        } else if (syscall(SYS_faccessat2,fd,"",X_OK,AT_EMPTY_PATH|MD_AT_EACCESS)) return -errno;
        out->mount=p->mount->id; memcpy(out->object,p->id,sizeof(out->object));
        return 0;
    }
    if (r!=-EXDEV) return r;
    struct md_fs_request access={.operation=MD_FS_ACCESS,.directory={fd,-1},.mode=X_OK,.flags=MD_AT_EACCESS};
    r=md_inode_metadata(fs->store,&access);
    if (!r) r=md_inode_object_id(fs->store,fd,out->object);
    if (!r && !strcmp(out->object,MDI_ROOT)) out->object[0]=0;
    return r;
}
int md_fs_root_select(struct md_filesystem *fs, const struct md_fs_location *root) {
    fs->native_root=NULL;
    if (root->mount) {
        struct md_view_object *p=md_view_object(fs,root->object);
        if (!p || p->mount->id!=root->mount) return -ESTALE;
        fs->native_root=p;
    }
    fs->store->root_id=root->mount || !root->object[0] ? NULL : root->object;
    if (fs->native_root && md_view_inode(fs->native_root->mount)) {
        struct md_inode_store *store;
        int r=md_fs_storage_get(fs,fs->native_root->mount,&store);
        if (r) return r;
        if (store==fs->store) fs->store->root_id=fs->native_root->inode;
    }
    return 0;
}
int md_fs_root_is_mount_root(struct md_filesystem *fs, const struct md_fs_location *root) {
    if (!fs->mounts) return -EINVAL;
    if (!root->mount) return fs->mounts->root==&fs->mounts->base
        && (!root->object[0] || !strcmp(root->object,MDI_ROOT));
    struct md_view_object *p=md_view_object(fs,root->object);
    if (!p || p->mount->id!=root->mount) return -ESTALE;
    return p->mount==fs->mounts->root && md_view_same(&p->identity,&p->mount->native);
}
int md_fs_mounts_join_context(struct md_filesystem *fs, struct md_guest_domain *context) {
    if (!fs->mounts || !context) return -EINVAL;
    struct md_filesystem selected=*fs;
    selected.native_root=NULL;
    const char *previous=fs->store->root_id;
    fs->store->root_id=NULL;
    struct md_view_location root={.fd=-1,.parent=-1};
    int r=md_view_walk(&selected,AT_FDCWD,NULL,"/",1,0,0,&root);
    struct md_fs_anchor *origin=NULL;
    struct md_fs_location location;
    if (!r) {
        struct stat st;
        if (fstat(root.fd,&st)) r=-errno;
        int retained=r ? -1 : fcntl(root.fd,F_DUPFD_CLOEXEC,3);
        if (!r && retained<0) r=-errno;
        if (!r) {
            origin=md_view_anchor_new(md_inode_store_lifetime(fs->store),fs->mounts,root.mount,
                retained,st.st_dev,st.st_ino);
            if (!origin) { r=-errno; close(retained); }
        }
    }
    if (!r) r=md_fs_root_capture(&selected,root.fd,origin,&location);
    if (!r) r=md_domain_set_root(context,&location);
    if (!r) r=md_domain_set_cwd(context,origin);
    if (!r) md_domain_bind_mounts(context,fs->mounts);
    md_fs_anchor_release(origin); md_view_location_close(&root);
    fs->store->root_id=previous; return r;
}
void md_fs_mounts_close(struct md_filesystem *fs) {
    md_mount_namespace_release(fs->mounts);
    fs->mounts = NULL; fs->native_root = NULL;
    md_fs_storage_prune(fs->storage);
}
int md_fs_mounts_open(struct md_filesystem *fs, const struct md_fs_attachment *entries, unsigned count) {
    if (fs->mounts || count > MD_FS_MOUNTS_MAX) return -EINVAL;
    fs->mounts = md_mount_namespace_new();
    if (!fs->mounts) return -errno;
    if (!count) return 0;
    struct md_fs_mounts *tree = calloc(1,sizeof(*tree));
    if (!tree) { md_fs_mounts_close(fs); return -ENOMEM; }
    fs->mounts->tree = tree;
    int r = 0;
    for (unsigned i = 0; i < count && !r; ++i) {
        const struct md_fs_attachment *entry = &entries[i];
        struct md_view_mount *m = &tree->mounts[tree->count];
        m->generation=1;
        m->source = m->target = -1;
        r = md_mount_policy_set(&m->policy,entry->readonly ? MD_MOUNT_READONLY : 0);
        if (!r) r = md_mount_id_allocate(&m->id);
        if (r) break;
        if (!entry->source || !entry->target || entry->source[0] != '/' || entry->target[0] != '/') { r = -EINVAL; break; }
        m->source = open(entry->source, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (m->source < 0) { r = -errno; break; }
        struct md_view_location target_location;
        r = md_view_walk(fs, MD_INODE_ROOT, NULL, entry->target, 1, 0, 0, &target_location);
        if (r) break;
        m->target = target_location.fd; target_location.fd = -1;
        m->parent = target_location.mount;
        md_view_location_close(&target_location);
        if (fstat(m->source, &m->native) || fstat(m->target, &m->guest)) { r = -errno; break; }
        char source[PATH_MAX], target[PATH_MAX];
        r = md_view_fdpath(m->source, source, sizeof(source));
        if (!r && !S_ISDIR(m->guest.st_mode)) r = -ENOTDIR;
        if (!r) r = md_view_path(fs, m->target, m->parent, target, sizeof(target));
        if (!r && (!strcmp(target, "/") || beneath(target, "/dev") || beneath(target, "/proc") || beneath(target, "/sys"))) r = -EINVAL;
        for (unsigned j = 0; j < i && !r; ++j) {
            char other[PATH_MAX];
            r = md_view_fdpath(tree->mounts[j].source, other, sizeof(other));
            if (!r && (beneath(source, other) || beneath(other, source))) r = -EXDEV;
            struct md_view_mount *prior = &tree->mounts[j];
            if (!r) r = md_view_path(fs, prior->target, prior->parent, other, sizeof(other));
            /* Covering an existing subtree requires explicit mount-stack and
             * open-description ownership; never silently hide earlier entries. */
            if (!r && beneath(other, target)) r = -EBUSY;
        }
        if (!r) ++tree->count;
    }
    if (r) {
        struct md_view_mount *pending = &tree->mounts[tree->count];
        if (pending->source >= 0) close(pending->source);
        if (pending->target >= 0) close(pending->target);
    }
    if (r) md_fs_mounts_close(fs);
    return r;
}

int md_fs_mounts_copy_cwd(struct md_mount_namespace *source, struct md_mount_namespace *copy,
        const struct md_fs_anchor *cwd, struct md_fs_anchor **out) {
    if (!source || !copy || !out || *out) return -EINVAL;
    if (!cwd || cwd->view!=source) {
        *out=md_fs_anchor_retain((struct md_fs_anchor *)cwd); return 0;
    }
    struct md_view_mount *mount=&copy->base;
    if (!md_view_base(source,cwd->mount)) {
        unsigned i=0;
        while (source->tree && i<source->tree->count && cwd->mount!=&source->tree->mounts[i]) ++i;
        if (!source->tree || i==source->tree->count || !copy->tree || i>=copy->tree->count) return -ESTALE;
        mount=&copy->tree->mounts[i];
    }
    int fd=fcntl(cwd->fd,F_DUPFD_CLOEXEC,3);
    if (fd<0) return -errno;
    struct md_fs_anchor *p=md_view_anchor_new(cwd->lifetime,copy,mount,fd,cwd->device,cwd->inode);
    if (!p) { int r=-errno; close(fd); return r; }
    *out=p; return 0;
}
int md_fs_mounts_copy(struct md_filesystem *fs, const struct md_fs_location *root,
        struct md_mount_namespace **out, struct md_fs_location *copied_root) {
    if (!fs->mounts || !root || !out || !copied_root) return -EINVAL;
    unsigned order[MD_FS_MOUNTS_MAX+1];
    int valid=md_view_topology_order(fs->mounts,order);
    if (valid) return valid;
    struct md_view_object *origin=NULL;
    if (root->mount) {
        origin=md_view_object(fs,root->object);
        if (!origin || origin->mount->id!=root->mount) return -ESTALE;
    }
    struct md_mount_namespace *copy=md_mount_namespace_new();
    if (!copy) return -errno;
    md_mount_namespace_set_owner(copy,md_mount_namespace_owner(fs->mounts));
    atomic_store_explicit(&copy->managed_paths,md_mount_namespace_managed_paths(fs->mounts),memory_order_relaxed);
    copy->base.policy.local=md_mount_policy_flags(&fs->mounts->base.policy);
    copy->base.locked=fs->mounts->base.locked;
    copy->base.root_providers=fs->mounts->base.root_providers;
    struct md_fs_mounts *source=fs->mounts->tree;
    int r=0;
    if (source && source->count) {
        copy->tree=calloc(1,sizeof(*copy->tree));
        if (!copy->tree) r=-ENOMEM;
    }
    for (unsigned i=0; !r && source && i<source->count; ++i) {
        const struct md_view_mount *a=&source->mounts[i];
        struct md_view_mount *b=&copy->tree->mounts[i];
        int skip=0;
        for (const struct md_view_mount *p=a;p;p=p->parent)
            if (md_view_file_namespace(p->file)) { skip=1; break; }
        /* Mount-namespace files are not inherited by a namespace copy: doing
         * so would reverse the acyclic ownership ordering enforced at bind. */
        if (!a->id || skip) {
            *b=(struct md_view_mount){.source=-1,.target=-1,.detached=1,.generation=a->generation};
            ++copy->tree->count;
            continue;
        }
        /* Namespace copies get independent policy, even from a shared view. */
        *b=(struct md_view_mount){.source=-1,.target=-1,
            .backing=a->backing,.detached=a->detached,.locked=a->locked,.generation=a->generation,
            .root_providers=a->root_providers,
            .storage=md_inode_lifetime_retain(a->storage),
            .pid_namespace=md_pid_namespace_retain(a->pid_namespace),
            .devpts=md_devpts_retain(a->devpts),
            .cgroup=md_cgroup_retain(a->cgroup),
            .sysfs=md_sysfs_retain(a->sysfs),
            .ipc_namespace=md_ipc_namespace_retain(a->ipc_namespace),
            .file=md_control_file_retain(a->file),
            .policy={.local=md_mount_policy_flags(&a->policy)},.native=a->native,.guest=a->guest,
            .parent=!a->parent ? NULL : !md_view_base(fs->mounts,a->parent)
                ? &copy->tree->mounts[a->parent-source->mounts] : &copy->base};
        /* Count partially built entries so rollback closes every acquired FD. */
        ++copy->tree->count;
        r=md_mount_id_allocate(&b->id);
        if (!r && (b->source=fcntl(a->source,F_DUPFD_CLOEXEC,3))<0) r=-errno;
        if (!r && (b->target=fcntl(a->target,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    }
    if (!r && fs->mounts->base.source>=0) {
        const struct md_view_mount *a=&fs->mounts->base;
        copy->base.native=a->native; copy->base.guest=a->guest; copy->base.detached=a->detached;
        copy->base.parent=a->parent ? &copy->tree->mounts[a->parent-source->mounts] : NULL;
        copy->base.source=fcntl(a->source,F_DUPFD_CLOEXEC,3);
        if (copy->base.source<0) r=-errno;
        if (!r && (copy->base.target=fcntl(a->target,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    }
    if (!r && fs->mounts->root!=&fs->mounts->base)
        copy->root=&copy->tree->mounts[fs->mounts->root-source->mounts];
    struct md_fs_location selected=*root;
    if (!r && origin) {
        struct md_filesystem candidate={.store=fs->store,.storage=fs->storage,.mounts=copy};
        struct md_view_mount *mount=origin->mount==&fs->mounts->base ? &copy->base
            : &copy->tree->mounts[origin->mount-source->mounts];
        struct md_view_object *object;
        r=md_view_record(&candidate,origin->fd,mount,&object);
        if (!r) {
            selected.mount=mount->id;
            memcpy(selected.object,object->id,sizeof(selected.object));
        }
    }
    if (r) md_mount_namespace_release(copy);
    else { *out=copy; *copied_root=selected; }
    return r;
}
