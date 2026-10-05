#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "linux_abi.h"
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
        r = md_view_fdpath(m->mounts[i].source, root, sizeof(root));
        if (r) return r;
        if (!beneath(path, root)) continue;
        if (mount) return -ENOTSUP;
        mount=&m->mounts[i];
    }
    return mount ? md_view_record(fs,fd,mount,out) : -EXDEV;
}
static int location_path(struct md_filesystem *fs, int fd, struct md_view_mount *m, char *out, size_t size) {
    if (!m) return md_inode_path(fs->store, fd, out, size);
    char root[PATH_MAX], path[PATH_MAX], target[PATH_MAX];
    struct stat st;
    if (fstat(fd, &st)) return -errno;
    if (!st.st_nlink) return -ENOENT;
    int r = md_view_fdpath(m->source, root, sizeof(root));
    if (!r) r = md_view_fdpath(fd, path, sizeof(path));
    if (!r && !beneath(path, root)) r = -EXDEV;
    if (!r) r = location_path(fs, m->target, m->parent, target, sizeof(target));
    if (!r) {
        const char *suffix = !strcmp(path,root) ? "" : path + (strlen(root) == 1 ? 0 : strlen(root));
        if (snprintf(out, size, "%s%s", target, suffix) >= (int)size) r = -ERANGE;
    }
    return r;
}
int md_view_path(struct md_filesystem *fs, int fd, struct md_view_mount *m, char *out, size_t size) {
    if (!fs->native_root) return location_path(fs,fd,m,out,size);
    struct md_view_mount *ancestor=m;
    while (ancestor && ancestor!=fs->native_root->mount) ancestor=ancestor->parent;
    if (!ancestor) return -ENOENT;
    char root[PATH_MAX], path[PATH_MAX];
    int r = location_path(fs,fs->native_root->fd,fs->native_root->mount,root,sizeof(root));
    if (!r) r = location_path(fs,fd,m,path,sizeof(path));
    if (!r && !beneath(path,root)) r = -ENOENT;
    if (!r) {
        const char *relative = !strcmp(path,root) ? "/" : path+strlen(root);
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
    int r = origin ? (origin->mount ? md_view_record(fs,fd,origin->mount,&p) : -EXDEV)
        : fs->mounts ? md_view_identity(fs,fd,&p) : -EXDEV;
    if (!r) {
        if (syscall(SYS_faccessat2,fd,"",X_OK,AT_EMPTY_PATH|MD_AT_EACCESS)) return -errno;
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
    return 0;
}
void md_fs_mounts_close(struct md_filesystem *fs) {
    md_mount_namespace_release(fs->mounts);
    fs->mounts = NULL; fs->native_root = NULL;
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
        m->source = m->target = -1; m->readonly = entry->readonly;
        r = md_mount_id_allocate(&m->id);
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

int md_fs_mounts_copy(struct md_filesystem *fs, const struct md_fs_location *root,
        struct md_mount_namespace **out, struct md_fs_location *copied_root) {
    if (!fs->mounts || !root || !out || !copied_root) return -EINVAL;
    struct md_view_object *origin=NULL;
    if (root->mount) {
        origin=md_view_object(fs,root->object);
        if (!origin || origin->mount->id!=root->mount) return -ESTALE;
    }
    struct md_mount_namespace *copy=md_mount_namespace_new();
    if (!copy) return -errno;
    struct md_fs_mounts *source=fs->mounts->tree;
    int r=0;
    if (source && source->count) {
        copy->tree=calloc(1,sizeof(*copy->tree));
        if (!copy->tree) r=-ENOMEM;
    }
    for (unsigned i=0; !r && source && i<source->count; ++i) {
        const struct md_view_mount *a=&source->mounts[i];
        struct md_view_mount *b=&copy->tree->mounts[i];
        *b=*a; b->source=b->target=-1;
        /* Count partially built entries so rollback closes every acquired FD. */
        ++copy->tree->count;
        b->parent=a->parent ? &copy->tree->mounts[a->parent-source->mounts] : NULL;
        r=md_mount_id_allocate(&b->id);
        if (!r && (b->source=fcntl(a->source,F_DUPFD_CLOEXEC,3))<0) r=-errno;
        if (!r && (b->target=fcntl(a->target,F_DUPFD_CLOEXEC,3))<0) r=-errno;
    }
    struct md_fs_location selected=*root;
    if (!r && origin) {
        struct md_filesystem candidate={.store=fs->store,.mounts=copy};
        struct md_view_mount *mount=&copy->tree->mounts[origin->mount-source->mounts];
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
