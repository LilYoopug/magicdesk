#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int writable(unsigned flags) {
    return !(flags & O_PATH) && (flags & (O_ACCMODE | O_TRUNC | O_CREAT));
}
static int reopen(struct md_view_object *p, int flags, int mutable,
        struct md_open_completion *completion) {
    if (p->mount->readonly && (mutable || writable(flags))) return -EROFS;
    return md_reopen_file(p->fd,flags,completion);
}
static void result_stat(struct md_fs_result *out, int fd, const struct md_view_mount *mount) {
    struct stat st;
    if (fstat(fd, &st)) out->error = -errno;
    else {
        md_fs_stat_info(&st, &out->info);
        out->info.mount_id=mount->id;
    }
}
static int record(struct md_filesystem *fs, int fd, struct md_view_mount *mount, struct md_fs_result *out) {
    if (fd < 0) return -errno;
    struct md_view_object *object;
    int r = md_view_record(fs, fd, mount, &object);
    if (r) close(fd); else out->fd = fd;
    return r;
}
static int descriptor(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    const struct md_fs_anchor *origin=q->origin[0];
    if (origin && !origin->mount) return 0;
    struct md_filesystem owner=*fs;
    if (origin) owner.mounts=origin->view;
    struct md_view_object *p = NULL;
    struct md_view_object retained={0};
    int r=0;
    if (origin) {
        retained.fd=origin->fd; retained.mount=origin->mount; p=&retained;
        if (q->operation==MD_FS_OBJECT_ID) r=md_view_record(&owner,q->directory[0],origin->mount,&p);
    } else r=md_view_identity(fs,q->directory[0],&p);
    if (r == -EXDEV) return 0;
    if (r) { out->error = r; return 1; }
    size_t capacity = output ? output->capacity : 0;
    void *data = output ? output->data : NULL;
    switch (q->operation) {
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
    case MD_FS_SETCAP: case MD_FS_REMOVECAP: case MD_FS_SETACL: case MD_FS_REMOVEACL:
        /* Real directory attachments retain host ownership and kernel checks.
         * The adapter handles EXDEV through the same readonly-aware reopen. */
        r = p->mount->readonly ? -EROFS : -EXDEV; break;
    case MD_FS_GETCAP: case MD_FS_GETACL: case MD_FS_LISTATTR: r = -EXDEV; break;
    case MD_FS_ACCESS:
        if (q->flags&~MD_AT_EACCESS || q->mode&~(R_OK|W_OK|X_OK)) r=-EINVAL;
        else if (p->mount->readonly && (q->mode&W_OK)) r=-EROFS;
        else if (syscall(SYS_faccessat2,p->fd,"",q->mode,AT_EMPTY_PATH|q->flags)) r=-errno;
        break;
    case MD_FS_XATTR_OPEN:
        r = p->mount->readonly && (q->mode & W_OK) ? -EROFS : -EXDEV; break;
    case MD_FS_FSTAT: result_stat(out, q->directory[0], p->mount); break;
    case MD_FS_STATFS: md_fs_statfs_result(q->directory[0],out,output); break;
    case MD_FS_READLINK: {
        if (!data || !capacity) { r=-EINVAL; break; }
        ssize_t n=readlinkat(q->directory[0],"",data,capacity);
        if (n<0) r=-errno; else out->size=(size_t)n;
        break;
    }
    case MD_FS_REOPEN:
        r = reopen(p, (int)q->flags, !!(q->mode&MD_FS_REOPEN_MUTABLE), &out->open_completion);
        if (r >= 0) { out->fd = r; r = 0; md_view_capture(fs,owner.mounts,p->mount,out,output); }
        break;
    case MD_FS_OBJECT_ID:
        if (!data || capacity < sizeof(p->id)) r = -ERANGE;
        else { memcpy(data, p->id, sizeof(p->id)); out->size = sizeof(p->id); }
        break;
    case MD_FS_PATH:
        if (!data || !capacity) r = -ERANGE;
        else if (owner.mounts!=fs->mounts) r=-ENOENT;
        else {
            r = md_view_path(fs, q->directory[0], p->mount, data, capacity);
            if (!r) out->size = strlen(data)+1;
        }
        break;
    case MD_FS_SEEKDIR: {
        off_t pos = lseek(q->directory[0], q->offset, (int)q->flags);
        if (pos < 0) r = -errno; else out->position = pos;
        break;
    }
    case MD_FS_GETDENTS: {
        if (!data || !capacity) { r = -EINVAL; break; }
        int fd = q->directory[0];
        off_t before = lseek(fd, 0, SEEK_CUR);
        if (before < 0) { r = -errno; break; }
        size_t count = q->capacity < capacity ? q->capacity : capacity;
        ssize_t n = syscall(SYS_getdents64, fd, data, count);
        if (n < 0) { r = -errno; break; }
        /* Native and inode directories share the same publish-before-commit
         * contract. Restore on rejected output; never redispatch the read. */
        if (output->directory_position) {
            off_t next=lseek(fd,0,SEEK_CUR);
            if (next<0) r=-errno;
            else *output->directory_position=next;
        } else if (output->deliver) r = output->deliver(output->context, data, (size_t)n);
        if (r || output->directory_position) { if (lseek(fd, before, SEEK_SET) < 0) r = -errno; }
        if (!r) out->size = (size_t)n;
        break;
    }
    default: return 0;
    }
    if (r) out->error = r;
    return 1;
}
static int has_path(unsigned operation) {
    switch (operation) {
    case MD_FS_CREATE: case MD_FS_OPEN: case MD_FS_MKDIR: case MD_FS_MKNOD: case MD_FS_SYMLINK:
    case MD_FS_READLINK: case MD_FS_LINK: case MD_FS_UNLINK: case MD_FS_RENAME:
    case MD_FS_STAT: case MD_FS_STATFS: case MD_FS_REALPATH: case MD_FS_OPEN_IMAGE:
    case MD_FS_SOCKET_BIND: case MD_FS_SOCKET_ADDRESS:
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
        return 1;
    default: return 0;
    }
}
static int follow(const struct md_fs_request *q) {
    switch (q->operation) {
    case MD_FS_OPEN: case MD_FS_OPEN_IMAGE:
        return (q->flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) ? -1 : !(q->flags & O_NOFOLLOW);
    case MD_FS_STAT: case MD_FS_ACCESS:
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
        return !(q->flags & AT_SYMLINK_NOFOLLOW);
    case MD_FS_LINK: return !!(q->flags & AT_SYMLINK_FOLLOW);
    case MD_FS_CREATE: case MD_FS_MKDIR: case MD_FS_MKNOD: case MD_FS_SYMLINK:
    case MD_FS_UNLINK: case MD_FS_RENAME: case MD_FS_SOCKET_BIND: return -1;
    case MD_FS_READLINK: return 0;
    default: return 1;
    }
}
static int missing(const struct md_fs_request *q) {
    if (q->operation == MD_FS_MKDIR) return 2;
    return q->operation == MD_FS_CREATE || q->operation == MD_FS_MKNOD || q->operation == MD_FS_SYMLINK
        || q->operation == MD_FS_SOCKET_BIND || (q->operation == MD_FS_OPEN && (q->flags & O_CREAT));
}
static int mutates(const struct md_fs_request *q) {
    switch (q->operation) {
    case MD_FS_CREATE: case MD_FS_MKDIR: case MD_FS_MKNOD: case MD_FS_SYMLINK: case MD_FS_LINK:
    case MD_FS_UNLINK: case MD_FS_RENAME: case MD_FS_SOCKET_BIND:
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
        return 1;
    case MD_FS_OPEN: return writable(q->flags);
    default: return 0;
    }
}
static int mounted_root(const struct md_view_location *p) {
    if (p->fd < 0 || !p->mount) return 0;
    struct stat st;
    return !fstat(p->fd, &st) && md_view_same(&st, &p->mount->native);
}
static void inode(struct md_filesystem *fs, struct md_mount_namespace *view,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    int foreign=view!=fs->mounts;
    if (foreign && (q->operation==MD_FS_PATH || q->operation==MD_FS_REALPATH || q->operation==MD_FS_OPEN_IMAGE)) {
        *out=(struct md_fs_result){.fd=-1,.error=-ENOENT}; return;
    }
    struct md_filesystem owner=*fs; owner.mounts=view;
    /* A root in another tree cannot clamp relative inode traversal. The worker
     * owns this borrowed context and restores it before handling another call. */
    const char *root_id=fs->store->root_id;
    if (foreign) fs->store->root_id=NULL;
    md_fs_inode_execute(&owner,q,out,output);
    fs->store->root_id=root_id;
}
static void native(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_view_location *a, struct md_view_location *b,
        struct md_fs_result *out, const struct md_fs_output *output) {
    int r = 0;
    struct md_filesystem owner=*fs; owner.mounts=a->view;
    void *data = output ? output->data : NULL;
    size_t capacity = output ? output->capacity : 0;
    switch (q->operation) {
    case MD_FS_CHMOD: {
        struct stat st;
        if (fstat(a->fd,&st)) r=-errno;
        else if (S_ISLNK(st.st_mode)) r=-EOPNOTSUPP;
        else {
            char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",a->fd);
            if (fchmodat(AT_FDCWD,path,q->mode,0)) r=-errno;
        }
        break;
    }
    case MD_FS_CHOWN:
        if (fchownat(a->fd,"",q->attributes.uid,q->attributes.gid,AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)) r=-errno;
        break;
    case MD_FS_UTIMENS: {
        const struct timespec times[2]={{q->attributes.seconds[0],q->attributes.nanos[0]},
            {q->attributes.seconds[1],q->attributes.nanos[1]}};
        if (utimensat(a->fd,"",times,AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)) r=-errno;
        break;
    }
    case MD_FS_ACCESS:
        if (q->flags & ~(AT_SYMLINK_NOFOLLOW | MD_AT_EACCESS) || q->mode & ~(R_OK | W_OK | X_OK)) r = -EINVAL;
        else if ((q->mode & W_OK) && a->mount->readonly) r = -EROFS;
        else if (syscall(SYS_faccessat2, a->fd, "", q->mode, AT_EMPTY_PATH | q->flags)) r = -errno;
        break;
    case MD_FS_CREATE: case MD_FS_OPEN: case MD_FS_OPEN_IMAGE: {
        int flags = q->operation == MD_FS_CREATE ? O_RDWR | O_CREAT | O_EXCL
            : q->operation == MD_FS_OPEN_IMAGE ? O_RDONLY : (int)q->flags;
        if (flags & ~(O_ACCMODE | O_CLOEXEC | O_APPEND | O_TRUNC | O_NOFOLLOW | O_DIRECTORY | O_PATH
                | O_CREAT | O_EXCL | O_NONBLOCK | O_NOCTTY | O_LARGEFILE | O_SYNC | O_DSYNC | O_DIRECT)) { r = -ENOTSUP; break; }
        if ((flags & O_ACCMODE) == O_ACCMODE) { r = -EINVAL; break; }
        if (q->operation == MD_FS_OPEN_IMAGE && (!data || capacity < sizeof(struct md_image_identity))) { r = -ERANGE; break; }
        if (flags & O_PATH) flags &= O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC;
        if (((flags & O_TRUNC) && !(flags & O_ACCMODE))
                || ((flags & O_CREAT) && (flags & O_DIRECTORY))) { r = -EINVAL; break; }
        if ((flags & O_CREAT) && (q->mode & ~01777)) { r = -ENOTSUP; break; }
        struct stat existing;
        if (a->fd >= 0 && fstat(a->fd, &existing)) { r = -errno; break; }
        int fifo = a->fd >= 0 && S_ISFIFO(existing.st_mode);
        if (fifo && q->operation == MD_FS_OPEN_IMAGE) { r = -EACCES; break; }
        if (fifo && (flags & O_CREAT) && (flags & O_EXCL)) { r = -EEXIST; break; }
        if (fifo && (flags & O_DIRECTORY)) { r = -ENOTDIR; break; }
        int deferred = fifo && !(flags & O_PATH);
        int fd = deferred ? fcntl(a->fd, F_DUPFD_CLOEXEC, 3)
            : openat(a->parent, a->name, flags | O_NOFOLLOW | O_CLOEXEC, q->mode&~q->attributes.creation_mask);
        r = record(&owner, fd, a->mount, out);
        if (!r && deferred) out->open_completion.kind = MD_OPEN_FIFO;
        if (!r && q->operation == MD_FS_OPEN_IMAGE) {
            struct stat st;
            if (fstat(fd, &st)) r = -errno;
            else if (!S_ISREG(st.st_mode)) r = -EACCES;
            struct md_view_object *object;
            if (!r) r = md_view_record(&owner, fd, a->mount, &object);
            struct md_image_identity *identity = data;
            if (!r && a->view!=fs->mounts) r=-ENOENT;
            if (!r) r = md_view_path(fs, fd, a->mount, identity->path, sizeof(identity->path));
            if (!r) { memcpy(identity->object, object->id, sizeof(identity->object)); out->size = offsetof(struct md_image_identity, path)+strlen(identity->path)+1; }
            if (r) { close(out->fd); out->fd = -1; }
        }
        if (!r) md_view_capture(fs,a->view,a->mount,out,output);
        break;
    }
    case MD_FS_STAT:
        if (q->flags & ~AT_SYMLINK_NOFOLLOW) r = -EINVAL;
        else result_stat(out, a->fd, a->mount);
        break;
    case MD_FS_STATFS:
        md_fs_statfs_result(a->fd,out,output);
        break;
    case MD_FS_REALPATH:
        if (!data || !capacity) r = -ERANGE;
        else if (a->view!=fs->mounts) r=-ENOENT;
        else { r = md_view_path(fs, a->fd, a->mount, data, capacity); if (!r) out->size = strlen(data)+1; }
        break;
    case MD_FS_READLINK: {
        ssize_t n = data && capacity ? readlinkat(a->fd, "", data, capacity) : -1;
        if (n < 0) r = data && capacity ? -errno : -EINVAL; else out->size = (size_t)n;
        break;
    }
    case MD_FS_MKDIR: if (mkdirat(a->parent, a->name, q->mode&~q->attributes.creation_mask)) r = -errno; break;
    case MD_FS_MKNOD:
        if (mknodat(a->parent,a->name,q->mode&~q->attributes.creation_mask,0)) r=-errno;
        break;
    case MD_FS_SYMLINK: if (symlinkat(q->path[1], a->parent, a->name)) r = -errno; break;
    case MD_FS_UNLINK: if (unlinkat(a->parent, a->name, (int)q->flags)) r = -errno; break;
    case MD_FS_RENAME: if (syscall(SYS_renameat2, a->parent, a->name, b->parent, b->name, q->flags)) r = -errno; break;
    case MD_FS_LINK:
        if (q->flags & ~AT_SYMLINK_FOLLOW) r = -EINVAL;
        else if (linkat(a->parent, a->name, b->parent, b->name, 0)) r = -errno;
        break;
    default: r = -EOPNOTSUPP; break;
    }
    if (r) out->error = r;
}
static int local_inode_view(struct md_filesystem *fs, const struct md_fs_request *q) {
    if (md_mount_namespace_attached(fs->mounts) || fs->native_root || q->resolve) return 0;
    for (unsigned i=0;i<2;++i) {
        const struct md_fs_anchor *p=q->origin[i];
        if (p && (p->view!=fs->mounts || p->mount)) return 0;
    }
    for (unsigned i=0;i<2;++i) {
        const struct md_fs_anchor *p=q->origin[i];
        if (!p || (q->path[i] && *q->path[i]
                && (q->directory[i]==MD_INODE_ROOT || q->path[i][0]=='/'))) continue;
        int error=md_view_anchor_check(fs,q->directory[i],p);
        if (error) return error;
    }
    return 1;
}
void md_fs_mounts_execute(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    *out = (struct md_fs_result){.fd=-1};
    /* A same-view inode origin does not introduce a mount crossing. Let the
     * inode engine perform its one authoritative walk after origin validation. */
    int local=local_inode_view(fs,q);
    if (local) {
        if (local<0) out->error=local;
        else md_fs_inode_execute(fs,q,out,output);
        return;
    }
    if (q->operation == MD_FS_OPEN_OBJECT) {
        struct md_view_object *p=md_view_object(fs,q->path[0]);
        if (p) {
            if (writable(q->flags)) { out->error = -EACCES; return; }
            struct stat st;
            if (fstat(p->fd, &st)) { out->error = -errno; return; }
            if (!S_ISREG(st.st_mode)) { out->error = -EINVAL; return; }
            int fd = reopen(p, (int)q->flags, 0, &out->open_completion);
            if (fd < 0) out->error = fd; else out->fd = fd;
            md_view_capture(fs,fs->mounts,p->mount,out,output);
            return;
        }
    }
    if ((!has_path(q->operation) || !q->path[0] || !*q->path[0])
            && !(q->operation == MD_FS_ACCESS && q->path[0] && *q->path[0])) {
        if (q->origin[0]) {
            int error=md_view_anchor_check(fs,q->directory[0],q->origin[0]);
            if (error) { out->error=error; return; }
            if (q->operation==MD_FS_PATH && q->origin[0]->view!=fs->mounts) {
                out->error=-ENOENT; return;
            }
        }
        switch (q->operation) {
        case MD_FS_FSTAT: case MD_FS_STATFS: case MD_FS_PATH: case MD_FS_REOPEN: case MD_FS_GETDENTS: case MD_FS_READLINK:
        case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_ACCESS: case MD_FS_UTIMENS:
        case MD_FS_GETCAP: case MD_FS_SETCAP: case MD_FS_REMOVECAP:
        case MD_FS_GETACL: case MD_FS_SETACL: case MD_FS_REMOVEACL: case MD_FS_LISTATTR: case MD_FS_XATTR_OPEN:
        case MD_FS_SEEKDIR: case MD_FS_OBJECT_ID:
            if (descriptor(fs, q, out, output)) return;
        }
        if (q->operation==MD_FS_PATH && fs->native_root) { out->error=-ENOENT; return; }
        inode(fs,q->origin[0] ? q->origin[0]->view : fs->mounts,q,out,output);
        return;
    }
    struct md_view_location a = {.parent=-1,.fd=-1}, b = {.parent=-1,.fd=-1};
    int r = md_view_walk(fs, q->directory[0], q->origin[0], q->path[0], follow(q), missing(q), q->resolve, &a);
    int pair = q->operation == MD_FS_LINK || q->operation == MD_FS_RENAME;
    if (!r && pair) r = md_view_walk(fs, q->directory[1], q->origin[1], q->path[1], -1, 1, 0, &b);
    if (!r && pair && (a.view != b.view || a.mount != b.mount)) r = -EXDEV;
    if (!r && mutates(q) && a.mount && a.mount->readonly) r = -EROFS;
    if (!r && (q->operation == MD_FS_UNLINK || q->operation == MD_FS_RENAME)
            && (mounted_root(&a) || (pair && mounted_root(&b)))) r = -EBUSY;
    if (!r && a.mount) native(fs, q, &a, &b, out, output);
    else if (!r) {
        struct md_fs_request local = *q;
        local.directory[0] = a.parent; local.path[0] = a.name; local.resolve = 0;
        if (pair) { local.directory[1] = b.parent; local.path[1] = b.name; }
        inode(fs,a.view,&local,out,output);
    } else out->error = r;
    md_view_location_close(&a); md_view_location_close(&b);
}
