#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "fs_storage.h"
#include "linux_abi.h"
#include "procfs_view.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/magic.h>
#include <sys/sysmacros.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void inode(struct md_filesystem *, struct md_mount_namespace *, struct md_view_mount *,
        const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
static int writable(unsigned flags) {
    return !(flags & O_PATH) && (flags & (O_ACCMODE | O_TRUNC | O_CREAT));
}
static int device_open(const struct md_view_mount *mount, int flags, mode_t mode) {
    return !(flags&O_PATH) && (S_ISCHR(mode) || S_ISBLK(mode))
        && (md_mount_policy_flags(&mount->policy)&MD_MOUNT_NODEV) ? -EACCES : 0;
}
static int execute_access(const struct md_view_mount *mount, int fd, unsigned mode) {
    if (!(mode&X_OK) || !mount || !(md_mount_policy_flags(&mount->policy)&MD_MOUNT_NOEXEC)) return 0;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    return S_ISREG(st.st_mode) ? -EACCES : 0;
}
static int reopen(struct md_view_object *p, int flags, int mutable,
        struct md_open_completion *completion) {
    if (md_view_readonly(p->mount) && (mutable || writable(flags))) return -EROFS;
    struct stat st;
    if (fstat(p->fd,&st)) return -errno;
    int error=device_open(p->mount,flags,st.st_mode);
    if (error) return error;
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
static int devpts_operation(struct md_filesystem *fs,struct md_mount_namespace *view,
        struct md_view_mount *mount,int fd,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!mount || !mount->devpts) return 0;
    const struct md_identity *id=fs->store->identity;
    int r=0;
    switch (q->operation) {
    case MD_FS_STATFS:
        md_fs_statfs_result(fd,md_mount_policy_flags(&mount->policy),NULL,out,output);
        if (!out->error) ((struct md_fs_statfs *)output->data)->type=DEVPTS_SUPER_MAGIC;
        break;
    case MD_FS_STAT: case MD_FS_FSTAT: {
        struct stat st; r=md_devpts_stat(mount->devpts,fd,&st);
        if (!r) { md_fs_stat_info(&st,&out->info); out->info.mount_id=mount->id; }
        break;
    }
    case MD_FS_ACCESS:
        if (q->flags&~(AT_SYMLINK_NOFOLLOW|MD_AT_EACCESS)) r=-EINVAL;
        else if ((q->mode&W_OK) && md_view_readonly(mount)) r=-EROFS;
        else {
            struct md_identity actor=*id;
            if (!(q->flags&MD_AT_EACCESS)) { actor.uid.fs=actor.uid.real; actor.gid.fs=actor.gid.real; }
            r=md_devpts_access(mount->devpts,fd,q->mode,&actor);
        }
        break;
    case MD_FS_CHMOD:
        r=md_view_readonly(mount) ? -EROFS : md_devpts_chmod(mount->devpts,fd,q->mode,id); break;
    case MD_FS_CHOWN:
        r=md_view_readonly(mount) ? -EROFS : md_devpts_chown(mount->devpts,fd,q->attributes.uid,q->attributes.gid,id); break;
    case MD_FS_OPEN: case MD_FS_REOPEN: {
        if (md_view_readonly(mount) && writable(q->flags)) { r=-EROFS; break; }
        if (!(q->flags&O_PATH) && (q->flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) { r=-EEXIST; break; }
        struct stat st;
        if (fstat(fd,&st)) { r=-errno; break; }
        r=device_open(mount,q->flags,st.st_mode); if (r) break;
        if (!(q->flags&(O_PATH|O_NOCTTY)) && S_ISCHR(st.st_mode)
                && !(major(st.st_rdev)==5 && minor(st.st_rdev)==2)) {
            /* Controlling-terminal acquisition belongs to the caller's session,
             * not to the namespace worker opening its retained path. */
            r=md_devpts_access(mount->devpts,fd,(q->flags&O_ACCMODE)==O_RDWR ? R_OK|W_OK
                : (q->flags&O_ACCMODE)==O_WRONLY ? W_OK : R_OK,id);
            if (!r) {
                r=fcntl(fd,F_DUPFD_CLOEXEC,3);
                if (r<0) r=-errno;
                else out->open_completion.kind=MD_OPEN_CALLER;
            }
        } else r=md_devpts_open(mount->devpts,fd,q->flags,id);
        if (r>=0) { out->fd=r; r=0; md_view_capture(fs,view,mount,out,output); }
        break;
    }
    case MD_FS_MKDIR: case MD_FS_CREATE: case MD_FS_MKNOD: case MD_FS_SYMLINK:
    case MD_FS_UNLINK: case MD_FS_RENAME: case MD_FS_LINK: case MD_FS_UTIMENS:
        r=-EPERM; break;
    default: return 0;
    }
    if (r) out->error=r;
    return 1;
}
static int descriptor(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    const struct md_fs_anchor *origin=q->origin[0];
    if (origin && q->operation==MD_FS_ACCESS) {
        int error=execute_access(origin->mount,q->directory[0],q->mode);
        if (error) { out->error=error; return 1; }
    }
    if (origin && md_view_inode(origin->mount)
            && !(!md_view_base(origin->view,origin->mount) && q->operation==MD_FS_OBJECT_ID)) return 0;
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
    if (!md_view_inode(p->mount) && (r=md_fs_landlock_native(fs,q,p->mount,q->directory[0]))) {
        out->error=r; return 1;
    }
    if (md_fs_mount_file_operation(fs,owner.mounts,p->mount,q->directory[0],q,out,output)) return 1;
    if (md_fs_proc_operation(fs,owner.mounts,p->mount,q->directory[0],q,out,output)) return 1;
    if (devpts_operation(fs,owner.mounts,p->mount,q->directory[0],q,out,output)) return 1;
    if (md_fs_cgroup_operation(fs,owner.mounts,p->mount,q->directory[0],-1,NULL,q,out,output)) return 1;
    if (md_fs_sysfs_operation(fs,owner.mounts,p->mount,q->directory[0],q,out,output)) return 1;
    if (md_fs_mqueue_operation(fs,owner.mounts,p->mount,q->directory[0],q,out,output)) return 1;
    if (q->operation==MD_FS_ACCESS && (r=execute_access(p->mount,q->directory[0],q->mode))) {
        out->error=r; return 1;
    }
    if (md_view_inode(p->mount) && q->operation!=MD_FS_OBJECT_ID) {
        if (q->operation==MD_FS_PATH) {
            out->error=!output || !output->data ? -EINVAL
                : md_view_path(fs,q->directory[0],p->mount,output->data,output->capacity);
            if (!out->error) out->size=strlen(output->data)+1;
        } else inode(fs,owner.mounts,p->mount,q,out,output);
        return 1;
    }
    size_t capacity = output ? output->capacity : 0;
    void *data = output ? output->data : NULL;
    switch (q->operation) {
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
    case MD_FS_SETCAP: case MD_FS_REMOVECAP: case MD_FS_SETACL: case MD_FS_REMOVEACL:
        /* Real directory attachments retain host ownership and kernel checks.
         * The adapter handles EXDEV through the same readonly-aware reopen. */
        r = md_view_readonly(p->mount) ? -EROFS : -EXDEV; break;
    case MD_FS_GETCAP: case MD_FS_GETACL: r = -EXDEV; break;
    case MD_FS_ACCESS:
        if (q->flags&~MD_AT_EACCESS || q->mode&~(R_OK|W_OK|X_OK)) r=-EINVAL;
        else if (md_view_readonly(p->mount) && (q->mode&W_OK)) r=-EROFS;
        else if (syscall(SYS_faccessat2,p->fd,"",q->mode,AT_EMPTY_PATH|q->flags)) r=-errno;
        break;
    case MD_FS_XATTR_OBJECT:
        r = md_view_readonly(p->mount) && (q->mode==MD_FS_XATTR_SET || q->mode==MD_FS_XATTR_REMOVE)
            ? -EROFS : -EXDEV; break;
    case MD_FS_FSTAT: result_stat(out, q->directory[0], p->mount); break;
    case MD_FS_STATFS: md_fs_statfs_result(q->directory[0],md_mount_policy_flags(&p->mount->policy),NULL,out,output); break;
    case MD_FS_READLINK: {
        if (!data || !capacity) { r=-EINVAL; break; }
        ssize_t n=p->mount->backing==MD_MOUNT_PROC
            ? md_procfs_readlink(fs,p->mount,q->directory[0],data,capacity)
            : readlinkat(q->directory[0],"",data,capacity);
        if (n<0) r=p->mount->backing==MD_MOUNT_PROC ? (int)n : -errno; else out->size=(size_t)n;
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
        ssize_t n = p->mount->backing==MD_MOUNT_PROC ? md_procfs_getdents(p->mount,fd,data,count)
            : p->mount->devpts ? md_devpts_getdents(p->mount->devpts,fd,data,count)
            : syscall(SYS_getdents64, fd, data, count);
        if (n < 0) { r=p->mount->backing==MD_MOUNT_PROC || p->mount->devpts ? (int)n : -errno; break; }
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
static int mutates(const struct md_fs_request *q, const struct md_view_location *location) {
    switch (q->operation) {
    case MD_FS_CREATE: case MD_FS_MKDIR: case MD_FS_MKNOD: case MD_FS_SYMLINK: case MD_FS_LINK:
    case MD_FS_UNLINK: case MD_FS_RENAME: case MD_FS_SOCKET_BIND:
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS:
        return 1;
    case MD_FS_OPEN: return writable(q->flags&~(location->fd>=0 ? O_CREAT : 0));
    default: return 0;
    }
}
static int mounted_root(const struct md_view_location *p) {
    if (p->fd < 0 || !p->mount) return 0;
    struct stat st;
    return !fstat(p->fd, &st) && md_view_same(&st, &p->mount->native);
}
static int selected_operation(unsigned operation) {
    switch (operation) {
    case MD_FS_CREATE: case MD_FS_OPEN: case MD_FS_OPEN_IMAGE: case MD_FS_STAT: case MD_FS_STATFS:
    case MD_FS_ACCESS: case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS: case MD_FS_READLINK:
        return 1;
    default: return 0;
    }
}
static void inode(struct md_filesystem *fs, struct md_mount_namespace *view, struct md_view_mount *mount,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    int foreign=view!=fs->mounts;
    if (foreign && (q->operation==MD_FS_PATH || q->operation==MD_FS_REALPATH || q->operation==MD_FS_OPEN_IMAGE)) {
        *out=(struct md_fs_result){.fd=-1,.error=-ENOENT}; return;
    }
    struct md_filesystem owner=*fs; owner.mounts=view; owner.inode_mount=mount;
    /* A root in another tree cannot clamp relative inode traversal. The worker
     * owns this borrowed context and restores it before handling another call. */
    struct md_fs_storage_scope scope;
    int r=md_fs_storage_enter(fs,mount,&scope);
    if (r) { *out=(struct md_fs_result){.fd=-1,.error=r}; return; }
    owner.selected_store=scope.store;
    if (foreign) scope.store->root_id=NULL;
    md_fs_inode_execute(&owner,q,out,output);
    md_fs_storage_leave(&scope);
}
static void inode_selected(struct md_filesystem *fs, const struct md_fs_request *q,
        const struct md_view_location *a, struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_fs_request local=*q;
    local.directory[0]=a->fd; local.path[0]=NULL; local.origin[0]=NULL;
    local.directory[1]=-1; local.path[1]=NULL; local.origin[1]=NULL; local.resolve=0;
    if (q->operation==MD_FS_STAT) local.operation=MD_FS_FSTAT;
    if (q->operation==MD_FS_OPEN || q->operation==MD_FS_CREATE || q->operation==MD_FS_OPEN_IMAGE) {
        unsigned flags=q->operation==MD_FS_CREATE ? O_RDWR|O_CREAT|O_EXCL
            : q->operation==MD_FS_OPEN_IMAGE ? O_RDONLY|O_CLOEXEC : q->flags;
        if (!(flags&O_PATH) && (flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) {
            out->error=-EEXIST; return;
        }
        struct stat st;
        if (fstat(a->fd,&st)) { out->error=-errno; return; }
        if (!(flags&O_PATH) && (flags&O_CREAT) && S_ISDIR(st.st_mode)) { out->error=-EISDIR; return; }
        if (q->operation==MD_FS_OPEN_IMAGE) {
            if (!output || !output->data || output->capacity<sizeof(struct md_image_identity)) {
                out->error=-ERANGE; return;
            }
            if (!S_ISREG(st.st_mode)) { out->error=-EACCES; return; }
            local.operation=MD_FS_ACCESS; local.flags=MD_AT_EACCESS; local.mode=X_OK;
            inode(fs,a->view,a->mount,&local,out,NULL);
            if (out->error) return;
        }
        local.operation=MD_FS_REOPEN; local.flags=flags&~(O_CREAT|O_EXCL); local.mode=0;
    }
    inode(fs,a->view,a->mount,&local,out,output);
    /* The selected FD preserves the object, not the caller's path syntax.
     * readlink(non-link) is EINVAL; readlinkat(fd, "") is ENOENT. */
    if (q->operation==MD_FS_READLINK && out->error==-ENOENT) {
        struct stat st;
        if (!fstat(a->fd,&st) && !S_ISLNK(st.st_mode)) out->error=-EINVAL;
    }
    if (out->error || q->operation!=MD_FS_OPEN_IMAGE) return;
    struct md_image_identity *identity=output->data;
    struct md_filesystem owner=*fs; owner.mounts=a->view;
    struct md_view_object *object=NULL;
    int r=a->view!=fs->mounts ? -ENOENT : md_view_record(&owner,a->fd,a->mount,&object);
    /* Named lookup already selected the dentry. Reconstructing the final
     * component from its inode loses hardlink identity unnecessarily. */
    if (!r && strcmp(a->name,".")) {
        r=md_view_path(fs,a->parent,a->mount,identity->path,sizeof(identity->path));
        if (!r) {
            size_t length=strlen(identity->path);
            int n=snprintf(identity->path+length,sizeof(identity->path)-length,"%s%s",
                length==1 ? "" : "/",a->name);
            if (n<0 || (size_t)n>=sizeof(identity->path)-length) r=-ERANGE;
        }
    } else if (!r) r=md_view_path(fs,a->fd,a->mount,identity->path,sizeof(identity->path));
    if (!r) {
        memcpy(identity->object,object->id,sizeof(identity->object));
        out->size=offsetof(struct md_image_identity,path)+strlen(identity->path)+1;
    } else {
        close(out->fd); out->fd=-1; out->error=r;
        if (output->origin) { md_fs_anchor_release(*output->origin); *output->origin=NULL; }
    }
}
static void native(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_view_location *a, struct md_view_location *b,
        struct md_fs_result *out, const struct md_fs_output *output) {
    int policy=md_fs_landlock_native(fs,q,a->mount,a->fd);
    if (policy) { out->error=policy; return; }
    if (md_fs_mount_file_operation(fs,a->view,a->mount,a->fd,q,out,output)) return;
    if (md_fs_proc_operation(fs,a->view,a->mount,a->fd,q,out,output)) return;
    if (devpts_operation(fs,a->view,a->mount,a->fd,q,out,output)) return;
    if (md_fs_cgroup_operation(fs,a->view,a->mount,a->fd,a->parent,a->name,q,out,output)) return;
    if (md_fs_sysfs_operation(fs,a->view,a->mount,a->fd,q,out,output)) return;
    if (md_fs_mqueue_operation(fs,a->view,a->mount,a->fd,q,out,output)) return;
    int r = 0;
    struct md_filesystem owner=*fs; owner.mounts=a->view;
    void *data = output ? output->data : NULL;
    size_t capacity = output ? output->capacity : 0;
    switch (q->operation) {
    case MD_FS_SOCKET_ADDRESS: {
        if (!(q->flags&MD_FS_SOCKET_PIN)) { r=-EOPNOTSUPP; break; }
        int fd=fcntl(a->fd,F_DUPFD_CLOEXEC,0);
        if (fd<0) r=-errno;
        else out->fd=fd;
        break;
    }
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
        else if ((q->mode & W_OK) && md_view_readonly(a->mount)) r = -EROFS;
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
        if (a->fd>=0 && (r=device_open(a->mount,flags,existing.st_mode))) break;
        int fifo = a->fd >= 0 && S_ISFIFO(existing.st_mode);
        if (fifo && q->operation == MD_FS_OPEN_IMAGE) { r = -EACCES; break; }
        if (fifo && (flags & O_CREAT) && (flags & O_EXCL)) { r = -EEXIST; break; }
        if (fifo && (flags & O_DIRECTORY)) { r = -ENOTDIR; break; }
        int deferred = fifo && !(flags & O_PATH);
        /* Proc entries can use namespace-visible PIDs. The walker has already
         * selected their native inode; replaying parent/name selects another
         * process when the logical and native PID numbers differ. */
        int selected=a->fd>=0 && (!strcmp(a->name,".") || a->mount->backing==MD_MOUNT_PROC);
        if (selected && !(flags&O_PATH) && (flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) { r=-EEXIST; break; }
        if (selected && !(flags&O_PATH) && (flags&O_CREAT) && S_ISDIR(existing.st_mode)) { r=-EISDIR; break; }
        int fd=selected ? md_reopen_file(a->fd,(flags&~(O_CREAT|O_EXCL))|O_CLOEXEC,&out->open_completion)
            : deferred ? fcntl(a->fd, F_DUPFD_CLOEXEC, 3)
            : openat(a->parent, a->name, flags | O_NOFOLLOW | O_CLOEXEC, q->mode&~q->attributes.creation_mask);
        r=selected && fd<0 ? fd : record(&owner,fd,a->mount,out);
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
        md_fs_statfs_result(a->fd,md_mount_policy_flags(&a->mount->policy),NULL,out,output);
        break;
    case MD_FS_REALPATH:
        if (!data || !capacity) r = -ERANGE;
        else if (a->view!=fs->mounts) r=-ENOENT;
        else { r = md_view_path(fs, a->fd, a->mount, data, capacity); if (!r) out->size = strlen(data)+1; }
        break;
    case MD_FS_READLINK: {
        if (!data || !capacity) { r=-EINVAL; break; }
        ssize_t n = a->mount->backing==MD_MOUNT_PROC ? md_procfs_readlink(fs,a->mount,a->fd,data,capacity)
            : readlinkat(a->fd, "", data, capacity);
        if (n < 0) r=a->mount->backing==MD_MOUNT_PROC ? (int)n : -errno; else out->size = (size_t)n;
        /* This branch resolved a nonempty pathname; descriptor-only requests
         * retain the kernel's empty-path errno in descriptor(). */
        if (r==-ENOENT && a->mount->backing!=MD_MOUNT_PROC) {
            struct stat st;
            if (!fstat(a->fd,&st) && !S_ISLNK(st.st_mode)) r=-EINVAL;
        }
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
    if (q->operation==MD_FS_ACCESS && (q->mode&X_OK) && fs->mounts
            && (md_mount_policy_flags(&fs->mounts->base.policy)&MD_MOUNT_NOEXEC)) return 0;
    for (unsigned i=0;i<2;++i) {
        const struct md_fs_anchor *p=q->origin[i];
        if (p && (p->view!=fs->mounts || !md_view_base(p->view,p->mount))) return 0;
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
    if (q->operation==MD_FS_PATH && q->mode==MD_FS_PATH_DISPLAY && q->origin[0]
            && q->origin[0]->view && q->origin[0]->view!=fs->mounts) {
        out->error=md_view_anchor_check(fs,q->directory[0],q->origin[0]);
        if (!out->error && (!output || !output->data)) out->error=-EINVAL;
        if (!out->error) {
            struct md_filesystem owner=*fs;
            owner.mounts=q->origin[0]->view; owner.native_root=NULL;
            const char *root=fs->store->root_id;
            fs->store->root_id=NULL;
            out->error=md_view_path(&owner,q->directory[0],q->origin[0]->mount,output->data,output->capacity);
            fs->store->root_id=root;
            if (!out->error) out->size=strlen(output->data)+1;
        }
        return;
    }
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
            if (md_view_inode(p->mount)) {
                struct md_fs_request local={.operation=MD_FS_REOPEN,.directory={p->fd,-1},.flags=q->flags};
                inode(fs,fs->mounts,p->mount,&local,out,output); return;
            }
            struct stat st;
            if (fstat(p->fd, &st)) { out->error = -errno; return; }
            if (!S_ISREG(st.st_mode)) { out->error = -EINVAL; return; }
            int policy=md_fs_landlock_native(fs,q,p->mount,p->fd);
            if (policy) { out->error=policy; return; }
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
        case MD_FS_GETACL: case MD_FS_SETACL: case MD_FS_REMOVEACL: case MD_FS_XATTR_OBJECT:
        case MD_FS_SEEKDIR: case MD_FS_OBJECT_ID:
            if (descriptor(fs, q, out, output)) return;
        }
        if (q->operation==MD_FS_PATH && fs->native_root && !q->origin[0]) {
            char inode[33];
            int known=md_inode_object_id(fs->store,q->directory[0],inode);
            /* An unannotated inode cannot choose a bind alias. A native
             * provider FD remains task-owned across pivot_root, however. */
            out->error=known==-EXDEV ? -EXDEV : known ? known : -ENOENT;
            return;
        }
        const struct md_fs_anchor *origin=q->origin[0];
        if (origin && origin->mount && q->operation==MD_FS_PATH) {
            *out=(struct md_fs_result){.fd=-1};
            out->error=!output || !output->data ? -EINVAL
                : md_view_path(fs,q->directory[0],origin->mount,output->data,output->capacity);
            if (!out->error) out->size=strlen(output->data)+1;
            return;
        }
        inode(fs,origin ? origin->view : fs->mounts,origin ? origin->mount : NULL,q,out,output);
        if (out->error==-EXDEV && q->operation==MD_FS_FSTAT) {
            /* Anonymous native objects have no mount/inode-store placement.
             * Inspect the retained FD, not the proc name which may be reused. */
            struct stat st;
            out->error=fstat(q->directory[0],&st) ? -errno : 0;
            if (!out->error) md_fs_stat_info(&st,&out->info);
        }
        return;
    }
    struct md_view_location a = {.parent=-1,.fd=-1}, b = {.parent=-1,.fd=-1};
    int pair = q->operation == MD_FS_LINK || q->operation == MD_FS_RENAME;
    /* A proc alias is task-owned for metadata and mutation as well as opens.
     * Never resolve self/fd against the filesystem worker's descriptor table. */
    uint64_t resolve=q->resolve|MD_VIEW_TASK_PATH;
    int r = md_view_walk(fs, q->directory[0], q->origin[0], q->path[0], follow(q), missing(q), resolve, &a);
    if (!r && pair) {
        r = md_view_walk(fs, q->directory[1], q->origin[1], q->path[1], -1, 1, MD_VIEW_TASK_PATH, &b);
        if (r==-EREMOTE && fs->store->boundary) fs->store->boundary->operand=1;
    }
    if (!r && pair && (a.view != b.view || a.mount != b.mount)) r = -EXDEV;
    if (!r && a.fd>=0 && (q->operation==MD_FS_MKDIR || q->operation==MD_FS_MKNOD
            || q->operation==MD_FS_SYMLINK || q->operation==MD_FS_CREATE
            || (q->operation==MD_FS_OPEN && !(q->flags&O_PATH)
                && (q->flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)))) r=-EEXIST;
    if (!r && mutates(q,&a) && a.mount && md_view_readonly(a.mount)) r = -EROFS;
    if (!r && q->operation==MD_FS_ACCESS) r=execute_access(a.mount,a.fd,q->mode);
    if (!r && (q->operation == MD_FS_UNLINK || q->operation == MD_FS_RENAME)
            && (mounted_root(&a) || (pair && mounted_root(&b)))) r = -EBUSY;
    if (!r && q->operation==MD_FS_REALPATH) {
        out->error=!output || !output->data ? -EINVAL
            : a.view!=fs->mounts ? -ENOENT : md_view_path(fs,a.fd,a.mount,output->data,output->capacity);
        if (!out->error) out->size=strlen(output->data)+1;
    } else if (!r && !md_view_inode(a.mount)) native(fs, q, &a, &b, out, output);
    else if (!r && ((q->operation==MD_FS_OPEN_IMAGE && !md_view_base(a.view,a.mount))
            || (a.fd>=0 && !strcmp(a.name,".") && selected_operation(q->operation)))) {
        inode_selected(fs,q,&a,out,output);
    } else if (!r) {
        struct md_fs_request local = *q;
        local.directory[0] = a.parent; local.path[0] = a.name; local.resolve = 0;
        if (pair) { local.directory[1] = b.parent; local.path[1] = b.name; }
        inode(fs,a.view,a.mount,&local,out,output);
    } else out->error = r;
    md_view_location_close(&a); md_view_location_close(&b);
}
