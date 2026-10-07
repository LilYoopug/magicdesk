#define _GNU_SOURCE
#include "namespace_internal.h"
#include "proc_paths.h"
#include "fs_rpc.h"
#include "fd_metadata.h"
#include "fd_client.h"
#include "linux_abi.h"
#include "raw.h"
#include "task_status.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static long namespace_request_deliver(const struct md_fs *fs, struct md_fs_request *q, struct md_fs_response *out,
        int (*deliver)(void *, const void *, size_t), void *target) {
    for (unsigned i=0;i<2;++i) if (q->directory[i]==MD_NAMESPACE_EXECUTABLE) {
        if (!fs->image || !fs->image->executable_object[0]) return -ENOENT;
        q->directory[i]=-1; q->object[i]=fs->image->executable_object;
    }
    unsigned bases = q->operation == MD_FS_LINK || q->operation == MD_FS_RENAME ? 2 : 1;
    for (unsigned i = 0; i < bases; ++i) {
        if (q->path[i] && q->path[i][0] == '/' && !(q->resolve & RESOLVE_IN_ROOT)) {
            q->directory[i] = -1; q->object[i]=NULL;
            q->capture[i]=(struct md_fs_task_capture){0};
        }
        else if (q->directory[i] < 0 && q->directory[i] != AT_FDCWD && !q->object[i] && !q->capture[i].path)
            return -EBADF;
    }
    long r = md_fs_call_deliver(fs->endpoint, 5000, q, out,deliver,target);
    /* Never replay an unconfirmed request, including a read that advanced a cursor. */
    return r < 0 ? r : out->result.host_path ? -EREMOTE : out->result.error;
}
long md_namespace_request(const struct md_fs *fs, struct md_fs_request *q, struct md_fs_response *out) {
    return namespace_request_deliver(fs,q,out,NULL,NULL);
}
long md_namespace_creation_mode(const struct md_fs *fs, unsigned mode) {
    long mask;
    if (fs->endpoint[0]) {
        struct md_fs_request q={.operation=MD_FS_UMASK,.directory={-1,-1}};
        struct md_fs_response out;
        long result=md_fs_call(fs->endpoint,5000,&q,&out);
        if (result<0) return result;
        if (out.result.error) return out.result.error;
        mask=out.result.position;
    } else mask=md_task_umask((int)RAW0(gettid));
    return mask<0 ? mask : (mode&07777)&~(unsigned)mask;
}
long md_namespace_open_result(struct md_fs_result *result, int flags) {
    int fd = result->fd;
    if (result->open_completion.kind != MD_OPEN_READY)
        return md_complete_open(fd, flags, result->open_completion);
    if (!(flags & O_CLOEXEC)) {
        long r = RAW3(fcntl, fd, F_SETFD, 0);
        if (r < 0) { RAW1(close, fd); return r; }
    }
    return fd;
}
static long reopen_request(const struct md_fs *fs, int fd, int flags, unsigned mode) {
    struct md_fs_request q = {.operation=MD_FS_REOPEN, .directory={fd,-1},
        .flags=(uint32_t)flags, .mode=mode};
    struct md_fs_response out;
    long r = md_namespace_request(fs, &q, &out);
    if (r < 0) return r;
    return md_namespace_open_result(&out.result, flags);
}
long md_namespace_proc_reopen(const struct md_fs *fs, int fd, int flags) {
    return reopen_request(fs,fd,flags,MD_FS_REOPEN_NATIVE);
}
long md_namespace_open(const struct md_fs *fs, int base, const char *path, int flags, unsigned mode) {
    if (md_fs_host_path(fs, path))
        return RAW4(openat, base, path, flags, mode);
    /* Legacy open ignores file-type bits; openat2 validates its mode separately. */
    struct open_how how = {.flags = (unsigned)flags,
        .mode = (flags & O_CREAT) && !(flags & O_PATH) ? mode & 07777U : 0};
    return md_namespace_open_resolved(fs, base, path, &how);
}
static long open_operand(const struct md_fs *fs, struct md_namespace_operand operand, const char *path,
        const struct open_how *how) {
    int base=operand.descriptor;
    int flags = (int)how->flags;
    unsigned mode = (unsigned)how->mode;
    unsigned mask=0;
    if ((flags & O_CREAT) && !(flags & O_PATH)) {
        long masked = md_namespace_creation_mode(fs,0777);
        if (masked < 0)
            return masked;
        mask = 0777U ^ (unsigned)masked;
    }
    struct md_fs_request q = {.operation = MD_FS_OPEN,
                              .directory = {base, -1}, .capture={operand.capture},
                              .path = {path, NULL},
                              .flags = (uint32_t)flags,
                              .mode = mode, .resolve = how->resolve, .attributes.creation_mask=mask};
    struct md_fs_response out;
    long r = md_namespace_request(fs, &q, &out);
    if (r==-EREMOTE) {
        unsigned long args[6]={(unsigned long)AT_FDCWD,(unsigned long)out.data,(unsigned)flags,mode,0,0};
        return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",SYS_openat,args,1,out.data);
    }
    if (r < 0)
        return r;
    return md_namespace_open_result(&out.result, flags);
}
long md_namespace_open_resolved(const struct md_fs *fs, int base, const char *path,
        const struct open_how *how) {
    return open_operand(fs,md_namespace_descriptor(base),path,how);
}
static void stat_info(const struct md_fs_info *i, struct stat *s) {
    memset(s, 0, sizeof(*s));
    s->st_dev = i->device;
    s->st_ino = i->inode;
    s->st_nlink = i->links;
    s->st_rdev = i->rdev;
    s->st_size = i->size;
    s->st_blocks = i->blocks;
    s->st_mode = i->mode;
    s->st_uid = i->uid;
    s->st_gid = i->gid;
    s->st_blksize = i->block_size;
    s->st_atim.tv_sec = i->access_seconds;
    s->st_atim.tv_nsec = i->access_nanos;
    s->st_mtim.tv_sec = i->modify_seconds;
    s->st_mtim.tv_nsec = i->modify_nanos;
    s->st_ctim.tv_sec = i->change_seconds;
    s->st_ctim.tv_nsec = i->change_nanos;
}
long md_namespace_inspect(const struct md_fs *fs, struct md_namespace_operand operand,
        const char *path, int flags, unsigned mode, struct md_fs_response *out) {
    int fd=operand.descriptor;
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT))
        return -EINVAL;
    struct md_fs_request q = {.operation = path && *path ? MD_FS_STAT : MD_FS_FSTAT,
                              .directory = {fd, -1}, .capture={operand.capture}, .mode=mode,
                              .path = {path, NULL},
                              .flags = (uint32_t)(flags & AT_SYMLINK_NOFOLLOW)};
    if (!path || !*path)
        q.flags = 0;
    if (path && !*path && !(flags & AT_EMPTY_PATH))
        return -ENOENT;
    return md_namespace_request(fs, &q, out);
}
static int copy_directory(void *target, const void *data, size_t size) {
    return (int)md_write_memory(target,data,size);
}
static long descriptor_call(const struct md_fs *fs, long nr, const unsigned long *a) {
    if ((int)a[0] < 0)
        return -EBADF;
    if (nr==SYS_lseek) {
        /* Only directories have a guest cursor. Hold the table turn through
         * native type selection and seek so dup/close cannot change the OFD. */
        long locked=md_fd_control(MD_FD_USE,0,0,0);
        if (locked<0) return locked;
        struct stat native;
        long value=RAW2(fstat,a[0],&native);
        int delegated=!value && S_ISDIR(native.st_mode);
        if (!value && !delegated) value=RAW3(lseek,a[0],a[1],a[2]);
        long released=md_fd_control(MD_FD_RELEASE,0,0,0);
        if (released<0) return released;
        if (!delegated) return value;
    }
    long native = md_namespace_native_descriptor((int)a[0]);
    if (native < 0) return native;
    if (native) return md_raw(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
    struct md_fs_response out;
    struct stat st;
    if (nr == SYS_getdents64) {
        /* The namespace validates the descriptor and advances its cursor in
         * one operation; a preliminary metadata RPC adds no authority. */
        struct md_fs_request q = {.operation = MD_FS_GETDENTS, .directory = {(int)a[0], -1},
            .capacity = a[2] > PATH_MAX ? PATH_MAX : (uint32_t)a[2]};
        long r = md_fs_call_deliver(fs->endpoint,5000,&q,&out,copy_directory,(void *)a[1]);
        if (!r) r=out.result.host_path ? -EREMOTE : out.result.error;
        if (r == -EXDEV) return md_raw(nr, a[0], a[1], a[2], 0, 0, 0);
        if (r < 0) return r;
        return out.result.size;
    }
    long r = md_namespace_inspect(fs, md_namespace_descriptor((int)a[0]), NULL, 0, 0, &out);
    if (r == -EXDEV)
        return md_raw(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (r < 0)
        return r;
    if (nr == SYS_fstat) {
        stat_info(&out.result.info, &st);
        return md_write_memory((void *)a[1], &st, sizeof(st));
    }
    if (!S_ISDIR(out.result.info.mode))
        return md_raw(nr, a[0], a[1], a[2], 0, 0, 0);
    struct md_fs_request q = {.operation = MD_FS_SEEKDIR, .directory = {(int)a[0], -1},
        .offset = (int64_t)a[1], .flags = (uint32_t)a[2]};
    r = md_namespace_request(fs, &q, &out);
    if (r < 0)
        return r;
    return out.result.position;
}
long md_namespace_xattr(const struct md_fs *fs, long nr, struct md_namespace_operand operand,
        const char *path, const unsigned long *a) {
    int base=operand.descriptor;
    int list=nr==SYS_listxattr || nr==SYS_llistxattr || nr==SYS_flistxattr;
    int set=nr==SYS_setxattr || nr==SYS_lsetxattr || nr==SYS_fsetxattr;
    int remove=nr==SYS_removexattr || nr==SYS_lremovexattr || nr==SYS_fremovexattr;
    int descriptor=nr==SYS_fgetxattr || nr==SYS_flistxattr || nr==SYS_fsetxattr || nr==SYS_fremovexattr;
    int nofollow=nr==SYS_lsetxattr || nr==SYS_lgetxattr || nr==SYS_llistxattr || nr==SYS_lremovexattr;
    char name[256]="";
    if (!list) {
        long error=md_read_string(name,sizeof(name),(const char *)a[1]);
        if (error<0) return error==-ENAMETOOLONG ? -ERANGE : error;
    }
    unsigned long capacity=remove ? 0 : list ? a[2] : a[3];
    if (set && (a[4]&~3UL)) return -EINVAL;
    if (set && capacity>MD_FS_VALUE_MAX) return -E2BIG;
    if (capacity>MD_FS_VALUE_MAX) capacity=MD_FS_VALUE_MAX;
    struct md_fs_request q={.operation=descriptor ? MD_FS_FXATTR : MD_FS_XATTR,
        .directory={base,-1},.capture={operand.capture},.path={path,name},.capacity=(unsigned)capacity,
        .mode=list ? MD_FS_XATTR_LIST : set ? MD_FS_XATTR_SET : remove ? MD_FS_XATTR_REMOVE : MD_FS_XATTR_GET,
        .flags=(nofollow ? AT_SYMLINK_NOFOLLOW : 0)|(set ? (unsigned)a[4] : 0),
        .value=set ? (const void *)a[2] : NULL,.value_size=set ? (unsigned)capacity : 0};
    struct md_fs_response out;
    void *target=list ? (void *)a[1] : (void *)a[2];
    long result=namespace_request_deliver(fs,&q,&out,set || remove ? NULL : copy_directory,target);
    if (result==-EREMOTE)
        return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",nr,a,0,out.data);
    return result<0 ? result : out.result.position;
}
static long metadata_request(const struct md_fs *fs, long nr, struct md_namespace_operand operand, const char *path,
        unsigned long mode, unsigned long extra, int flags, struct md_fs_response *out) {
    int fd=operand.descriptor;
    if ((!path || !*path) && fd!=MD_NAMESPACE_EXECUTABLE && !operand.capture.path) {
        long native = md_namespace_native_descriptor(fd);
        if (native < 0) return native;
        if (native) return -EXDEV;
    }
    struct md_fs_request q = {.directory = {fd, -1}, .capture={operand.capture}, .path={path,NULL}, .flags = (unsigned)flags};
    switch (nr) {
    case SYS_fchmod: case SYS_fchmodat: case SYS_fchmodat2:
        q.operation = MD_FS_CHMOD; q.mode = (unsigned)mode; break;
    case SYS_fchown: case SYS_fchownat:
        q.operation = MD_FS_CHOWN; q.attributes.uid = (uint32_t)mode; q.attributes.gid = (uint32_t)extra; break;
    case SYS_faccessat: case SYS_faccessat2:
        q.operation = MD_FS_ACCESS; q.mode = (unsigned)mode; break;
    case SYS_utimensat: {
        q.operation = MD_FS_UTIMENS;
        struct timespec times[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
        if (mode) { long r = md_read_memory(times, (void *)mode, sizeof(times)); if (r < 0) return r; }
        for (unsigned i = 0; i < 2; i++) {
            q.attributes.seconds[i] = times[i].tv_sec; q.attributes.nanos[i] = times[i].tv_nsec;
        }
        break;
    }
    default: return -EXDEV;
    }
    return md_namespace_request(fs, &q, out);
}
long md_namespace_call(const struct md_fs *fs, const char *exe, long nr, const unsigned long *a) {
    if (nr == SYS_fchdir) {
        if ((int)a[0]<0) return -EBADF;
        long native=md_namespace_native_descriptor((int)a[0]);
        if (native<0) return native;
        if (native) return RAW1(fchdir,a[0]);
        struct md_fs_request q={.operation=MD_FS_TASK_PATH,.directory={(int)a[0],-1},
            .mode=MD_FS_TASK_FCHDIR};
        struct md_fs_response out;
        return md_namespace_request(fs,&q,&out);
    }
    if (nr == SYS_fstat || nr == SYS_getdents64 || nr == SYS_lseek)
        return descriptor_call(fs, nr, a);
    if (nr == SYS_fsetxattr || nr == SYS_fremovexattr || nr == SYS_fgetxattr || nr == SYS_flistxattr)
        return md_namespace_xattr(fs, nr, md_namespace_descriptor((int)a[0]), NULL, a);
    if (nr == SYS_fchmod || nr == SYS_fchown || (nr == SYS_utimensat && !a[1])) {
        long flags = RAW3(fcntl, a[0], F_GETFL, 0);
        if (flags < 0) return flags;
        if (flags & O_PATH) return -EBADF;
        struct md_fs_response out;
        long result = metadata_request(fs, nr, md_namespace_descriptor((int)a[0]), NULL, nr == SYS_utimensat ? a[2] : a[1], a[2], 0,&out);
        if (result != -EXDEV) return result;
        return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
    }
    if (nr==SYS_mount || nr==SYS_umount2 || nr==SYS_pivot_root) return md_namespace_mount(fs,nr,a);
    if (nr == SYS_getcwd) {
        struct md_fs_request q = {.operation = MD_FS_PATH, .directory = {AT_FDCWD, -1}};
        struct md_fs_response out;
        long r = md_namespace_request(fs, &q, &out);
        if (r < 0)
            return r;
        if (out.result.size > a[1])
            return -ERANGE;
        r = md_write_memory((void *)a[0], out.data, out.result.size);
        return r < 0 ? r : out.result.size;
    }
    char first[PATH_MAX];
    int base = (int)a[0];
    unsigned path_index = 1;
    uintptr_t pointer = a[1];
    switch (nr) {
    case SYS_inotify_add_watch:
        base = AT_FDCWD;
        break;
    case SYS_chdir:
    case SYS_chroot:
    case SYS_truncate:
    case SYS_statfs:
    case SYS_setxattr:
    case SYS_lsetxattr:
    case SYS_getxattr:
    case SYS_lgetxattr:
    case SYS_listxattr:
    case SYS_llistxattr:
    case SYS_removexattr:
    case SYS_lremovexattr:
        pointer = a[0];
        path_index = 0;
        base = AT_FDCWD;
        break;
    case SYS_symlinkat:
        pointer = a[2];
        path_index = 2;
        base = (int)a[1];
        break;
    }
    long r = md_read_string(first, sizeof(first), (const char *)pointer);
    if (r < 0)
        return r;
    r = md_namespace_relative_mount(fs, base, first);
    if (r < 0)
        return r;
    /* Direct and symlink-resolved host boundaries use the same task adapter. */
    if (md_fs_host_path(fs, first) && nr != SYS_inotify_add_watch && nr != SYS_chroot)
        return md_namespace_host_call(fs, exe, nr, a, path_index, first);
    return md_namespace_path_call(fs, nr, a, md_namespace_descriptor(base), first);
}
static long path_metadata(const struct md_fs *, long, const unsigned long *, struct md_namespace_operand, const char *);
long md_namespace_path_call(const struct md_fs *fs, long nr, const unsigned long *a,
                            struct md_namespace_operand operand, const char *first) {
    int base=operand.descriptor;
    switch (nr) {
    case SYS_chroot: {
        struct md_fs_request q = {.operation=MD_FS_CHROOT, .directory={base,-1}, .capture={operand.capture}, .path={first,NULL}};
        struct md_fs_response out;
        return md_namespace_request(fs, &q, &out);
    }
    case SYS_openat: {
        struct open_how how={.flags=(unsigned)a[2],
            .mode=(a[2]&O_CREAT) && !(a[2]&O_PATH) ? a[3]&07777U : 0};
        return open_operand(fs,operand,first,&how);
    }
    case SYS_mknodat: {
        unsigned mode = (unsigned)a[2];
        if (!(mode&S_IFMT)) mode|=S_IFREG;
        if ((mode&S_IFMT)!=S_IFIFO && (mode&S_IFMT)!=S_IFREG) return -ENOTSUP;
        long masked=md_namespace_creation_mode(fs,0777);
        if (masked<0) return masked;
        struct md_fs_request q={.operation=MD_FS_MKNOD,.directory={base,-1}, .capture={operand.capture},
            .path={first,NULL},.mode=mode&(S_IFMT|07777),
            .attributes.creation_mask=0777U^(unsigned)masked};
        struct md_fs_response out;
        long r=md_namespace_request(fs,&q,&out);
        if (r==-EREMOTE)
            return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",nr,a,1,out.data);
        return r;
    }
    case SYS_chdir: case SYS_truncate: {
        struct md_fs_request q={.operation=MD_FS_TASK_PATH,.directory={base,-1}, .capture={operand.capture},.path={first,NULL},
            .mode=nr==SYS_chdir ? MD_FS_TASK_CHDIR : MD_FS_TASK_TRUNCATE,
            .offset=nr==SYS_truncate ? (int64_t)a[1] : 0};
        struct md_fs_response out;
        long r=md_namespace_request(fs,&q,&out);
        if (r==-EREMOTE)
            return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",nr,a,0,out.data);
        return r;
    }
    default: return path_metadata(fs, nr, a, operand, first);
    }
}
/* Keep metadata payloads off posix_spawn's small open/chdir file-action stack. */
__attribute__((noinline)) static long path_metadata(const struct md_fs *fs, long nr,
                                                    const unsigned long *a, struct md_namespace_operand operand, const char *first) {
    int base=operand.descriptor;
    char second[PATH_MAX];
    long r;
    struct md_fs_request q = {.directory = {base, -1}, .capture={operand.capture}, .path = {first, NULL}};
    struct md_fs_response out;
    switch (nr) {
    case SYS_inotify_add_watch: {
        q.operation=MD_FS_WATCH_PATH; q.directory[1]=(int)a[0]; q.flags=(unsigned)a[2];
        r=md_namespace_request(fs,&q,&out);
        if (r!=-EREMOTE) return r<0 ? r : out.result.position;
        return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",
            nr,a,1,out.data);
    }
    case SYS_newfstatat:
    case SYS_statx: {
        int flags = nr == SYS_statx ? (int)a[2] : (int)a[3];
        if (nr == SYS_statx &&
            (((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE) || (a[3] & STATX__RESERVED)))
            return -EINVAL;
        if (nr == SYS_statx)
            flags &= ~(AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC);
        if (!*first && (flags & AT_EMPTY_PATH) && base!=MD_NAMESPACE_EXECUTABLE && !operand.capture.path) {
            /* Native boundary FDs need no namespace ownership lookup. Some LSM
             * policies allow local stat but reject SCM_RIGHTS for these FDs. */
            r=md_namespace_native_descriptor(base);
            if (r<0) return r;
            if (r) return nr==SYS_statx ? md_namespace_native_statx(fs,a)
                : md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
        }
        r = md_namespace_inspect(fs, operand, first, flags, nr==SYS_statx ? MD_FS_STAT_MOUNT : 0, &out);
        if (r==-EREMOTE) return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",nr,a,1,out.data);
        if (r == -EXDEV && !operand.capture.path && !*first && (flags & AT_EMPTY_PATH))
            return nr==SYS_statx ? md_namespace_native_statx(fs,a)
                : md_raw(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (r < 0)
            return r;
        if (nr == SYS_newfstatat) {
            struct stat st;
            stat_info(&out.result.info, &st);
            return md_write_memory((void *)a[2], &st, sizeof(st));
        }
        struct statx st = {0};
        st.stx_mask = STATX_BASIC_STATS;
        if (out.result.info.mount_id) {
            st.stx_mask |= STATX_MNT_ID;
            st.stx_mnt_id=out.result.info.mount_id;
        }
        st.stx_blksize = out.result.info.block_size;
        st.stx_nlink = (uint32_t)out.result.info.links;
        st.stx_uid = out.result.info.uid;
        st.stx_gid = out.result.info.gid;
        st.stx_mode = (uint16_t)out.result.info.mode;
        st.stx_ino = out.result.info.inode;
        st.stx_size = out.result.info.size;
        st.stx_blocks = out.result.info.blocks;
        st.stx_atime.tv_sec = out.result.info.access_seconds;
        st.stx_atime.tv_nsec = out.result.info.access_nanos;
        st.stx_mtime.tv_sec = out.result.info.modify_seconds;
        st.stx_mtime.tv_nsec = out.result.info.modify_nanos;
        st.stx_ctime.tv_sec = out.result.info.change_seconds;
        st.stx_ctime.tv_nsec = out.result.info.change_nanos;
        st.stx_dev_major = major(out.result.info.device);
        st.stx_dev_minor = minor(out.result.info.device);
        st.stx_rdev_major = major(out.result.info.rdev);
        st.stx_rdev_minor = minor(out.result.info.rdev);
        return md_write_memory((void *)a[4], &st, sizeof(st));
    }
    case SYS_mkdirat:
        r = md_namespace_creation_mode(fs,0777);
        if (r < 0)
            return r;
        q.operation = MD_FS_MKDIR;
        q.mode = (uint32_t)a[2] & 07777U;
        q.attributes.creation_mask=0777U^(unsigned)r;
        break;
    case SYS_unlinkat:
        q.operation = MD_FS_UNLINK;
        q.flags = (uint32_t)a[2];
        break;
    case SYS_readlinkat:
        if (!a[3])
            return -EINVAL;
        q.operation = MD_FS_READLINK;
        r = md_namespace_request(fs, &q, &out);
        if (r==-EREMOTE) return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",nr,a,1,out.data);
        if (r==-EXDEV && !operand.capture.path && !*first) return RAW4(readlinkat,base,first,a[2],a[3]);
        if (r < 0)
            return r;
        if (out.result.size > a[3])
            out.result.size = (uint32_t)a[3];
        r = md_write_memory((void *)a[2], out.data, out.result.size);
        return r < 0 ? r : out.result.size;
    case SYS_symlinkat:
        r = md_read_string(second, sizeof(second), (const char *)a[0]);
        if (r < 0)
            return r;
        q.operation = MD_FS_SYMLINK;
        q.path[1] = second;
        break;
    case SYS_renameat:
    case SYS_renameat2:
    case SYS_linkat:
        r = md_read_string(second, sizeof(second), (const char *)a[3]);
        if (r < 0)
            return r;
        r = md_namespace_relative_mount(fs, (int)a[2], second);
        if (r < 0)
            return r;
        if (md_fs_host_path(fs, second))
            return -EXDEV;
        q.operation = nr == SYS_linkat ? MD_FS_LINK : MD_FS_RENAME;
        q.directory[1] = (int)a[2];
        q.path[1] = second;
        q.flags = nr == SYS_renameat ? 0 : (uint32_t)a[4];
        break;
    case SYS_faccessat:
    case SYS_faccessat2: {
        int flags = nr == SYS_faccessat2 ? (int)a[3] : 0;
        if (flags & ~(MD_AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
            return -EINVAL;
        if (*first) {
            q.operation = MD_FS_ACCESS; q.mode = (unsigned)a[2]; q.flags = flags & ~AT_EMPTY_PATH;
            break;
        }
        if (!(flags & AT_EMPTY_PATH)) return -ENOENT;
        r = metadata_request(fs, nr, operand, NULL, a[2], 0, flags & ~AT_EMPTY_PATH,&out);
        if (r == -EXDEV && !operand.capture.path) r = RAW4(faccessat2, base, "", a[2], flags);
        return r;
    }
    case SYS_setxattr:
    case SYS_lsetxattr:
    case SYS_getxattr:
    case SYS_lgetxattr:
    case SYS_listxattr:
    case SYS_llistxattr:
    case SYS_removexattr:
    case SYS_lremovexattr:
        return md_namespace_xattr(fs, nr, operand, first, a);
    case SYS_fchmodat:
    case SYS_fchmodat2:
    case SYS_fchownat:
    case SYS_utimensat: {
        int flags=nr==SYS_fchownat ? (int)a[4] : nr==SYS_fchmodat ? 0 : (int)a[3];
        if (flags & ~(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH)) return -EINVAL;
        if (!*first && !(flags&AT_EMPTY_PATH)) return -ENOENT;
        r=metadata_request(fs,nr,operand,first,a[2],a[3],flags&~AT_EMPTY_PATH,&out);
        if (r==-EREMOTE) return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",
            nr,a,1,out.data);
        if (r==-EXDEV && !operand.capture.path && !*first) return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
        return r;
    }
    case SYS_statfs: {
        q.operation=MD_FS_STATFS;
        r=md_namespace_request(fs,&q,&out);
        if (r==-EREMOTE) return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",
            nr,a,0,out.data);
        return r<0 ? r : md_write_memory((void *)a[1],out.data,out.result.size);
    }
    default:
        return -ENOTSUP;
    }
    r=md_namespace_request(fs, &q, &out);
    if (r==-EREMOTE) return md_namespace_host_call(fs,fs->image ? fs->image->executable_path : "",
        nr,a,nr==SYS_symlinkat ? 2 : 1,out.data);
    return r;
}
