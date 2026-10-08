#define _GNU_SOURCE
#include "fs_operation.h"
#include "ipc_credentials.h"
#include "posix_acl.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int md_fs_request_validate(const struct md_fs_request *q) {
    if (!q) return -EINVAL;
    unsigned descriptors=0;
    for (unsigned i=0;i<2;++i) {
        if (q->capture[i].path) {
            if (q->directory[i]!=-1 || q->object[i] || q->origin[i]
                    || (md_fs_operation_data_inputs(q->operation)&(1U<<i))
                    || !*q->capture[i].path || strnlen(q->capture[i].path,PATH_MAX)==PATH_MAX
                    || !(q->capture[i].flags&O_PATH)
                    || q->capture[i].flags&~(O_PATH|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW)) return -EINVAL;
            descriptors|=1U<<i;
        } else if (q->capture[i].flags) return -EINVAL;
        if (q->object[i]) {
            if (q->directory[i]!=-1 || q->origin[i] || !md_fs_object_id_valid(q->object[i])
                    || (md_fs_operation_data_inputs(q->operation)&(1U<<i))) return -EINVAL;
            descriptors|=1U<<i;
        }
        if (q->directory[i]<0 && q->directory[i]!=-1 && q->directory[i]!=AT_FDCWD) return -EBADF;
        if (q->directory[i]==AT_FDCWD && (md_fs_operation_data_inputs(q->operation)&(1U<<i))) return -EBADF;
        if (q->directory[i]!=-1) descriptors|=1U<<i;
    }
    const char *a=q->path[0] ? q->path[0] : "", *b=q->path[1] ? q->path[1] : "";
    if (q->operation < MD_FS_CREATE || q->operation > MD_FS_LAST) return -ENOTSUP;
    if (q->attributes.creation_mask & ~0777U) return -EINVAL;
    if (q->resolve && q->operation != MD_FS_OPEN) return -EINVAL;
    if (q->value_size>MD_FS_VALUE_MAX || (q->value_size && !q->value)
            || (q->value_size && q->operation!=MD_FS_XATTR && q->operation!=MD_FS_FXATTR && q->operation!=MD_FS_XATTR_OBJECT
                && q->operation!=MD_FS_SETACL && q->operation!=MD_FS_MOUNT)) return -EINVAL;
    if (q->operation==MD_FS_MOUNT) {
        int pair=q->mode==MD_FS_MOUNT_BIND || q->mode==MD_FS_MOUNT_PIVOT || q->mode==MD_FS_MOUNT_MOVE;
        if ((!*a && !(descriptors&1)) || q->mode<MD_FS_MOUNT_BIND || q->mode>MD_FS_MOUNT_CGROUP2
                || q->capacity || q->offset || q->value_size>PATH_MAX
                || (pair ? (!*b && !(descriptors&2)) : *b || (descriptors&2))
                || (q->mode!=MD_FS_MOUNT_TMPFS && q->mode!=MD_FS_MOUNT_OVERLAY && q->mode!=MD_FS_MOUNT_PROC
                    && q->mode!=MD_FS_MOUNT_DEVPTS && q->mode!=MD_FS_MOUNT_CGROUP
                    && q->mode!=MD_FS_MOUNT_CGROUP2 && q->value_size)) return -EINVAL;
        return q->value_size && strnlen(q->value,q->value_size)!=q->value_size-1 ? -EINVAL : 0;
    }
    if (q->operation==MD_FS_XATTR || q->operation==MD_FS_FXATTR || q->operation==MD_FS_XATTR_OBJECT) {
        int descriptor=q->operation!=MD_FS_XATTR, set=q->mode==MD_FS_XATTR_SET;
        return (descriptors&2) || (descriptor ? descriptors!=1 || *a : !*a && descriptors!=1)
            || q->mode<MD_FS_XATTR_GET || q->mode>MD_FS_XATTR_REMOVE
            || (q->mode==MD_FS_XATTR_LIST ? *b!=0 : !*b || strlen(b)>255)
            || (q->flags & ~((descriptor ? 0 : AT_SYMLINK_NOFOLLOW) | (set ? 3U : 0)))
            || q->offset || q->capacity>MD_FS_VALUE_MAX || (!set && q->value_size)
            || (set && q->value_size!=q->capacity)
            || (q->mode==MD_FS_XATTR_REMOVE && q->capacity) ? -EINVAL : 0;
    }
    if (q->operation==MD_FS_UMASK)
        return descriptors || *a || *b || q->flags || q->mode || q->capacity || q->offset ? -EINVAL : 0;
    if (q->operation==MD_FS_STATFS)
        return (descriptors&2) || (!*a && descriptors!=1) || *b || q->flags || q->mode || q->capacity || q->offset ? -EINVAL : 0;
    if (q->operation==MD_FS_WATCH_PATH)
        return q->directory[1]<0 || !*a || *b || q->mode || q->capacity || q->offset ? -EINVAL : 0;
    if (q->operation==MD_FS_TASK_PATH)
        return (descriptors&2) || (!*a && descriptors!=1) || *b || q->flags || q->capacity
            || (q->mode!=MD_FS_TASK_CHDIR && q->mode!=MD_FS_TASK_TRUNCATE && q->mode!=MD_FS_TASK_FCHDIR)
            || (q->mode!=MD_FS_TASK_TRUNCATE && q->offset)
            || (q->mode==MD_FS_TASK_FCHDIR && (q->directory[0]<0 || *a || q->object[0])) ? -EINVAL : 0;
    if (q->operation==MD_FS_MKNOD)
        return (descriptors&2) || !*a || *b || q->flags || q->capacity || q->offset
            || (q->mode&~(S_IFMT|07777U))
            || ((q->mode&S_IFMT)!=S_IFREG && (q->mode&S_IFMT)!=S_IFIFO) ? -EINVAL : 0;
    if (q->operation==MD_FS_MOUNT_TABLE)
        return descriptors || *a || *b || (q->flags&~(O_PATH|O_CLOEXEC)) || q->mode>1
            || q->capacity || q->offset || q->resolve ? -EINVAL : 0;
    if (q->operation==MD_FS_NATIVE_MOUNT)
        return descriptors || *a || *b || q->flags || q->mode || q->capacity || q->offset<=0 || q->resolve ? -EINVAL : 0;
    if (q->operation>=MD_FS_GETACL && q->operation<=MD_FS_REMOVEACL) {
        int set=q->operation==MD_FS_SETACL;
        return descriptors!=1 || *a || *b || q->offset
            || (q->mode!=MD_ACL_ACCESS && q->mode!=MD_ACL_DEFAULT)
            || q->capacity>MD_ACL_MAX
            || (set ? (q->capacity && q->capacity<4) || q->value_size!=q->capacity || (q->flags&~3U)
                : q->flags || (q->operation==MD_FS_REMOVEACL && q->capacity)) ? -EINVAL : 0;
    }
    if (q->operation==MD_FS_IPC_PEER)
        return descriptors!=1 || *a || *b || q->flags || q->mode>1 || q->capacity || q->offset ? -EINVAL : 0;
    if (q->operation == MD_FS_IPC)
        return (descriptors != 1 && !((q->flags == MD_IPC_PAIR || q->flags == MD_IPC_MESSAGE_READ) && descriptors == 3))
            || *b || q->mode || q->capacity || q->flags < MD_IPC_LISTEN_BEGIN || q->flags > MD_IPC_MESSAGE_READ ? -EINVAL : 0;
    if (q->operation == MD_FS_GETCAP || q->operation == MD_FS_SETCAP || q->operation == MD_FS_REMOVECAP)
        return descriptors != 1 || *a || *b || q->mode || q->offset
            || (q->operation != MD_FS_SETCAP && (q->capacity || q->flags))
            || q->capacity > MD_FILE_CAPABILITY_MAX ? -EINVAL : 0;
    if ((q->capacity && q->operation != MD_FS_GETDENTS && q->operation != MD_FS_WATCH_READ) || q->capacity > PATH_MAX
            || (q->offset && q->operation != MD_FS_SEEKDIR)) return -EINVAL;
    if (q->operation == MD_FS_REOPEN)
        return descriptors != 1 || *a || *b || (q->mode&~(MD_FS_REOPEN_MUTABLE|MD_FS_REOPEN_NATIVE)) ? -EINVAL : 0;
    if (q->operation == MD_FS_ACCESS)
        return (descriptors & 2) || (!*a && descriptors != 1) || *b ? -EINVAL : 0;
    if (q->operation >= MD_FS_CHMOD && q->operation <= MD_FS_UTIMENS)
        return (descriptors & 2) || (!*a && descriptors != 1) || *b
            || (q->flags & ~AT_SYMLINK_NOFOLLOW) ? -EINVAL : 0;
    if (q->operation >= MD_FS_WATCH_CREATE && q->operation <= MD_FS_WATCH_READ) {
        unsigned expected = q->operation == MD_FS_WATCH_CREATE ? 0 : q->operation == MD_FS_WATCH_ADD ? 3 : 1;
        if (descriptors != expected || *a || *b || q->mode) return -EINVAL;
        if (q->flags && q->operation != MD_FS_WATCH_CREATE && q->operation != MD_FS_WATCH_ADD
                && q->operation != MD_FS_WATCH_REMOVE) return -EINVAL;
        return 0;
    }
    if (q->operation == MD_FS_TEMPORARY)
        return descriptors || *a || *b || q->flags || q->mode ? -EINVAL : 0;
    if (q->operation == MD_FS_OBJECT_ID)
        return descriptors != 1 || *a || *b || q->flags || q->mode ? -EINVAL : 0;
    if (q->operation == MD_FS_OPEN_OBJECT)
        return descriptors || !*a || *b || q->mode ? -EINVAL : 0;
    if (q->operation == MD_FS_OPEN_IMAGE)
        return (descriptors & 2) || !*a || *b || q->mode || (q->flags & ~O_NOFOLLOW) ? -EINVAL : 0;
    if (q->operation == MD_FS_GETDENTS || q->operation == MD_FS_SEEKDIR) {
        if (descriptors != 1 || *a || *b || q->mode) return -EINVAL;
        return q->operation == MD_FS_GETDENTS ? (q->flags ? -EINVAL : 0)
            : (q->flags == SEEK_SET || q->flags == SEEK_CUR ? 0 : -EINVAL);
    }
    if (q->operation == MD_FS_SOCKET_BIND)
        return !(descriptors & 2) || !*a || *b || q->flags || (q->mode & ~0777) ? -EINVAL : 0;
    if (q->operation == MD_FS_SOCKET_ADDRESS || q->operation == MD_FS_SOCKET_NAME)
        return (descriptors & 2) || !*a || *b || q->flags || q->mode
            || (q->operation == MD_FS_SOCKET_NAME && descriptors) ? -EINVAL : 0;
    int binary = q->operation == MD_FS_LINK || q->operation == MD_FS_RENAME;
    if ((!binary && (descriptors & 2))
            || (!binary && q->operation != MD_FS_SYMLINK && *b)
            || (q->mode && q->operation != MD_FS_CREATE && q->operation != MD_FS_MKDIR && q->operation != MD_FS_OPEN
                && !((q->operation==MD_FS_STAT || q->operation==MD_FS_FSTAT) && q->mode==MD_FS_STAT_MOUNT))
            || (q->flags && q->operation != MD_FS_OPEN && q->operation != MD_FS_LINK
                && q->operation != MD_FS_RENAME && q->operation != MD_FS_UNLINK && q->operation != MD_FS_STAT)
            || ((q->operation == MD_FS_FSTAT || q->operation == MD_FS_PATH) && *a)
            || (q->operation == MD_FS_FSTAT && !(descriptors & 1))) return -EINVAL;
    return 0;
}
