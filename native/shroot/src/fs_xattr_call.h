#ifndef MD_FS_XATTR_CALL_H
#define MD_FS_XATTR_CALL_H
#include "fs_operation.h"
#include "linux_abi.h"
#include <errno.h>
#include <sys/syscall.h>

/* Shared scalar contract; callers own pathname, name and value capture. */
static inline int md_fs_xattr_call(struct md_fs_request *q,long nr,const unsigned long *a) {
    int list=nr==SYS_listxattr || nr==SYS_llistxattr || nr==SYS_flistxattr;
    int set=nr==SYS_setxattr || nr==SYS_lsetxattr || nr==SYS_fsetxattr;
    int remove=nr==SYS_removexattr || nr==SYS_lremovexattr || nr==SYS_fremovexattr;
    int get=nr==SYS_getxattr || nr==SYS_lgetxattr || nr==SYS_fgetxattr;
    if (!list && !set && !remove && !get) return 0;
    int descriptor=nr==SYS_fgetxattr || nr==SYS_flistxattr || nr==SYS_fsetxattr || nr==SYS_fremovexattr;
    int nofollow=nr==SYS_lsetxattr || nr==SYS_lgetxattr || nr==SYS_llistxattr || nr==SYS_lremovexattr;
    unsigned long capacity=remove ? 0 : list ? a[2] : a[3];
    if (set && (a[4]&~3UL)) return -EINVAL;
    if (set && capacity>MD_FS_VALUE_MAX) return -E2BIG;
    if (capacity>MD_FS_VALUE_MAX) capacity=MD_FS_VALUE_MAX;
    *q=(struct md_fs_request){.operation=descriptor ? MD_FS_FXATTR : MD_FS_XATTR,
        .directory={descriptor ? (int)a[0] : AT_FDCWD,-1},.capacity=(unsigned)capacity,
        .mode=list ? MD_FS_XATTR_LIST : set ? MD_FS_XATTR_SET : remove ? MD_FS_XATTR_REMOVE : MD_FS_XATTR_GET,
        .flags=(nofollow ? AT_SYMLINK_NOFOLLOW : 0)|(set ? (unsigned)a[4] : 0),
        .value=set ? (const void *)a[2] : NULL,.value_size=set ? (unsigned)capacity : 0};
    return 1;
}
#endif
