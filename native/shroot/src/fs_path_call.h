#ifndef MD_FS_PATH_CALL_H
#define MD_FS_PATH_CALL_H
#include "fs_operation.h"
#include <fcntl.h>
#include <errno.h>
#include <linux/mount.h>
#include <sys/syscall.h>

/* Scalar decoding is shared by stopped-task capture and the task-local adapter.
 * Capturing operands and deciding host boundaries remain their owners' jobs. */
static inline void md_fs_open_parameters(struct md_fs_request *q,unsigned flags,unsigned mode,uint64_t resolve) {
    q->operation=MD_FS_OPEN; q->flags=flags; q->mode=mode; q->resolve=resolve;
    q->attributes.creation_mask=(flags&O_CREAT) && !(flags&O_PATH) ? MD_FS_CAPTURE_UMASK : 0;
}
static inline int md_fs_fsopen_parameters(struct md_fs_request *q,unsigned flags) {
    if (flags&~FSOPEN_CLOEXEC) return -EINVAL;
    q->operation=MD_FS_FSOPEN; q->flags=O_RDWR|((flags&FSOPEN_CLOEXEC) ? O_CLOEXEC : 0);
    return 0;
}
static inline unsigned md_fs_path_call(struct md_fs_request *q,long nr,const unsigned long *args) {
    switch (nr) {
    case SYS_openat:
        md_fs_open_parameters(q,(unsigned)args[2],
            (args[2]&O_CREAT) && !(args[2]&O_PATH) ? args[3]&07777U : 0,0);
        return 1;
    case SYS_unlinkat:
        q->operation=MD_FS_UNLINK; q->flags=(unsigned)args[2]; return 1;
    case SYS_mkdirat:
        q->operation=MD_FS_MKDIR; q->mode=args[2]&07777U;
        q->attributes.creation_mask=MD_FS_CAPTURE_UMASK; return 1;
    case SYS_renameat: case SYS_renameat2: case SYS_linkat:
        q->operation=nr==SYS_linkat ? MD_FS_LINK : MD_FS_RENAME;
        q->directory[1]=(int)args[2]; q->flags=nr==SYS_renameat ? 0 : (unsigned)args[4];
        return 2;
    default: return 0;
    }
}
#endif
