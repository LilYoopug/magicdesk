#define _GNU_SOURCE
#include "fd_mutation.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <sys/syscall.h>

int md_fd_mutation_prepare(struct md_fd_origins *files, long nr,
        const unsigned long a[6], struct md_fd_mutation *out) {
    *out=(struct md_fd_mutation){.nr=nr,.args={a[0],a[1],a[2]}};
    unsigned command=(unsigned)a[1];
    if (nr==SYS_fcntl) out->args[1]=command;
    int duplicate=nr==SYS_dup || nr==SYS_dup3
        || (nr==SYS_fcntl && (command==F_DUPFD || command==F_DUPFD_CLOEXEC));
    if (!duplicate) return 0;
    unsigned flags=(nr==SYS_dup3 && (a[2]&O_CLOEXEC))
        || (nr==SYS_fcntl && command==F_DUPFD_CLOEXEC) ? FD_CLOEXEC : 0;
    struct md_fs_anchor *source=md_fd_origins_get(files,(int)a[0],NULL);
    int error=md_fd_origins_prepare(files,source,flags,&out->update);
    md_fs_anchor_release(source); return error;
}
int md_fd_mutation_finish(struct md_fd_mutation *op, struct md_fd_origins *files, long result) {
    int error=0;
    if (op->update.table) md_fd_origins_finish(&op->update,result<0 ? -1 : (int)result);
    else if (op->nr==SYS_close && (!result || result==-EINTR || result==-EIO || result==-ENOSPC || result==-EDQUOT)) {
        /* Linux releases a valid slot before reporting close's late IO errors. */
        if ((int)op->args[0]>=0)
            error=md_fd_origins_close_range(files,(unsigned)op->args[0],(unsigned)op->args[0],0);
    } else if (!result && op->nr==SYS_close_range)
        error=md_fd_origins_close_range(files,(unsigned)op->args[0],(unsigned)op->args[1],
            !!(op->args[2]&CLOSE_RANGE_CLOEXEC));
    else if (!result && op->nr==SYS_fcntl && op->args[1]==F_SETFD)
        error=md_fd_origins_set_flags(files,(int)op->args[0],(unsigned)op->args[2]&FD_CLOEXEC);
    *op=(struct md_fd_mutation){0}; return error;
}
void md_fd_mutation_discard(struct md_fd_mutation *op) {
    md_fd_origins_finish(&op->update,-1);
    *op=(struct md_fd_mutation){0};
}
int md_fd_mutation_abandon(struct md_fd_mutation *op, struct md_fd_origins *files) {
    int error=0;
    if (op->nr==SYS_close || (op->nr==SYS_fcntl && op->args[1]==F_SETFD)) {
        if ((int)op->args[0]>=0)
            error=md_fd_origins_close_range(files,(unsigned)op->args[0],(unsigned)op->args[0],0);
    } else if (op->nr==SYS_dup3 && (int)op->args[1]>=0)
        error=md_fd_origins_close_range(files,(unsigned)op->args[1],(unsigned)op->args[1],0);
    else if (op->nr==SYS_close_range && (unsigned)op->args[0]<=(unsigned)op->args[1])
        error=md_fd_origins_close_range(files,(unsigned)op->args[0],(unsigned)op->args[1],0);
    md_fd_mutation_discard(op); return error;
}
