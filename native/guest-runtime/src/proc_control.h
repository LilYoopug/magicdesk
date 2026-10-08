#ifndef MD_PROC_CONTROL_H
#define MD_PROC_CONTROL_H
#include "proc_paths.h"
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/stat.h>
struct md_proc_io_spec { int writing, vector, seek, directory, positional; int64_t offset; int whence; };
static inline int md_proc_io_decode(long nr, const unsigned long *a, struct md_proc_io_spec *out) {
    *out=(struct md_proc_io_spec){0};
    if (nr==SYS_lseek) {
        out->seek=1; out->offset=(int64_t)a[1]; out->whence=(int)a[2]; return 0;
    }
    if (nr==SYS_getdents64) { out->directory=1; return 0; }
    switch (nr) {
    case SYS_write: case SYS_writev: case SYS_pwrite64: case SYS_pwritev: case SYS_pwritev2:
        out->writing=1; break;
    case SYS_read: case SYS_readv: case SYS_pread64: case SYS_preadv: case SYS_preadv2: break;
    default: return -EINVAL;
    }
    out->vector=nr==SYS_readv || nr==SYS_writev || nr==SYS_preadv || nr==SYS_pwritev
        || nr==SYS_preadv2 || nr==SYS_pwritev2;
    out->positional=nr!=SYS_read && nr!=SYS_write && nr!=SYS_readv && nr!=SYS_writev;
    if (out->positional) out->offset=(int64_t)a[3];
    /* The native 64-bit ABI puts the complete offset in pos_l; pos_h is unused. */
    if (nr==SYS_preadv2 || nr==SYS_pwritev2) {
        if (a[5]) return -EOPNOTSUPP;
        if (out->offset==-1) { out->positional=0; out->offset=0; }
    }
    return out->positional && out->offset<0 ? -EINVAL : 0;
}
enum { MD_PROC_FILE_OPEN=1, MD_PROC_FILE_KIND, MD_PROC_FILE_REOPEN, MD_PROC_FILE_NAMESPACE_QUERY };
struct md_proc_metadata_request { int32_t process, descriptor; uint32_t kind, access, effective, nofollow; };
struct md_proc_metadata_result { struct stat value; uint32_t kind; };
static inline int md_proc_control_kind(enum md_proc_kind kind) {
    return kind>=MD_PROC_UID_MAP && kind<=MD_PROC_NS_UNSUPPORTED;
}
long md_proc_control_open(int process, enum md_proc_kind, int flags);
long md_proc_control_open_view(int process, enum md_proc_kind, int flags, uint64_t view);
long md_proc_control_known(int fd);
long md_proc_control_reopen(int process, int fd, int flags);
long md_proc_control_metadata(int process, enum md_proc_kind, int fd, long nr, const unsigned long *);
long md_proc_control_call(long nr, const unsigned long *);
#endif
