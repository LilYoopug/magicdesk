#ifndef MD_OPEN_REQUEST_H
#define MD_OPEN_REQUEST_H
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>

/* Validation is independent of the transport that captured open_how. */
static inline int md_open_how_validate(const struct open_how *how) {
    const uint64_t allowed=O_ACCMODE|O_CREAT|O_EXCL|O_NOCTTY|O_TRUNC|O_APPEND|
        O_NONBLOCK|O_DSYNC|O_ASYNC|O_DIRECT|O_LARGEFILE|O_DIRECTORY|O_NOFOLLOW|
        O_NOATIME|O_CLOEXEC|O_SYNC|O_PATH|O_TMPFILE;
    if ((how->flags&~allowed) || (how->mode&~07777UL)) return -EINVAL;
    if (how->mode && !(how->flags&O_CREAT) && (how->flags&O_TMPFILE)!=O_TMPFILE) return -EINVAL;
    if ((how->flags&O_PATH) && (how->flags&~(O_PATH|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW))) return -EINVAL;
    if ((how->flags&(O_CREAT|O_DIRECTORY))==(O_CREAT|O_DIRECTORY)) return -EINVAL;
    if ((how->flags&O_TMPFILE)==O_TMPFILE && !(how->flags&(O_WRONLY|O_RDWR))) return -EINVAL;
    if (how->resolve&~(RESOLVE_BENEATH|RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS|
            RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV|RESOLVE_CACHED)) return -EINVAL;
    if ((how->resolve&(RESOLVE_IN_ROOT|RESOLVE_BENEATH))==(RESOLVE_IN_ROOT|RESOLVE_BENEATH)) return -EINVAL;
    return 0;
}
#endif
