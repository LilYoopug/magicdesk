#define _GNU_SOURCE
#include "fd_filter.h"
#include "fd_client.h"
#include <errno.h>

long md_fd_filter_prepared(unsigned selectors) {
    if (selectors&~((1U<<MD_FD_SELECTOR_KINDS)-1)) return -EINVAL;
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) if (selectors&(1U<<kind)) {
        long ready=md_fd_control(MD_FD_SELECTOR_QUERY,kind,-1,0);
        if (ready<=0) return ready;
    }
    return 1;
}

long md_fd_filter_arm_mask(unsigned selectors, int fd) {
    if (selectors&~((1U<<MD_FD_SELECTOR_KINDS)-1)) return -EINVAL;
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) if (selectors&(1U<<kind)) {
        long error=md_fd_filter_arm((enum md_fd_selector_kind)kind,fd);
        if (error) return error;
    }
    return 0;
}

static long arm(enum md_fd_selector_kind kind, int fd) {
    if (fd< -1 || kind<0 || kind>=MD_FD_SELECTOR_KINDS) return -EINVAL;
#ifdef MD_USE_LIBC
    return -ENOTSUP;
#else
    for (;;) {
        long result=md_fd_control(MD_FD_SELECTOR_INSTALL,kind,fd,0);
        if (result<=0) return result;
        /* EVENT_WAIT: a retiring private helper can temporarily reject TSYNC.
         * Retry only after its exit; incompatible live filters remain errors. */
        result=md_fd_control(MD_FD_SELECTOR_EXIT,(uint64_t)result,0,0);
        if (result<0) return result;
    }
#endif
}
long md_fd_filter_arm(enum md_fd_selector_kind kind, int fd) {
    return fd<0 ? -EINVAL : arm(kind,fd);
}
long md_fd_filter_prepare_sandbox(void) {
    /* Prepare descriptor and readiness selectors for future typed FDs before an
     * application can deny seccomp. Its ERRNO/TRAP/KILL decisions still win.
     * Unsandboxed workloads keep the selective per-number path. */
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) if (MD_FD_SANDBOX_SELECTORS&(1U<<kind)) {
        long result=arm((enum md_fd_selector_kind)kind,-1);
        if (result) return result;
    }
    return 0;
}
