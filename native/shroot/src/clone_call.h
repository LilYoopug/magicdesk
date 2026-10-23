#ifndef MD_CLONE_CALL_H
#define MD_CLONE_CALL_H
#include <linux/sched.h>
#include <sys/syscall.h>
#include "pid_namespace.h"

struct md_clone_request {
    struct clone_args args;
    pid_t tids[MD_PID_LEVELS];
};

static inline int md_clone_call(long nr) { return nr==SYS_clone || nr==SYS_clone3; }
/* Capture in the caller, retaining the shared buffer until kernel completion.
 * Never rewrite the application's clone_args or execute clone on an adapter stack. */
long md_clone3_prepare(unsigned long address,unsigned long size);
#endif
