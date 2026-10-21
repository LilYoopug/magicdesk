#ifndef MD_SYSCALL_RESULT_H
#define MD_SYSCALL_RESULT_H

/* Kernel-internal syscall-exit values, not application errno. In particular,
 * EINTR can be a final result and must not imply replay of an operation. */
static inline int md_syscall_restarting(long value) {
    return value==-512 || value==-513 || value==-514 || value==-516;
}
#endif
