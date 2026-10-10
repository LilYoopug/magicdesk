#define _GNU_SOURCE
#include "task_wait.h"
#include <errno.h>
#include <sys/wait.h>

void md_task_wait_hint(struct md_task_wait *w, pid_t pid) {
    if (pid <= 0) return;
    w->drained = 0;
    if (!w->hint) w->hint = pid;
}
pid_t md_task_wait_ready(struct md_task_wait *w, int *status, struct rusage *usage) {
    if (w->drained) return 0;
    /* A hot child cannot indefinitely postpone stops whose SIGCHLD coalesced.
     * This is an event budget, not a timer or a readiness assumption. */
    enum { DIRECTED_BUDGET = 8 };
    if (w->hint && w->directed < DIRECTED_BUDGET) {
        pid_t selected = w->hint;
        w->hint = 0;
        pid_t pid = wait4(selected, status, __WALL | WNOHANG, usage);
        if (pid > 0) { w->directed++; return pid; }
        if (pid < 0 && errno != ECHILD && errno != ESRCH) return pid;
    }
    w->directed = 0;
    pid_t pid = wait4(-1, status, __WALL | WNOHANG, usage);
    if (!pid) {
        /* Only a general wait proves the kernel queue empty. A stale directed
         * hint cannot prove that other tracees have no outstanding events. */
        w->drained = 1;
        w->hint = 0;
    }
    return pid;
}
