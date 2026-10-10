#ifndef MD_TASK_WAIT_H
#define MD_TASK_WAIT_H
#include <sys/resource.h>
#include <sys/types.h>

/* SIGCHLD is a lossy hint, never ownership or proof of a stopped task.
 * The kernel remains the event queue; no wait status is buffered here. */
struct md_task_wait {
    pid_t hint;
    unsigned directed;
    int drained;
};
void md_task_wait_hint(struct md_task_wait *, pid_t);
/* Nonblocking __WALL wait with bounded preference for the notified TID.
 * A general empty result remains valid until SIGCHLD invalidates it. Callers
 * must drain the blocked signal source before sleeping for its next event.
 * Returns the unmodified wait4 result, status, rusage and errno. */
pid_t md_task_wait_ready(struct md_task_wait *, int *, struct rusage *);
#endif
