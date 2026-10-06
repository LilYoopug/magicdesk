#ifndef MD_TASK_LIFETIME_H
#define MD_TASK_LIFETIME_H
#include <sys/types.h>

/* Exact task identity, never a numeric PID re-lookup. Initialize fd to -1.
 * Proc-stat fallback is retained once; it is inspected only on demand. */
struct md_task_lifetime { int fd, proc_stat; };
int md_task_lifetime_open(struct md_task_lifetime *, pid_t);
int md_task_lifetime_copy(struct md_task_lifetime *, const struct md_task_lifetime *);
int md_task_lifetime_alive(const struct md_task_lifetime *);
void md_task_lifetime_close(struct md_task_lifetime *);
#endif
