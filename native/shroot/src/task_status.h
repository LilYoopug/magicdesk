#ifndef MD_TASK_STATUS_H
#define MD_TASK_STATUS_H
#include <stdint.h>
/* Kernel state read by its native owner, never cached or changed to inspect it. */
long md_task_umask(int tid);
long md_task_signal_handlers(int tid, uint64_t *caught);
long md_task_parent(int tid);
#endif
