#ifndef MD_TASK_STATUS_H
#define MD_TASK_STATUS_H
#include <stdint.h>
/* Kernel state read by its native owner, never cached or changed to inspect it. */
long md_task_status_open(int tid);
/* The caller owns the descriptor; each read starts a fresh proc snapshot. */
long md_task_umask_fd(int fd);
long md_task_umask(int tid);
long md_task_signal_handlers(int tid, uint64_t *caught);
long md_task_parent(int tid);
long md_task_nofile(int tid,uint64_t *soft);
#endif
