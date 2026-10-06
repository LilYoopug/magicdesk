#ifndef MD_TASK_STATUS_H
#define MD_TASK_STATUS_H
/* Kernel state read by its native owner, never cached or changed to inspect it. */
long md_task_umask(int tid);
#endif
