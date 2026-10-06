#ifndef MD_TASK_DESCRIPTOR_H
#define MD_TASK_DESCRIPTOR_H
#include <sys/types.h>

/* Never substitutes the leader for a non-leader. ENOTSUP means the kernel
 * cannot address this task. thread_handle distinguishes exact-thread death
 * from flags-zero group death. The caller retains identity during acquisition. */
int md_task_pidfd_open(pid_t, int *thread_handle);
int md_task_descriptor_needs_export(int error);

/* Caller holds the source table's publication turn. The returned descriptor
 * retains the actual OFD; no pathname or inode identity substitutes for it.
 * Initialize process to -1 and close it before retiring the task identity. */
int md_task_descriptor_copy(pid_t actor, int number, int *process);
#endif
