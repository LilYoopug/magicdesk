#ifndef MD_TASK_DESCRIPTOR_H
#define MD_TASK_DESCRIPTOR_H
#include <sys/types.h>

/* Caller holds the source table's publication turn. The returned descriptor
 * retains the actual OFD; no pathname or inode identity substitutes for it.
 * Initialize process to -1 and close it before retiring the task identity. */
int md_task_descriptor_copy(pid_t actor, int number, int *process);
#endif
