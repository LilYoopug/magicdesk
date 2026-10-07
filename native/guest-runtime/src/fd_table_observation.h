#ifndef MD_FD_TABLE_OBSERVATION_H
#define MD_FD_TABLE_OBSERVATION_H
#include "fd_receipt.h"

/* Borrowed, task-captured /proc/<exact tid>/fd directory with an exclusive cursor.
 * It retains neither the
 * task's table nor its application OFDs. Only for one lowest-free-slot receive
 * under an uninterrupted destination-table turn. No close/dup/exec or other
 * installation may run between begin and read, including channel admission.
 * Read at syscall completion or PTRACE_EVENT_EXIT, never after task reaping. */
struct md_fd_table_observation {
    int directory;
    unsigned capacity;
    int candidates[MD_FD_RECEIPT_MAX];
};
/* Zero-initialized caller-owned storage; no allocation or descriptor duplication. */
int md_fd_table_observation_begin(struct md_fd_table_observation *, int directory, unsigned capacity);
/* Installed prefix, or explicit observation failure; never reads guest memory.
 * Output remains unchanged on failure. The caller owns directory through read. */
int md_fd_table_observation_read(const struct md_fd_table_observation *, int *numbers);
#endif
