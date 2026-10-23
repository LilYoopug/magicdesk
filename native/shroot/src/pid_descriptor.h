#ifndef MD_PID_DESCRIPTOR_H
#define MD_PID_DESCRIPTOR_H
#include "fd_object.h"
#include "pid_namespace.h"
struct md_fd_object *md_pid_descriptor_new(struct md_pid_identity *);
/* Borrowed identity; retain the descriptor object throughout use. */
struct md_pid_identity *md_pid_descriptor_identity(struct md_fd_object *);
/* Exact captured description, not a reopened application pathname.
 * Zero PID means another descriptor kind; -1 is a retired pidfd target. */
int md_pid_descriptor_read(int fd,pid_t *);
#endif
