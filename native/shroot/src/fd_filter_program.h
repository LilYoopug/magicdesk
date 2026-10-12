#ifndef MD_FD_FILTER_PROGRAM_H
#define MD_FD_FILTER_PROGRAM_H
#include "fd_selector.h"
#include <linux/filter.h>
#include <stdint.h>

struct md_fd_filter_gates { uintptr_t raw,watch,task; };
enum { MD_FD_FILTER_INSTRUCTIONS=256 };
struct md_fd_filter_program {
    struct sock_filter code[MD_FD_FILTER_INSTRUCTIONS];
    unsigned short count;
};
struct md_task_filter_image {
    struct md_fd_filter_program code;
    struct sock_fprog program;
};
/* Pure construction, shared by task-local and supervisor-directed admission.
 * No installation, allocation or pointers into another address space. */
int md_fd_filter_build(enum md_fd_selector_kind,int fd,
    const struct md_fd_filter_gates *,struct md_fd_filter_program *);
#endif
