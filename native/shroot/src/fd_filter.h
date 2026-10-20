#ifndef MD_FD_FILTER_H
#define MD_FD_FILTER_H
#include "fd_selector.h"
enum { MD_FD_SANDBOX_SELECTORS=(1U<<MD_FD_SELECTOR_PROC)|(1U<<MD_FD_SELECTOR_EPOLL_TARGET)
    |(1U<<MD_FD_SELECTOR_EPOLL)|(1U<<MD_FD_SELECTOR_POLL) };
long md_fd_filter_arm(enum md_fd_selector_kind, int fd);
long md_fd_filter_arm_mask(unsigned selectors, int fd);
long md_fd_filter_prepare_sandbox(void);
/* Whether future numbers need no further filter installation. */
long md_fd_filter_prepared(unsigned selectors);
#endif
