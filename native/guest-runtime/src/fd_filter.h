#ifndef MD_FD_FILTER_H
#define MD_FD_FILTER_H
#include "fd_selector.h"
long md_fd_filter_arm(enum md_fd_selector_kind, int fd);
long md_fd_filter_arm_mask(unsigned selectors, int fd);
#endif
