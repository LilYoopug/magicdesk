#ifndef MD_FD_FILESYSTEM_H
#define MD_FD_FILESYSTEM_H
#include <sys/statfs.h>

/* Retained native FD; negative errno. Only pidfd filesystem metadata has a
 * fallback for denied host statfs. No process operation gains permission. */
int md_fd_filesystem(int fd, struct statfs *out);
#endif
