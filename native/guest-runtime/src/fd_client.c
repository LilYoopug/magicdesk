#define _GNU_SOURCE
#include "fd_client.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#ifndef MD_USE_LIBC
static int enabled;
extern long md_guest_fd_control(unsigned, uint64_t, long, long);
extern long md_guest_open_anchor(int, const char *, int, unsigned, int);
void md_fd_client_enable(void) { enabled=1; }
long md_fd_control(unsigned op, uint64_t id, long first, long second) {
    return enabled ? md_guest_fd_control(op,id,first,second) : 0;
}
#endif
long md_fd_capture_cwd(void) {
    return md_fd_capture_path(".",AT_FDCWD,1);
}
long md_fd_capture_path(const char *path, int source, int directory) {
    if (source<0 && source!=AT_FDCWD) return -EINVAL;
    int flags=O_PATH|O_CLOEXEC|(directory ? O_DIRECTORY : 0);
#ifndef MD_USE_LIBC
    if (enabled) return md_guest_open_anchor(AT_FDCWD,path,flags,0,source);
#endif
    return RAW4(openat,AT_FDCWD,path,flags,0);
}
