#define _GNU_SOURCE
#include "fd_client.h"
#include "raw.h"
#include <fcntl.h>
static int enabled;
const char md_guest_cwd_path[]=".";
extern long md_guest_fd_control(unsigned, uint64_t, long, long);
extern long md_guest_open_cwd(int, const char *, int, unsigned);
void md_fd_client_enable(void) { enabled=1; }
long md_fd_control(unsigned op, uint64_t id, long first, long second) {
    return enabled ? md_guest_fd_control(op,id,first,second) : 0;
}
long md_fd_capture_cwd(void) {
    return enabled ? md_guest_open_cwd(AT_FDCWD,md_guest_cwd_path,O_PATH|O_DIRECTORY|O_CLOEXEC,0)
        : RAW4(openat,AT_FDCWD,".",O_PATH|O_DIRECTORY|O_CLOEXEC,0);
}
