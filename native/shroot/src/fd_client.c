#define _GNU_SOURCE
#include "fd_client.h"
#ifndef MD_USE_LIBC
static int enabled;
extern struct md_fd_observation md_guest_fd_control(unsigned, uint64_t, long, long);
void md_fd_client_enable(void) { enabled=1; }
long md_fd_control(unsigned op, uint64_t id, long first, long second) {
    return enabled ? md_guest_fd_control(op,id,first,second).selectors : 0;
}
struct md_fd_observation md_fd_observe(int fd) {
    return enabled ? md_guest_fd_control(MD_FD_SELECTORS,0,fd,0) : (struct md_fd_observation){0};
}
#endif
