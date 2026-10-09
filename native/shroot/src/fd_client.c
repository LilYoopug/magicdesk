#define _GNU_SOURCE
#include "fd_client.h"
#ifndef MD_USE_LIBC
static int enabled;
extern long md_guest_fd_control(unsigned, uint64_t, long, long);
void md_fd_client_enable(void) { enabled=1; }
long md_fd_control(unsigned op, uint64_t id, long first, long second) {
    return enabled ? md_guest_fd_control(op,id,first,second) : 0;
}
#endif
