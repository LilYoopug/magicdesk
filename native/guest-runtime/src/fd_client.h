#ifndef MD_FD_CLIENT_H
#define MD_FD_CLIENT_H
#include <stdint.h>
enum md_fd_control { MD_FD_INPUT=1, MD_FD_SENT, MD_FD_RECEIVE, MD_FD_RECEIVED, MD_FD_END,
    MD_FD_USE, MD_FD_RELEASE };
/* USE/RELEASE bracket short task-affine native descriptor operations only.
 * They allocate no exchange and must not cover blocking reads or rendezvous. */
#ifdef MD_USE_LIBC
static inline long md_fd_control(unsigned op, uint64_t id, long first, long second) {
    (void)op; (void)id; (void)first; (void)second; return 0;
}
#else
long md_fd_control(unsigned op, uint64_t id, long first, long second);
void md_fd_client_enable(void);
#endif
#endif
