#ifndef MD_PID_CALLS_H
#define MD_PID_CALLS_H
#include "adapter_buffer.h"

static inline long md_pid_visible(int native) {
#ifdef MD_USE_LIBC
    return native;
#else
    return md_guest_buffer_control(MD_BUFFER_PID_NUMBER,(unsigned)native,0);
#endif
}
static inline long md_pid_native(int visible) {
#ifdef MD_USE_LIBC
    return visible;
#else
    return md_guest_buffer_control(MD_BUFFER_PID_NUMBER,(unsigned)visible,1);
#endif
}
long md_pid_signal_group(int selector,int signal);
long md_pidfd_signal(const unsigned long *);
long md_pidfd_namespace(const unsigned long *);
long md_pid_terminal(const unsigned long *);
#endif
