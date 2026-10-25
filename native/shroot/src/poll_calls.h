#ifndef MD_POLL_CALLS_H
#define MD_POLL_CALLS_H
#include "epoll_calls.h"
#include <poll.h>
enum { MD_POLL_CHUNK=256, MD_POLL_LOAD=0x50000003 };
struct md_poll_frame {
    struct md_epoll_frame wait;
    int64_t elapsed;
    unsigned total,offset,count,select;
    struct pollfd items[MD_POLL_CHUNK];
    unsigned long signal[2];
};
/* The variable native vector follows the fixed protocol frame in one loan. */
static inline struct pollfd *md_poll_native(struct md_poll_frame *f) { return (void *)(f+1); }
static inline size_t md_poll_bytes(unsigned count) {
    return sizeof(struct md_poll_frame)+(size_t)count*sizeof(struct pollfd)+3*((count+63UL)/64)*sizeof(unsigned long);
}
#ifndef MD_USE_LIBC
long md_poll_call(long,const unsigned long *,unsigned long);
#endif
#endif
