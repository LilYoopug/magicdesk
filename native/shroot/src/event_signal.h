#ifndef MD_EVENT_SIGNAL_H
#define MD_EVENT_SIGNAL_H
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

/* Coalesced readiness on an owned, nonblocking, non-semaphore eventfd.
 * The queue/state is authoritative; this counter carries no payload. */
static inline int md_event_signal(int fd) {
    const uint64_t one=1;
    ssize_t n;
    do { n=write(fd,&one,sizeof(one)); } while (n<0 && errno==EINTR);
    return n==sizeof(one) || (n<0 && errno==EAGAIN) ? 0 : n<0 ? -errno : -EIO;
}
static inline int md_event_acknowledge(int fd) {
    uint64_t value;
    ssize_t n;
    /* One read consumes a burst. Do not drain a concurrent producer forever. */
    do { n=read(fd,&value,sizeof(value)); } while (n<0 && errno==EINTR);
    return n==sizeof(value) || (n<0 && errno==EAGAIN) ? 0 : n<0 ? -errno : -EIO;
}
#endif
