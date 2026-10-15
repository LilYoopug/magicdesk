#ifndef MD_QUEUE_SIGNAL_H
#define MD_QUEUE_SIGNAL_H
#include "event_signal.h"
#include <fcntl.h>

/* Readiness only: the separately synchronized queue owns the payload. A full
 * nonblocking pipe already carries readiness. A bounded drain cannot starve
 * other event sources when producers keep publishing. */
struct md_queue_signal { int reader, writer; };
static inline int md_queue_signal_open(struct md_queue_signal *s) {
    *s=(struct md_queue_signal){-1,-1};
    int fd[2];
    if (pipe2(fd,O_NONBLOCK|O_CLOEXEC)) return -errno;
    *s=(struct md_queue_signal){fd[0],fd[1]}; return 0;
}
static inline int md_queue_signal_send(const struct md_queue_signal *s) {
    return md_event_signal(s->writer);
}
static inline int md_queue_signal_acknowledge(const struct md_queue_signal *s) {
    uint64_t signals[512];
    ssize_t n;
    do { n=read(s->reader,signals,sizeof(signals)); } while (n<0 && errno==EINTR);
    return (n>0 && !(n%sizeof(*signals))) || (n<0 && errno==EAGAIN) ? 0 : n<0 ? -errno : -EIO;
}
static inline void md_queue_signal_close(struct md_queue_signal *s) {
    if (s->writer>=0) close(s->writer);
    if (s->reader>=0) close(s->reader);
    *s=(struct md_queue_signal){-1,-1};
}
#endif
