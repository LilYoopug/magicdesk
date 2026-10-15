#define _GNU_SOURCE
#include "event_signal.h"
#include "queue_signal.h"
#include <assert.h>
#include <stdio.h>
#include <sys/eventfd.h>

static int read_interrupt,write_interrupt;
ssize_t __real_read(int,void *,size_t);
ssize_t __real_write(int,const void *,size_t);
ssize_t __wrap_read(int fd,void *data,size_t size) {
    if (read_interrupt) { read_interrupt=0; errno=EINTR; return -1; }
    return __real_read(fd,data,size);
}
ssize_t __wrap_write(int fd,const void *data,size_t size) {
    if (write_interrupt) { write_interrupt=0; errno=EINTR; return -1; }
    return __real_write(fd,data,size);
}
int main(void) {
    int fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC); assert(fd>=0);
    assert(!md_event_acknowledge(fd));
    write_interrupt=1;
    assert(!md_event_signal(fd) && !write_interrupt);
    assert(!md_event_signal(fd));
    uint64_t value=0;
    assert(read(fd,&value,sizeof(value))==sizeof(value) && value==2);
    value=UINT64_MAX-1;
    assert(write(fd,&value,sizeof(value))==sizeof(value));
    assert(!md_event_signal(fd));
    read_interrupt=1;
    assert(!md_event_acknowledge(fd) && !read_interrupt);
    assert(read(fd,&value,sizeof(value))==-1 && errno==EAGAIN);
    assert(!md_event_acknowledge(fd));
    close(fd);
    assert(md_event_signal(fd)==-EBADF && md_event_acknowledge(fd)==-EBADF);
    struct md_queue_signal queue;
    assert(!md_queue_signal_open(&queue));
    write_interrupt=1;
    assert(!md_queue_signal_send(&queue) && !write_interrupt);
    read_interrupt=1;
    assert(!md_queue_signal_acknowledge(&queue) && !read_interrupt);
    assert(!md_queue_signal_acknowledge(&queue));
    assert(!close(queue.writer)); queue.writer=-1;
    assert(md_queue_signal_acknowledge(&queue)==-EIO);
    md_queue_signal_close(&queue);
    assert(md_queue_signal_send(&queue)==-EBADF && md_queue_signal_acknowledge(&queue)==-EBADF);
    puts("PASS event signal: coalescing, saturation, interrupted IO, acknowledgement and invalid lifetime");
    return 0;
}
