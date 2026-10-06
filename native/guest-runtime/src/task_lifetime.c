#define _GNU_SOURCE
#include "task_lifetime.h"
#include "task_descriptor.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int md_task_lifetime_open(struct md_task_lifetime *out, pid_t tid) {
    if (!out || out->fd>=0) return -EINVAL;
    int exact=0, fd=md_task_pidfd_open(tid,&exact), fallback=0;
    /* A flags-zero pidfd reports group death, not leader-thread death. */
    if (fd==-ENOTSUP || (fd>=0 && !exact)) {
        if (fd>=0) close(fd);
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/stat",tid);
        fd=open(path,O_RDONLY|O_CLOEXEC);
        if (fd<0) return -errno;
        fallback=1;
    }
    if (fd<0) return fd;
    *out=(struct md_task_lifetime){fd,fallback};
    int error=md_task_lifetime_alive(out);
    if (error) md_task_lifetime_close(out);
    return error;
}
int md_task_lifetime_copy(struct md_task_lifetime *out, const struct md_task_lifetime *source) {
    if (!out || out->fd>=0 || !source || source->fd<0) return -EINVAL;
    int fd=fcntl(source->fd,F_DUPFD_CLOEXEC,0);
    if (fd<0) return -errno;
    *out=(struct md_task_lifetime){fd,source->proc_stat};
    return 0;
}
int md_task_lifetime_alive(const struct md_task_lifetime *task) {
    if (!task || task->fd<0) return -EINVAL;
    if (!task->proc_stat) {
        struct pollfd event={.fd=task->fd,.events=POLLIN};
        int r;
        do { r=poll(&event,1,0); } while (r<0 && errno==EINTR);
        return r<0 ? -errno : (event.revents&POLLNVAL) ? -EBADF : r ? -ENOENT : 0;
    }
    char status[256]; ssize_t n;
    do { n=pread(task->fd,status,sizeof(status)-1,0); } while (n<0 && errno==EINTR);
    if (n<0) return errno==ESRCH ? -ENOENT : -errno;
    if (!n) return -ENOENT;
    status[n]=0;
    /* comm may contain spaces, newlines and ')'; numeric fields cannot. */
    char *end=strrchr(status,')');
    if (!end || status+n-end<4 || end[1]!=' ' || end[3]!=' ') return -EPROTO;
    return end[2]=='Z' || end[2]=='X' || end[2]=='x' ? -ENOENT : 0;
}
void md_task_lifetime_close(struct md_task_lifetime *task) {
    if (!task) return;
    if (task->fd>=0) close(task->fd);
    *task=(struct md_task_lifetime){.fd=-1};
}
