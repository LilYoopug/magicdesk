#define _GNU_SOURCE
#include "task_descriptor.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

int md_task_descriptor_copy(pid_t actor, int number, int *process) {
    if (actor<=0 || !process) return -EINVAL;
    if (number<0) return -EBADF;
    if (actor==getpid()) {
        int fd=fcntl(number,F_DUPFD_CLOEXEC,0);
        return fd<0 ? -errno : fd;
    }
    if (*process<0) {
        *process=(int)syscall(SYS_pidfd_open,actor,MD_PIDFD_THREAD);
        if (*process<0 && errno==EINVAL) *process=(int)syscall(SYS_pidfd_open,actor,0);
        if (*process<0) return -errno;
    }
    int fd=(int)syscall(SYS_pidfd_getfd,*process,number,0);
    return fd<0 ? -errno : fd;
}
