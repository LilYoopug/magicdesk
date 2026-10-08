#define _GNU_SOURCE
#include "ipc_storage.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int md_ipc_storage_open(const char *store, const char *kind) {
    if (!store || !kind || (strcmp(kind,"sysv") && strcmp(kind,"shm"))) return -EINVAL;
    int fd=open(store,O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -errno;
    const char *parts[]={"ipc","v2",kind};
    for (unsigned i=0;i<sizeof(parts)/sizeof(*parts);++i) {
        int error=mkdirat(fd,parts[i],0700) && errno!=EEXIST ? -errno : 0;
        int child=error ? -1 : openat(fd,parts[i],O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if (!error && child<0) error=-errno;
        close(fd);
        if (error) return error;
        fd=child;
    }
    return fd;
}
