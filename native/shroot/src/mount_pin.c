#define _GNU_SOURCE
#include "mount_pin.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int md_mount_pin_create(int root) {
    int fd=openat(root,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0600);
    return fd<0 ? -errno : fd;
}
static int reopen(int source, int flags) {
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",source);
    int fd=open(path,flags|O_CLOEXEC);
    return fd<0 ? -errno : fd;
}
static int acquire(int source, unsigned slot, int exclusive) {
    int fd=reopen(source,exclusive ? O_RDWR : O_RDONLY);
    if (fd<0) return fd;
    struct flock lock={.l_type=exclusive ? F_WRLCK : F_RDLCK,.l_whence=SEEK_SET,.l_start=slot,.l_len=1};
    if (fcntl(fd,F_OFD_SETLK,&lock)) {
        int r=-errno; close(fd);
        return exclusive && (r==-EAGAIN || r==-EACCES) ? -EBUSY : r;
    }
    return fd;
}
int md_mount_pin_acquire(int source, unsigned slot) { return acquire(source,slot,0); }
int md_mount_pin_exclude(int source, unsigned slot) { return acquire(source,slot,1); }
int md_mount_pin_check(int source, int pin) {
    if (source<0 || pin<0) return -EPROTO;
    int flags=fcntl(pin,F_GETFL);
    if (flags<0) return -errno;
    if (flags&O_PATH || (flags&O_ACCMODE)!=O_RDONLY) return -EPROTO;
    struct stat a,b;
    if (fstat(source,&a) || fstat(pin,&b)) return -errno;
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino ? 0 : -EPROTO;
}
