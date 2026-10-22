#define _GNU_SOURCE
#include "fd_filesystem.h"
#include <errno.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PID_FS_MAGIC
#define PID_FS_MAGIC 0x50494446
#endif

int md_fd_filesystem(int fd, struct statfs *out) {
    /* Return the kernel ABI, including ST_VALID which Bionic's wrapper clears. */
    if (!syscall(SYS_fstatfs,fd,out)) return 0;
    int error=-errno;
    if (error!=-EACCES && error!=-EPERM) return error;
    struct stat st,anonymous;
    if (fstat(fd,&st) || (st.st_mode&S_IFMT)) return error;
    char path[64],name[64];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    ssize_t size=readlink(path,name,sizeof(name));
    static const char pidfd[]="anon_inode:[pidfd]";
    if (size!=sizeof(pidfd)-1 || memcmp(name,pidfd,sizeof(pidfd)-1)) return error;
    /* Old pidfds share anon_inodefs; newer kernels have a distinct pidfs.
     * Compare actual superblock identities, not uname or an assumed release. */
    int probe=eventfd(0,EFD_CLOEXEC);
    if (probe<0) return error;
    int result=fstat(probe,&anonymous);
    close(probe);
    if (result) return error;
    unsigned long type=st.st_dev==anonymous.st_dev ? ANON_INODE_FS_MAGIC : PID_FS_MAGIC;
    /* Both providers use simple_statfs. The hidden kernel mount has no user
     * mount flags; ST_VALID is Linux's 0x20. Keep the real device identity. */
    uint64_t dev=(minor(st.st_dev)&0xffU)|(major(st.st_dev)<<8)|((uint64_t)(minor(st.st_dev)&~0xffU)<<12);
    *out=(struct statfs){.f_type=type,.f_bsize=(unsigned long)getpagesize(),
        .f_frsize=(unsigned long)getpagesize(),.f_namelen=NAME_MAX,.f_flags=0x20};
    _Static_assert(sizeof(out->f_fsid)==sizeof(dev),"native filesystem identity");
    memcpy(&out->f_fsid,&dev,sizeof(dev));
    return 0;
}
