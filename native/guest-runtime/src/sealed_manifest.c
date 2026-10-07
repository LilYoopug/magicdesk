#define _GNU_SOURCE
#include "sealed_manifest.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

enum { SEALS=F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_WRITE|F_SEAL_SEAL };
int md_sealed_manifest_create(const char *name, const void *data, size_t size, struct md_fd_identity *id) {
    if (!name || !data || !size || !id) return -EINVAL;
    int fd=memfd_create(name,MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (fd<0) return -errno;
    ssize_t n;
    do { n=pwrite(fd,data,size,0); } while (n<0 && errno==EINTR);
    int r=n<0 ? -errno : (size_t)n!=size ? -EIO : 0;
    if (!r && fcntl(fd,F_ADD_SEALS,SEALS)) r=-errno;
    struct stat st;
    if (!r && fstat(fd,&st)) r=-errno;
    if (r) { close(fd); return r; }
    *id=md_fd_identity(&st); return fd;
}
int md_sealed_manifest_read(int fd, void *data, size_t capacity, size_t *size, struct md_fd_identity *id) {
    if (!data || !size || !id) return -EINVAL;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISREG(st.st_mode) || st.st_size<=0 || (uint64_t)st.st_size>capacity) return -EPROTO;
    int seals=fcntl(fd,F_GET_SEALS);
    if (seals<0) return -errno;
    if ((seals&SEALS)!=SEALS) return -EPROTO;
    ssize_t n;
    do { n=pread(fd,data,(size_t)st.st_size,0); } while (n<0 && errno==EINTR);
    if (n<0) return -errno;
    if (n!=st.st_size) return -EPROTO;
    *size=(size_t)n; *id=md_fd_identity(&st); return 0;
}
