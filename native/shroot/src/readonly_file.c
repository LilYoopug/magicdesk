#define _GNU_SOURCE
#include "readonly_file.h"
#include "file_open.h"
#include "file_permissions.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

struct readonly_file { atomic_uint references; int fd; };
static void *retain(void *context) {
    struct readonly_file *f=context;
    atomic_fetch_add_explicit(&f->references,1,memory_order_relaxed); return f;
}
static void release(void *context) {
    struct readonly_file *f=context;
    if (atomic_fetch_sub_explicit(&f->references,1,memory_order_acq_rel)==1) { close(f->fd); free(f); }
}
static int metadata(void *context,struct stat *st) {
    struct readonly_file *f=context;
    return fstat(f->fd,st) ? -errno : 0;
}
static long read_at(void *context,const struct md_control_actor *actor,void *data,size_t size,int64_t offset) {
    (void)actor;
    struct readonly_file *f=context;
    ssize_t n=pread(f->fd,data,size,offset); return n<0 ? -errno : n;
}
static size_t read_size(void *context) { (void)context; return MD_CONTROL_IO_MAX; }
static long poll_value(void *context) {
    (void)context; return POLLIN|POLLOUT|POLLRDNORM|POLLWRNORM;
}
static int poll_descriptor(void *context,int *fd) {
    struct readonly_file *f=context; *fd=f->fd; return 0;
}
static int access_mode(void *context,const struct md_identity *identity,unsigned mode) {
    if (mode&W_OK) return -EACCES;
    struct stat st;
    int error=metadata(context,&st);
    return error ? error : md_file_permissions(&st,mode,identity);
}
static int descriptor(void *context,int flags) {
    (void)flags;
    struct readonly_file *f=context;
    return md_open_pinned(f->fd,O_PATH|O_CLOEXEC);
}
static int seals(void *context) {
    struct readonly_file *f=context;
    int value=fcntl(f->fd,F_GET_SEALS); return value<0 ? -errno : value;
}
static long mapping(void *context,const struct md_control_actor *actor,unsigned protection,unsigned flags,
        struct md_control_pending **pending) {
    (void)actor; (void)protection; (void)flags; (void)pending;
    struct readonly_file *f=context;
    int fd=fcntl(f->fd,F_DUPFD_CLOEXEC,3); return fd<0 ? -errno : fd;
}
static const struct md_control_file_ops ops={.retain=retain,.release=release,.stat=metadata,
    .read=read_at,.read_size=read_size,.access=access_mode,.descriptor=descriptor,.seals=seals,
    .poll=poll_value,.poll_descriptor=poll_descriptor,
    .filesystem=TMPFS_MAGIC,.mapping=mapping,.mapping_readonly=1};
struct md_control_file md_readonly_file_new(int fd) {
    struct stat st;
    int flags=fcntl(fd,F_GETFL);
    int error=flags<0 ? errno : fstat(fd,&st) ? errno : 0;
    if (!error && ((flags&O_PATH) || (flags&O_ACCMODE)==O_WRONLY || !S_ISREG(st.st_mode)
            || st.st_nlink || fcntl(fd,F_GET_SEALS)<0)) error=EACCES;
    struct readonly_file *f=error ? NULL : calloc(1,sizeof(*f));
    if (!error && !f) error=errno;
    if (!error) {
        f->fd=fcntl(fd,F_DUPFD_CLOEXEC,3);
        if (f->fd<0) { error=errno; free(f); f=NULL; }
        else atomic_init(&f->references,1);
    }
    if (error) errno=error;
    return (struct md_control_file){f ? &ops : NULL,f};
}
