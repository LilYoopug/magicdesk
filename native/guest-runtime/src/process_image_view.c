#define _GNU_SOURCE
#include "process_image_view.h"
#include "proc_paths.h"
#include "fs_rpc.h"
#include "control_file.h"
#include "program_files.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <linux/magic.h>
#include <stdatomic.h>
#include <unistd.h>

struct md_process_executable { atomic_uint references; int fd; };
struct md_process_executable *md_process_executable_new(int fd) {
    struct md_process_executable *image=malloc(sizeof(*image));
    if (!image) return NULL;
    int retained=fcntl(fd,F_DUPFD_CLOEXEC,0);
    if (retained<0) { int error=errno; free(image); errno=error; return NULL; }
    atomic_init(&image->references,1); image->fd=retained; return image;
}
struct md_process_executable *md_process_executable_retain(struct md_process_executable *image) {
    if (image) atomic_fetch_add_explicit(&image->references,1,memory_order_relaxed);
    return image;
}
void md_process_executable_release(struct md_process_executable *image) {
    if (!image || atomic_fetch_sub_explicit(&image->references,1,memory_order_acq_rel)!=1) return;
    close(image->fd); free(image);
}
static void *image_retain(void *image) { return md_process_executable_retain(image); }
static void image_release(void *image) { md_process_executable_release(image); }
static int image_stat(void *context,struct stat *st) {
    struct md_process_executable *image=context;
    return fstat(image->fd,st) ? -errno : 0;
}
static long image_read(void *context,const struct md_control_actor *actor,void *out,size_t size,int64_t offset) {
    (void)actor;
    struct md_process_executable *image=context;
    ssize_t result=pread(image->fd,out,size,offset);
    return result<0 ? -errno : result;
}
static int image_access(void *context,const struct md_identity *identity,unsigned mode) {
    (void)context; (void)identity;
    return mode&W_OK ? -ETXTBSY : 0;
}
static int image_descriptor(void *context,int flags) {
    struct md_process_executable *image=context;
    int fd;
    if (flags&O_PATH) {
        char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",image->fd);
        fd=open(path,O_PATH|O_CLOEXEC);
    } else fd=fcntl(image->fd,F_DUPFD_CLOEXEC,0);
    return fd<0 ? -errno : fd;
}
static int image_seals(void *context) {
    struct md_process_executable *image=context;
    int seals=fcntl(image->fd,F_GET_SEALS);
    return seals<0 ? -errno : seals;
}
static const struct md_control_file_ops image_ops={.retain=image_retain,.release=image_release,
    .stat=image_stat,.read=image_read,.access=image_access,.filesystem=TMPFS_MAGIC,
    .descriptor=image_descriptor,.seals=image_seals,.mappable=1};
struct md_control_file md_process_executable_view(struct md_process_executable *image) {
    return (struct md_control_file){image ? &image_ops : NULL,image};
}
static int copy(pid_t pid, uintptr_t address, void *data, size_t size) {
    if (address>UINTPTR_MAX-size) return -EFAULT;
    struct iovec local={data,size}, remote={(void *)address,size};
    return process_vm_readv(pid,&local,1,&remote,1,0)==(ssize_t)size ? 0 : -EFAULT;
}
ssize_t md_process_image_link(pid_t pid, uintptr_t image, char *out, size_t capacity) {
    if (!image) return -ENOENT;
    if (!out || !capacity || image>UINTPTR_MAX-sizeof(struct md_process_image)) return -EINVAL;
    uintptr_t path=0;
    int error=copy(pid,image+offsetof(struct md_process_image,executable_path),&path,sizeof(path));
    if (error) return error;
    for (size_t size=0;size<capacity;++size) {
        if (path>UINTPTR_MAX-size) return -EFAULT;
        error=copy(pid,path+size,out+size,1);
        if (error) return error;
        if (!out[size]) return (ssize_t)size;
    }
    return -ENAMETOOLONG;
}
int md_process_image_identity(pid_t pid,uintptr_t image,struct md_image_identity *out) {
    memset(out,0,sizeof(*out));
    ssize_t result=md_process_image_link(pid,image,out->path,sizeof(out->path));
    if (result<0) return (int)result;
    int error=copy(pid,image+offsetof(struct md_process_image,executable_object),out->object,sizeof(out->object));
    if (!error && out->object[sizeof(out->object)-1]) error=-EPROTO;
    return error;
}
int md_process_image_view(pid_t pid, uintptr_t image, unsigned kind, unsigned flags, const char *endpoint, pid_t caller) {
    if (!image) return -ENOENT;
    if (kind!=MD_PROC_AUXV && kind!=MD_PROC_CMDLINE && kind!=MD_PROC_EXE) return -ENOTSUP;
    if (flags&O_DIRECTORY) return -ENOTDIR;
    if ((flags&O_ACCMODE)!=O_RDONLY || (flags&O_TRUNC)) return -EACCES;
    if ((flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) return -EEXIST;
    struct md_process_image *view=malloc(sizeof(*view));
    if (!view) return -ENOMEM;
    int r=copy(pid,image,view,sizeof(*view));
    if (!r && (view->argc>1040 || view->auxv_bytes>sizeof(view->auxv) || view->executable_object[32])) r=-EPROTO;
    struct md_fs_request q={.actor=caller,.operation=kind==MD_PROC_EXE ? MD_FS_OPEN_OBJECT : MD_FS_TEMPORARY,
        .directory={-1,-1},.path={view->executable_object,NULL}};
    if (q.operation==MD_FS_TEMPORARY) q.path[0]=NULL;
    else q.flags=flags&~(O_CREAT|O_EXCL|O_NOFOLLOW);
    struct md_fs_response response;
    if (!r) r=(int)md_fs_call(endpoint,5000,&q,&response);
    if (!r) r=response.result.error;
    int fd=r ? -1 : response.result.fd;
    if (!r && q.operation==MD_FS_TEMPORARY) {
        if (kind==MD_PROC_AUXV) {
            if (write(fd,view->auxv,view->auxv_bytes)!=(ssize_t)view->auxv_bytes) r=-EIO;
        } else {
            char bytes[4096];
            for (unsigned i=0; !r && i<view->argc; ++i) {
                uintptr_t address=view->argv[i];
                size_t count=view->arg_lengths[i];
                if (count>sizeof(bytes)) { r=-E2BIG; break; }
                r=copy(pid,address,bytes,count);
                if (!r && write(fd,bytes,count)!=(ssize_t)count) r=-EIO;
            }
        }
        if (!r) {
            char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
            int readable=open(path,(flags&~(O_CREAT|O_EXCL|O_NOFOLLOW))|O_CLOEXEC);
            if (readable<0) r=-errno;
            else { close(fd); fd=readable; }
        }
    }
    free(view);
    if (r && fd>=0) close(fd);
    return r ? r : fd;
}
