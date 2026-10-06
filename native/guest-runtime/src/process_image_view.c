#define _GNU_SOURCE
#include "process_image_view.h"
#include "proc_paths.h"
#include "fs_rpc.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

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
