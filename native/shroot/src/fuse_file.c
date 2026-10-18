#define _GNU_SOURCE
#include "fuse_view_internal.h"
#include "fuse_image.h"
#include "fs_control.h"
#include "resource_order.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct fuse_file {
    atomic_uint references;
    struct fuse_view *view;
    struct fuse_node *node;
    struct md_fs_anchor *origin;
    struct md_identity opener;
    uint64_t handle;
    unsigned flags;
    int opened;
    int snapshot;
    uint64_t snapshot_changes;
    struct fuse_attr snapshot_attributes;
};
static void *file_retain(void *context) {
    struct fuse_file *f=context; atomic_fetch_add_explicit(&f->references,1,memory_order_relaxed); return f;
}
void md_fuse_file_release_remote(struct fuse_view *v,uint64_t node,int directory,const struct md_identity *identity,
        uint64_t handle,unsigned flags) {
    struct fuse_release_in in={.fh=handle,.flags=flags&~(O_CREAT|O_EXCL|O_TRUNC)};
    struct md_fuse_request *request=NULL;
    unsigned opcode=directory ? FUSE_RELEASEDIR : FUSE_RELEASE;
    int error=md_fuse_session_request(v->session,identity,0,opcode,node,&in,sizeof(in),0,0,NULL,&request);
    if (!error) md_fuse_request_release(request);
    else if (error==-EAGAIN) md_fuse_session_abort(v->session,error);
}
void md_fuse_file_release_handle(struct fuse_view *v,struct fuse_node *node,const struct md_identity *identity,
        uint64_t handle,unsigned flags) {
    md_fuse_file_release_remote(v,node->id,S_ISDIR(node->type),identity,handle,flags);
}
static void file_release(void *context) {
    struct fuse_file *f=context;
    if (atomic_fetch_sub_explicit(&f->references,1,memory_order_acq_rel)!=1) return;
    if (f->opened) md_fuse_file_release_handle(f->view,f->node,&f->opener,f->handle,f->flags);
    if (f->snapshot>=0) close(f->snapshot);
    md_fs_anchor_release(f->origin); md_identity_release(&f->opener); md_fuse_view_release(f->view); free(f);
}
static int file_stat(void *context,struct stat *out) {
    struct fuse_file *f=context;
    pthread_mutex_lock(&f->view->lock); *out=f->node->attributes; pthread_mutex_unlock(&f->view->lock); return 0;
}
static int file_access(void *context,const struct md_identity *id,unsigned mode) {
    (void)context; (void)id; return mode&~7U ? -EINVAL : 0;
}
static int file_descriptor(void *context,int flags) {
    struct fuse_file *f=context;
    return md_fuse_node_open(f->view,f->node,(flags&(O_PATH|O_DIRECTORY))|O_RDONLY);
}
static struct md_fs_anchor *file_origin(void *context) { return ((struct fuse_file *)context)->origin; }
struct file_io {
    struct md_control_pending base;
    struct fuse_file *file;
    struct md_fuse_request *request;
    unsigned operation,command;
    size_t length;
    int64_t offset;
};
static long io_resume(struct md_control_pending *base,void *data,size_t capacity) {
    struct file_io *io=(void *)base;
    if (io->command) {
        struct fuse_attr_out result; struct stat st;
        long n=md_fuse_request_result(io->request,&result,sizeof(result));
        if (io->command!=MD_CONTROL_TRUNCATE) return n==-ENOSYS ? 0 : n>0 ? -EPROTO : n;
        if (n<0) return n;
        int error=n!=sizeof(result) ? -EPROTO : md_fuse_view_attributes(io->file->view,&result.attr,&st);
        if (error) return error;
        pthread_mutex_lock(&io->file->view->lock);
        io->file->node->attributes=st;
        ++io->file->node->changes;
        pthread_mutex_unlock(&io->file->view->lock); return 0;
    }
    if (!io->operation) {
        struct fuse_attr_out result; struct stat st;
        long n=md_fuse_request_result(io->request,&result,sizeof(result));
        if (n<0) return n;
        int error=n!=sizeof(result) ? -EPROTO : md_fuse_view_attributes(io->file->view,&result.attr,&st);
        if (error) return error;
        if (!S_ISREG(st.st_mode)) return -EINVAL;
        pthread_mutex_lock(&io->file->view->lock);
        io->file->node->attributes=st;
        pthread_mutex_unlock(&io->file->view->lock);
        int64_t offset;
        return __builtin_add_overflow(io->offset,st.st_size,&offset) || offset<0 ? -EINVAL : offset;
    }
    if (io->operation==MD_CONTROL_WRITE) {
        struct fuse_write_out result;
        long n=md_fuse_request_result(io->request,&result,sizeof(result));
        if (n<0) return n;
        if (n!=sizeof(result) || result.size>io->length) return -EPROTO;
        struct fuse_view *v=io->file->view;
        pthread_mutex_lock(&v->lock);
        if (result.size) ++io->file->node->changes;
        if (result.size && io->file->node->attributes.st_size<io->offset+(int64_t)result.size)
            io->file->node->attributes.st_size=io->offset+result.size;
        pthread_mutex_unlock(&v->lock); return result.size;
    }
    if (io->operation==MD_CONTROL_READ) return md_fuse_request_result(io->request,data,capacity);
    union { uint64_t alignment; unsigned char bytes[MD_FUSE_IO_SIZE]; } input;
    long n=md_fuse_request_result(io->request,input.bytes,sizeof(input.bytes));
    if (n<0) return n;
    struct directory_entry { uint64_t ino; int64_t off; uint16_t length; unsigned char type; char name[]; };
    size_t used=0;
    io->base.position=io->offset;
    for (size_t at=0;at<(size_t)n;) {
        const struct fuse_dirent *e=(const void *)(input.bytes+at);
        size_t remaining=(size_t)n-at;
        if (remaining<offsetof(struct fuse_dirent,name) || !e->namelen || e->namelen>NAME_MAX
                || FUSE_DIRENT_SIZE(e)>remaining || e->off>INT64_MAX || e->type>15
                || memchr(e->name,0,e->namelen) || memchr(e->name,'/',e->namelen)) return -EPROTO;
        size_t size=(offsetof(struct directory_entry,name)+e->namelen+1+7)&~(size_t)7;
        if (size>capacity-used) return used ? (long)used : -EINVAL;
        struct directory_entry *out=(void *)((char *)data+used);
        memset(out,0,size); out->ino=e->ino; out->off=e->off; out->length=size; out->type=e->type;
        memcpy(out->name,e->name,e->namelen); used+=size; io->base.position=e->off;
        at+=FUSE_DIRENT_SIZE(e);
    }
    return used;
}
static void io_destroy(struct md_control_pending *base) {
    struct file_io *io=(void *)base;
    md_fuse_request_cancel(io->request); md_fuse_request_release(io->request); file_release(io->file); free(io);
}
static long file_seek(void *context,const struct md_control_actor *actor,int64_t offset,int whence,
        struct md_control_pending **out) {
    struct fuse_file *f=context;
    if (whence!=SEEK_END || S_ISDIR(f->node->type)) return -EINVAL;
    if (!actor || !actor->identity || !f->opened) return -EBADF;
    struct file_io *io=calloc(1,sizeof(*io)); if (!io) return -ENOMEM;
    io->base=(struct md_control_pending){.resume=io_resume,.dispose=io_destroy,.deadline=INT64_MAX};
    io->file=file_retain(f); io->offset=offset;
    struct fuse_getattr_in in={.getattr_flags=FUSE_GETATTR_FH,.fh=f->handle};
    int error=md_fuse_session_request(f->view->session,actor->identity,md_fuse_view_pid(f->view,actor->pid),
        FUSE_GETATTR,f->node->id,&in,sizeof(in),sizeof(struct fuse_attr_out),0,actor->wakeup,&io->request);
    if (error) { io_destroy(&io->base); return error; }
    *out=&io->base; return -EINPROGRESS;
}
static long file_command(void *context,const struct md_control_actor *actor,unsigned command,int64_t value,
        struct md_control_pending **out) {
    struct fuse_file *f=context;
    if (!actor || !actor->identity || !f->opened) return -EBADF;
    int directory=S_ISDIR(f->node->type);
    union { struct fuse_setattr_in truncate; struct fuse_fsync_in sync; } input={0};
    unsigned opcode; size_t size,capacity=0;
    if (command==MD_CONTROL_TRUNCATE) {
        if (directory || value<0 || (f->flags&O_ACCMODE)==O_RDONLY) return -EINVAL;
        if (md_fs_anchor_policy(f->origin)&MD_MOUNT_READONLY) return -EROFS;
        input.truncate=(struct fuse_setattr_in){.valid=FATTR_SIZE|FATTR_FH,.fh=f->handle,.size=value};
        opcode=FUSE_SETATTR; size=sizeof(input.truncate); capacity=sizeof(struct fuse_attr_out);
    } else if (command==MD_CONTROL_SYNC || command==MD_CONTROL_DATASYNC) {
        input.sync=(struct fuse_fsync_in){.fh=f->handle,.fsync_flags=command==MD_CONTROL_DATASYNC};
        opcode=directory ? FUSE_FSYNCDIR : FUSE_FSYNC; size=sizeof(input.sync);
    } else return -EINVAL;
    struct file_io *io=calloc(1,sizeof(*io)); if (!io) return -ENOMEM;
    io->base=(struct md_control_pending){.resume=io_resume,.dispose=io_destroy,.deadline=INT64_MAX};
    io->file=file_retain(f); io->command=command;
    int error=md_fuse_session_request(f->view->session,actor->identity,md_fuse_view_pid(f->view,actor->pid),
        opcode,f->node->id,&input,size,capacity,0,actor->wakeup,&io->request);
    if (error) { io_destroy(&io->base); return error; }
    *out=&io->base; return -EINPROGRESS;
}
static long file_io(void *context,const struct md_control_actor *actor,unsigned operation,
        void *data,size_t size,int64_t offset,struct md_control_pending **out) {
    struct fuse_file *f=context;
    if (!actor || !actor->identity || !f->opened) return -EBADF;
    if (!size) return operation==MD_CONTROL_GETDENTS ? -EINVAL : 0;
    if (offset<0 || size>(uint64_t)(INT64_MAX-offset)) return -EINVAL;
    struct file_io *io=calloc(1,sizeof(*io)); if (!io) return -ENOMEM;
    io->base=(struct md_control_pending){.resume=io_resume,.dispose=io_destroy,.deadline=INT64_MAX};
    io->file=file_retain(f); io->operation=operation; io->offset=offset;
    uint32_t max=operation==MD_CONTROL_WRITE ? md_fuse_session_write_size(f->view->session)
        : md_fuse_session_read_size(f->view->session);
    if (size>max) size=max;
    io->length=size;
    unsigned char input[sizeof(struct fuse_write_in)+MD_FUSE_IO_SIZE];
    size_t input_size,reply_size; unsigned opcode;
    if (operation==MD_CONTROL_WRITE) {
        struct fuse_write_in in={.fh=f->handle,.offset=offset,.size=size,.flags=f->flags};
        memcpy(input,&in,sizeof(in)); memcpy(input+sizeof(in),data,size);
        input_size=sizeof(in)+size; reply_size=sizeof(struct fuse_write_out); opcode=FUSE_WRITE;
    } else {
        struct fuse_read_in in={.fh=f->handle,.offset=offset,.size=operation==MD_CONTROL_GETDENTS ? max : size,.flags=f->flags};
        memcpy(input,&in,sizeof(in)); input_size=sizeof(in); reply_size=in.size;
        opcode=operation==MD_CONTROL_GETDENTS ? FUSE_READDIR : FUSE_READ;
    }
    int error=md_fuse_session_request(f->view->session,actor->identity,md_fuse_view_pid(f->view,actor->pid),
        opcode,f->node->id,input,input_size,reply_size,0,actor->wakeup,&io->request);
    if (error) { io_destroy(&io->base); return error; }
    *out=&io->base; return -EINPROGRESS;
}
struct file_mapping {
    struct md_control_pending base;
    struct fuse_file *file;
    struct md_identity identity;
    struct md_resource_wakeup *wake;
    struct md_fuse_request *attributes;
    struct fuse_attr attr;
    struct md_fuse_image *image;
    uint32_t pid;
    uint64_t changes;
};
static long mapping_resume(struct md_control_pending *base,void *data,size_t size) {
    (void)data; (void)size;
    struct file_mapping *p=(void *)base;
    struct fuse_file *f=p->file;
    if (p->attributes) {
        struct fuse_attr_out reply;
        long result=md_fuse_request_result(p->attributes,&reply,sizeof(reply));
        if (result<0) return result;
        if (result!=sizeof(reply)) return -EPROTO;
        md_fuse_request_release(p->attributes); p->attributes=NULL;
        p->attr=reply.attr;
        pthread_mutex_lock(&f->view->lock);
        int cached=f->snapshot>=0 && p->changes==f->snapshot_changes
            && p->changes==f->node->changes && md_fuse_image_same(&p->attr,&f->snapshot_attributes);
        int fd=cached ? fcntl(f->snapshot,F_DUPFD_CLOEXEC,3) : -1;
        int error=cached && fd<0 ? -errno : 0;
        pthread_mutex_unlock(&f->view->lock);
        if (cached) return error ? error : fd;
        error=md_fuse_image_new(f->view->session,&p->identity,p->pid,f->node->id,f->handle,&p->attr,&p->image);
        if (error) return error;
    }
    int fd=md_fuse_image_advance(p->image,p->wake);
    if (fd<0) return fd;
    pthread_mutex_lock(&f->view->lock);
    int changed=p->changes!=f->node->changes;
    pthread_mutex_unlock(&f->view->lock);
    if (changed) { close(fd); return -EAGAIN; }
    int cached=fcntl(fd,F_DUPFD_CLOEXEC,3);
    if (cached>=0) {
        pthread_mutex_lock(&f->view->lock);
        int old=f->snapshot; f->snapshot=cached; f->snapshot_attributes=p->attr;
        f->snapshot_changes=p->changes;
        pthread_mutex_unlock(&f->view->lock);
        if (old>=0) close(old);
    }
    return fd;
}
static void mapping_destroy(struct md_control_pending *base) {
    struct file_mapping *p=(void *)base;
    md_fuse_request_cancel(p->attributes); md_fuse_request_release(p->attributes);
    md_fuse_image_destroy(p->image); md_resource_wakeup_release(p->wake);
    md_identity_release(&p->identity); file_release(p->file); free(p);
}
static long file_mapping(void *context,const struct md_control_actor *actor,unsigned protection,unsigned flags,
        struct md_control_pending **out) {
    struct fuse_file *f=context;
    if (!actor || !actor->identity || !f->opened) return -EBADF;
    if ((flags&MAP_TYPE)!=MAP_PRIVATE) return -EOPNOTSUPP;
    if (!S_ISREG(f->node->type)) return -ENODEV;
    if ((protection&PROT_EXEC) && (md_fs_anchor_policy(f->origin)&MD_MOUNT_NOEXEC)) return -EPERM;
    int error=md_fuse_session_access(f->view->session,actor->identity);
    if (error) return error;
    struct file_mapping *p=calloc(1,sizeof(*p)); if (!p) return -ENOMEM;
    p->base=(struct md_control_pending){.resume=mapping_resume,.dispose=mapping_destroy,.deadline=INT64_MAX};
    p->file=file_retain(f); p->identity=md_identity_copy(actor->identity);
    pthread_mutex_lock(&f->view->lock); p->changes=f->node->changes; pthread_mutex_unlock(&f->view->lock);
    p->pid=md_fuse_view_pid(f->view,actor->pid); p->wake=md_resource_wakeup_retain(actor->wakeup);
    struct fuse_getattr_in in={.getattr_flags=FUSE_GETATTR_FH,.fh=f->handle};
    error=md_fuse_session_request(f->view->session,actor->identity,p->pid,FUSE_GETATTR,f->node->id,
        &in,sizeof(in),sizeof(struct fuse_attr_out),0,actor->wakeup,&p->attributes);
    if (error) { mapping_destroy(&p->base); return error; }
    *out=&p->base; return -EINPROGRESS;
}
static const struct md_control_file_ops file_ops={.retain=file_retain,.release=file_release,.stat=file_stat,
    .access=file_access,.descriptor=file_descriptor,.origin=file_origin,.filesystem_paths=1,
    .io=file_io,.seek=file_seek,.command=file_command,.mapping=file_mapping,.splice=1,.filesystem=FUSE_SUPER_MAGIC};

int md_fuse_file_publish(struct fuse_view *view,struct fuse_node *node,struct md_fs_anchor *origin,
        const struct md_identity *identity,unsigned flags,const struct fuse_open_out *opened,
        struct md_fs_result *out,const struct md_fs_output *output) {
    struct fuse_file *f=calloc(1,sizeof(*f)); if (!f) {
        if (opened) md_fuse_file_release_handle(view,node,identity,opened->fh,flags);
        return -ENOMEM;
    }
    atomic_init(&f->references,1); f->view=md_fuse_view_retain(view); f->node=node; f->snapshot=-1;
    f->origin=md_fs_anchor_retain(origin); f->opener=md_identity_copy(identity);
    f->flags=flags&~(O_CREAT|O_EXCL|O_TRUNC|O_NOCTTY);
    if (opened) { f->handle=opened->fh; f->opened=1; }
    int error=md_fs_control_publish(file_descriptor(f,f->flags),(struct md_control_file){&file_ops,f},
        f->origin,&f->opener,f->flags,out,output);
    file_release(f); return error;
}
