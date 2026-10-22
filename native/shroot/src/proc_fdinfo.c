#define _GNU_SOURCE
#include "proc_fdinfo.h"
#include "fs_engine.h"
#include "fs_control.h"
#include "fs_mounts.h"
#include "pid_namespace.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <linux/stat.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

struct fdinfo {
    atomic_uint references;
    int fd;
    struct stat stat;
    struct md_pid_namespace *view;
    char *text;
    size_t size;
    uint64_t mount_id, inode;
    uint64_t native_mount, native_inode;
};
static void *retain(void *context) {
    struct fdinfo *f=context;
    atomic_fetch_add_explicit(&f->references,1,memory_order_relaxed); return f;
}
static void release(void *context) {
    struct fdinfo *f=context;
    if (atomic_fetch_sub_explicit(&f->references,1,memory_order_acq_rel)!=1) return;
    close(f->fd); md_pid_namespace_release(f->view); free(f->text); free(f);
}
static int stat_info(void *context,struct stat *st) {
    *st=((struct fdinfo *)context)->stat; return 0;
}
static int access_info(void *context,const struct md_identity *identity,unsigned mode) {
    (void)context; (void)identity; return mode&(W_OK|X_OK) ? -EACCES : 0;
}
static void write_pid(FILE *out,const char *name,long pid,struct md_pid_namespace *view,int nested) {
    struct md_pid_identity *id=pid>0 ? md_pid_namespace_find(view,(pid_t)pid) : NULL;
    pid_t visible=pid>0 ? md_pid_identity_number(id,view) : (pid_t)pid;
    fprintf(out,"%s\t%d",name,visible);
    if (nested && visible>0) {
        struct md_pid_namespace *views[33],*space=md_pid_identity_namespace(id);
        unsigned count=0;
        while (space && space!=view && count<32) {
            views[count++]=space; space=md_pid_namespace_parent(space);
        }
        while (count) fprintf(out,"\t%d",md_pid_identity_number(id,views[--count]));
    }
    fputc('\n',out); md_pid_identity_release(id);
}
static int refresh(struct fdinfo *f) {
    if (lseek(f->fd,0,SEEK_SET)<0) return -errno;
    int copy=fcntl(f->fd,F_DUPFD_CLOEXEC,0);
    if (copy<0) return -errno;
    FILE *in=fdopen(copy,"r");
    if (!in) { int error=-errno; close(copy); return error; }
    char *text=NULL,*line=NULL; size_t size=0,capacity=0;
    FILE *out=open_memstream(&text,&size);
    if (!out) { int error=-errno; fclose(in); return error; }
    int error=0,has_pid=0,has_nested=0;
    long target=0;
    errno=0;
    while (getline(&line,&capacity,in)>=0) {
        size_t prefix=!strncmp(line,"Pid:",4) ? 4 : !strncmp(line,"NSpid:",6) ? 6 : 0;
        if (prefix && f->view) {
            char *end; long pid=strtol(line+prefix,&end,10);
            if (end==line+prefix || pid>INT_MAX || pid<-1) { error=-EPROTO; break; }
            if (prefix==4) { has_pid=1; target=pid; }
            else has_nested=1;
            write_pid(out,prefix==4 ? "Pid:" : "NSpid:",pid,f->view,prefix==6);
        } else if (f->mount_id && !strncmp(line,"mnt_id:",7)) {
            uint64_t current;
            if (sscanf(line+7,"%" SCNu64,&current)!=1 || current!=f->native_mount) { error=-ESTALE; break; }
            fprintf(out,"mnt_id:\t%" PRIu64 "\n",f->mount_id);
        } else if (f->mount_id && !strncmp(line,"ino:",4)) {
            uint64_t current;
            if (sscanf(line+4,"%" SCNu64,&current)!=1 || current!=f->native_inode) { error=-ESTALE; break; }
            fprintf(out,"ino:\t%" PRIu64 "\n",f->inode);
        } else fputs(line,out);
    }
    /* Native kernels without CONFIG_PID_NS omit NSpid. A logical proc mount
     * still exposes the namespace chain owned by the runtime. */
    if (has_pid && !has_nested) write_pid(out,"NSpid:",target,f->view,1);
    if (ferror(in) || ferror(out)) error=errno ? -errno : -EIO;
    free(line); fclose(in);
    if (fclose(out) && !error) error=-errno;
    if (error) free(text);
    else { free(f->text); f->text=text; f->size=size; }
    return error;
}
static long read_info(void *context,const struct md_control_actor *actor,void *out,size_t size,int64_t offset) {
    (void)actor;
    struct fdinfo *f=context;
    if (offset<0) return -EINVAL;
    if (!size) return 0;
    if (!offset || !f->text) { int error=refresh(f); if (error) return error; }
    if ((uint64_t)offset>=f->size) return 0;
    if (size>f->size-(size_t)offset) size=f->size-(size_t)offset;
    memcpy(out,f->text+offset,size); return (long)size;
}
static const struct md_control_file_ops ops={.retain=retain,.release=release,.stat=stat_info,
    .access=access_info,.read=read_info,.filesystem=PROC_SUPER_MAGIC};
void md_fs_fdinfo(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_fs_result *result,const struct md_fs_output *output) {
    *result=(struct md_fs_result){.fd=-1};
    if (!fs->actor || !output || !output->control) { result->error=-EOPNOTSUPP; return; }
    struct fdinfo *f=calloc(1,sizeof(*f));
    if (!f) { result->error=-ENOMEM; return; }
    atomic_init(&f->references,1); f->fd=-1;
    f->view=q->offset ? md_pid_namespace_by_inode((uint64_t)q->offset) : NULL;
    if (q->offset && !f->view && (uint64_t)q->offset!=md_pid_namespace_inode(NULL)) result->error=-ENOENT;
    if (!result->error && q->directory[1]>=0) {
        struct md_control_file control=q->control;
        const struct md_fs_anchor *origin=control.ops && control.ops->origin
            ? control.ops->origin(control.context) : q->origin[1];
        struct md_fs_request metadata={.operation=MD_FS_FSTAT,
            .directory={origin ? md_fs_anchor_fd(origin) : q->directory[1],-1},
            .origin={origin,NULL},.mode=MD_FS_STAT_MOUNT};
        struct md_fs_result info={.error=-EXDEV};
        if (control.ops) {
            struct stat st;
            info.error=control.ops->stat(control.context,&st);
            if (!info.error) {
                md_fs_stat_info(&st,&info.info);
                md_fs_anchor_mount_info(origin,&info.info);
            }
        } else md_fs_view_execute(fs,&metadata,&info,NULL);
        if (info.error && info.error!=-EXDEV) result->error=info.error;
        if (!info.error) { f->mount_id=info.info.mount_id; f->inode=info.info.inode; }
        struct statx native;
        if (!result->error && syscall(SYS_statx,q->directory[1],"",AT_EMPTY_PATH,
                STATX_MNT_ID|STATX_INO,&native)) result->error=-errno;
        if (!result->error) {
            f->native_mount=native.stx_mnt_id; f->native_inode=native.stx_ino;
            if (!f->mount_id && native.stx_mnt_id) {
                result->error=md_fs_native_mount(fs,native.stx_mnt_id,&f->mount_id);
                f->inode=native.stx_ino;
            }
        }
        if (!result->error && control.ops) {
            struct stat st;
            result->error=control.ops->stat(control.context,&st);
            if (!result->error) f->inode=st.st_ino;
            if (!result->error && !origin && control.ops->filesystem==PROC_SUPER_MAGIC) {
                struct statx proc;
                if (syscall(SYS_statx,AT_FDCWD,"/proc",0,STATX_MNT_ID,&proc)) result->error=-errno;
                else result->error=md_fs_native_mount(fs,proc.stx_mnt_id,&f->mount_id);
            }
        }
    }
    if (!result->error) {
        f->fd=fcntl(q->directory[0],F_DUPFD_CLOEXEC,0);
        if (f->fd<0) result->error=-errno;
    }
    int fd=-1;
    if (!result->error) {
        if (q->flags&O_PATH) {
            char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",f->fd);
            fd=open(path,O_CLOEXEC|O_PATH);
        } else fd=fcntl(f->fd,F_DUPFD_CLOEXEC,0);
        if (fd<0 || fstat(fd,&f->stat)) result->error=-errno;
    }
    if (!result->error) {
        f->stat.st_uid=fs->actor->identity.uid.effective;
        f->stat.st_gid=fs->actor->identity.gid.effective;
        result->error=md_fs_control_publish(fd,(struct md_control_file){&ops,f},NULL,
            &fs->actor->identity,(int)q->flags,result,output);
        fd=-1;
    }
    release(f);
    if (fd>=0) close(fd);
}
