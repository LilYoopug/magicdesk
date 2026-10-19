#define _GNU_SOURCE
#include "exec_prepare.h"
#include "fs_engine.h"
#include "fs_continuation.h"
#include "elf_admission.h"
#include "mount_policy.h"
#include "proc_paths.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void execute(struct md_fs_context *context,const struct md_fs_request *q,
        struct md_fs_result *result,struct md_fs_output *output,struct md_fs_continuation **pending) {
    struct md_fs_continuation *previous=*pending;
    output->continuation=pending;
    if (previous) md_fs_context_resume(context,previous,result,output);
    else md_fs_context_execute(context,q,result,output);
    md_fs_continuation_pending(previous,pending,result);
}
static long acquire_at(struct md_fs_context *context, int base, const struct md_fs_anchor *origin,
        const char *path, unsigned flags, const char *object, struct md_program *program,
        struct md_fs_anchor **image_origin,struct md_fs_continuation **pending) {
    memset(program,0,sizeof(*program)); program->fd=-1;
    struct md_fs_request q={.actor=context->actor,.peer=context->peer,
        .operation=object ? MD_FS_OPEN_OBJECT : MD_FS_OPEN_IMAGE,
        .directory={object ? -1 : base,-1},.origin={object ? NULL : origin,NULL},
        .path={object ? object : path,NULL},.flags=object ? O_RDONLY|O_CLOEXEC : flags};
    if (object) q.mode=MD_FS_OBJECT_EXECUTE;
    struct md_fs_result result;
    struct md_fs_anchor *resolved=NULL;
    struct md_fs_output output={.data=&program->identity,.capacity=sizeof(program->identity),.origin=&resolved};
    execute(context,&q,&result,&output,pending);
    program->mount_flags=md_fs_anchor_policy(resolved);
    if (image_origin && !result.error) *image_origin=resolved;
    else md_fs_anchor_release(resolved);
    if (result.error) return result.error;
    if (result.host_path) {
        char native[PATH_MAX];
        int error=md_copy(native,sizeof(native),(char *)&program->identity);
        memset(&program->identity,0,sizeof(program->identity));
        if (error) return error;
        struct md_proc_path proc=md_proc_path(native);
        enum md_proc_kind kind=proc.kind==MD_PROC_FOREIGN ? proc.foreign_kind : proc.kind;
        if (kind==MD_PROC_EXE && !*proc.tail) {
            if (flags&O_NOFOLLOW) return -ELOOP;
            md_copy(program->identity.path,sizeof(program->identity.path),native);
            return -EREMOTE;
        }
        /* Never select the bootstrap or a supervisor FD for a guest magic link. */
        if (kind!=MD_PROC_NONE) return -ENOTSUP;
        /* Native paths remain subject to real permissions; never inspect the
         * worker's own /proc/self when the caller asked for its process. */
        if (md_prefix(native,"/proc/self/") || md_prefix(native,"/proc/thread-self/")) {
            const char *tail=native+(md_prefix(native,"/proc/self/") ? 11 : 18);
            char absolute[PATH_MAX];
            int n=snprintf(absolute,sizeof(absolute),"/proc/%d/%s",context->actor,tail);
            if (n<0 || (size_t)n>=sizeof(absolute)) return -ENAMETOOLONG;
            memcpy(native,absolute,(size_t)n+1);
        }
        int fd=open(native,O_RDONLY|O_CLOEXEC|O_NONBLOCK|flags);
        if (fd<0) return -errno;
        result.fd=fd;
        error=md_copy(program->identity.path,sizeof(program->identity.path),path);
        if (error) { close(fd); return error; }
    }
    if (result.fd<0 || result.open_completion.kind) {
        if (result.fd>=0) close(result.fd);
        return -EPROTO;
    }
    program->fd=result.fd;
    if (object) {
        memcpy(program->identity.object,object,sizeof(program->identity.object));
        md_copy(program->identity.path,sizeof(program->identity.path),path);
    }
    return 0;
}
static int acquire_fd(struct md_fs_context *context,int fd,const struct md_fs_anchor *origin,
        const char *path,struct md_program *program,struct md_fs_anchor **image_origin,
        struct md_fs_continuation **pending) {
    *program=(struct md_program){.fd=-1};
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (S_ISLNK(st.st_mode)) return -ELOOP;
    if (!S_ISREG(st.st_mode)) return -EACCES;
    struct md_fs_request q={.actor=context->actor,.peer=context->peer,.operation=MD_FS_REOPEN,
        .directory={fd,-1},.origin={origin,NULL},.flags=O_RDONLY|O_CLOEXEC,
        .mode=MD_FS_REOPEN_EXECUTE};
    struct md_fs_result result;
    struct md_fs_output output={.origin=image_origin};
    execute(context,&q,&result,&output,pending);
    int error=result.error;
    if (error==-EXDEV && !origin) {
        /* Only anonymous kernel images may bypass the managed filesystem.
         * Ordinary unlinked files still retain logical permissions and origin. */
        if (!st.st_nlink && fcntl(fd,F_GET_SEALS)>=0) {
            result.fd=fcntl(fd,F_DUPFD_CLOEXEC,0);
            error=result.fd<0 ? -errno : 0;
        }
    }
    if (!error && (result.fd<0 || result.host_path || result.open_completion.kind)) error=-EPROTO;
    if (!error) error=md_copy(program->identity.path,sizeof(program->identity.path),path);
    if (!error && !*image_origin) {
        char link[64]; snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
        ssize_t n=readlink(link,program->identity.path,sizeof(program->identity.path)-1);
        if (n<0) error=-errno;
        else program->identity.path[n]=0;
    }
    if (error) {
        if (result.fd>=0) close(result.fd);
        md_fs_anchor_release(*image_origin); *image_origin=NULL;
        return error;
    }
    program->fd=result.fd;
    program->mount_flags=md_fs_anchor_policy(*image_origin);
    return 0;
}
struct md_exec_preparation {
    struct md_fs_continuation *pending;
    struct md_fs_anchor *origin;
    struct md_command_recipe recipe;
    struct md_command_images images;
    struct md_exec_image *setid;
    struct md_fs_info attributes;
    enum md_command_file kind;
    int first, prepared;
    char path[MD_INTERPRETER_MAX];
};
static void preparation_clear(struct md_exec_preparation *p) {
    if (p->pending) p->pending->destroy(p->pending);
    md_fs_anchor_release(p->origin);
    md_command_images_close(&p->images);
    md_exec_image_release(p->setid);
}
static int prepare_identity(struct md_exec_preparation *p, struct md_fs_context *context, unsigned mode) {
    /* Only the provider can authorize stored identity. Anonymous/host-only
     * images and suppressed set-ID execs retain their ordinary loading path. */
    if (!p->origin || context->task.identity.no_new_privs
            || (mode&MD_EXEC_TRACED) || (p->images.mount_flags&MD_MOUNT_NOSUID)) return 0;
    /* Providers may materialize a separate loader image. Stored authority
     * belongs to the retained source object, never that image's backing FD. */
    struct md_fs_request q={.actor=context->actor,.peer=context->peer,.operation=MD_FS_FSTAT,
        .directory={md_fs_anchor_fd(p->origin),-1},.origin={p->origin,NULL}};
    struct md_fs_result result;
    struct md_fs_output output={0};
    execute(context,&q,&result,&output,&p->pending);
    if (result.error) return result.error;
    if (result.host_path) return 0;
    const struct md_fs_info *info=&result.info;
    if (p->setid) {
        const struct md_fs_info *before=&p->attributes;
        if (info->uid!=before->uid || info->gid!=before->gid || info->mode!=before->mode
                || info->size!=before->size || info->change_seconds!=before->change_seconds
                || info->change_nanos!=before->change_nanos) return -ESTALE;
    } else {
        if (!(info->mode&S_ISUID) && (info->mode&(S_ISGID|S_IXGRP))!=(S_ISGID|S_IXGRP)) return 0;
        int error=md_exec_image_snapshot(p->images.program,info->uid,info->gid,info->mode,&p->setid);
        if (error) return error;
        p->attributes=*info;
        /* Recheck logical metadata around the content snapshot as well as the
         * physical checks inside it. A concurrent chmod/chown cannot lend stale authority. */
        return prepare_identity(p,context,mode);
    }
    int fd=md_exec_image_dup(p->setid);
    if (fd<0) return fd;
    close(p->images.program); p->images.program=fd;
    return 0;
}
void md_exec_preparation_destroy(struct md_exec_preparation *p) {
    if (p) { preparation_clear(p); free(p); }
}
int md_exec_preparation_ready(struct md_exec_preparation *p) {
    return p && p->pending ? p->pending->ready(p->pending) : -EINVAL;
}
static long acquire(struct md_exec_preparation *p,struct md_fs_context *context,
        struct md_program *program,struct md_fs_anchor **image_origin,unsigned mode) {
    const char *path=p->path;
    const struct md_fs_anchor *cwd=context->task.cwd;
    if (*path!='/' && !cwd) return -ENODATA;
    if (p->kind==MD_COMMAND_INTERPRETER) {
        struct md_fs_request q={.actor=context->actor,.peer=context->peer,.operation=MD_FS_OPEN_IMAGE,
            .directory={-1,-1},.path={path,NULL},
            .mode=mode&MD_EXEC_TRACED ? 0 : MD_FS_IMAGE_INTERPRETER};
        struct md_fs_anchor *origin=NULL;
        struct md_fs_output output={.data=&program->identity,.capacity=sizeof(program->identity),.origin=&origin};
        struct md_fs_result result;
        *program=(struct md_program){.fd=-1};
        execute(context,&q,&result,&output,&p->pending);
        program->mount_flags=md_fs_anchor_policy(origin);
        md_fs_anchor_release(origin);
        if (result.error || result.host_path || result.open_completion.kind || result.fd<0) {
            if (result.fd>=0) close(result.fd);
            return result.error ? result.error : -EOPNOTSUPP;
        }
        program->fd=result.fd; return 0;
    }
    return acquire_at(context,*path=='/' ? -1 : md_fs_anchor_fd(cwd),
        *path=='/' ? NULL : cwd,path,0,NULL,program,image_origin,&p->pending);
}
static int acquire_first(struct md_exec_preparation *p,struct md_fs_context *context,
        const struct md_fs_request *q,struct md_program **proc_image,struct md_program *first,
        struct md_fs_anchor **origin) {
    int error;
    if (*proc_image) {
        if ((*proc_image)->fd>=0) {
            error=acquire_fd(context,(*proc_image)->fd,(*proc_image)->origin,
                (*proc_image)->identity.path,first,origin,&p->pending);
        }
        else if ((*proc_image)->identity.object[0]) {
            error=(int)acquire_at(context,-1,NULL,(*proc_image)->identity.path,0,
                (*proc_image)->identity.object,first,origin,&p->pending);
        } else error=-EPROTO;
    } else if (!*q->path[0]) {
        char path[64]; snprintf(path,sizeof(path),"/dev/fd/%lld",(long long)q->offset);
        error=acquire_fd(context,q->directory[0],q->origin[0],path,first,origin,&p->pending);
    } else {
        error=(int)acquire_at(context,q->directory[0],q->origin[0],q->path[0],q->flags,
            q->mode&MD_EXEC_OBJECT ? q->path[1] : NULL,first,origin,&p->pending);
        if (error==-EREMOTE) {
            *proc_image=malloc(sizeof(**proc_image));
            if (!*proc_image) return -ENOMEM;
            **proc_image=*first; first->fd=-1;
            return error;
        }
    }
    return error;
}
int md_fs_command_prepare(struct md_fs_context *context, const struct md_fs_request *q,
        struct md_program **proc_image,struct md_command_recipe *recipe,struct md_command_images *images,
        struct md_fs_anchor **image_origin,struct md_exec_image **setid,struct md_exec_preparation **owner) {
    struct md_exec_preparation local={.first=1,.images={.program=-1,.loader=-1}};
    struct md_exec_preparation *p=*owner ? *owner : &local;
    int error=0;
    while (!p->prepared) {
        struct md_program current={.fd=-1};
        struct md_fs_anchor *origin=NULL;
        error=p->first ? acquire_first(p,context,q,proc_image,&current,&origin)
            : (int)acquire(p,context,&current,&origin,q->mode);
        if (!error) {
            if (p->kind==MD_COMMAND_EXECUTABLE) {
                md_fs_anchor_release(p->origin); p->origin=origin; origin=NULL;
            }
            p->first=0;
            error=md_command_images_step(&p->recipe,&p->images,&current,p->kind,
                q->mode&MD_EXEC_INACCESSIBLE,p->path);
        }
        md_fs_anchor_release(origin);
        if (current.fd>=0) close(current.fd);
        if (error<=0) { p->prepared=!error; break; }
        p->kind=(enum md_command_file)(error-1);
    }
    if (!error) error=prepare_identity(p,context,q->mode);
    if (error==-EINPROGRESS) {
        if (p==&local) {
            *owner=malloc(sizeof(**owner));
            if (*owner) **owner=local;
            else { preparation_clear(&local); return -ENOMEM; }
        }
        return error;
    }
    if (!error) {
        *recipe=p->recipe; *images=p->images;
        p->images=(struct md_command_images){.program=-1,.loader=-1};
        *image_origin=p->origin; p->origin=NULL;
        *setid=p->setid; p->setid=NULL;
    }
    if (p==&local) preparation_clear(p); else md_exec_preparation_destroy(p);
    *owner=NULL;
    return error;
}
