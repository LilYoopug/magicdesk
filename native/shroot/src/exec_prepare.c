#define _GNU_SOURCE
#include "exec_prepare.h"
#include "fs_engine.h"
#include "proc_paths.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static long acquire_at(struct md_fs_context *context, int base, const struct md_fs_anchor *origin,
        const char *path, unsigned flags, const char *object, struct md_program *program,
        struct md_fs_anchor **image_origin) {
    memset(program,0,sizeof(*program)); program->fd=-1;
    struct md_fs_request q={.actor=context->actor,.peer=context->peer,
        .operation=object ? MD_FS_OPEN_OBJECT : MD_FS_OPEN_IMAGE,
        .directory={object ? -1 : base,-1},.origin={object ? NULL : origin,NULL},
        .path={object ? object : path,NULL},.flags=object ? O_RDONLY|O_CLOEXEC : flags};
    if (object) q.mode=MD_FS_OBJECT_EXECUTE;
    struct md_fs_result result;
    struct md_fs_anchor *resolved=NULL;
    struct md_fs_output output={.data=&program->identity,.capacity=sizeof(program->identity),.origin=&resolved};
    md_fs_context_execute(context,&q,&result,&output);
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
        const char *path,struct md_program *program,struct md_fs_anchor **image_origin) {
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
    md_fs_context_execute(context,&q,&result,&output);
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
struct image_selection {
    struct md_fs_context *context;
    struct { struct md_fs_anchor *origin; char object[33]; } entries[MD_SCRIPT_DEPTH+2];
    unsigned count;
};
static long acquire(void *owner, const char *path, struct md_program *program, enum md_command_file kind) {
    struct image_selection *selection=owner;
    struct md_fs_context *context=selection->context;
    const struct md_fs_anchor *cwd=context->task.cwd;
    if (*path!='/' && !cwd) return -ENODATA;
    if (kind==MD_COMMAND_INTERPRETER) {
        struct md_fs_request q={.actor=context->actor,.peer=context->peer,.operation=MD_FS_OPEN_IMAGE,
            .directory={-1,-1},.path={path,NULL},.mode=MD_FS_IMAGE_INTERPRETER};
        struct md_fs_anchor *origin=NULL;
        struct md_fs_output output={.data=&program->identity,.capacity=sizeof(program->identity),.origin=&origin};
        struct md_fs_result result;
        *program=(struct md_program){.fd=-1};
        md_fs_context_execute(context,&q,&result,&output);
        program->mount_flags=md_fs_anchor_policy(origin);
        md_fs_anchor_release(origin);
        if (result.error || result.host_path || result.open_completion.kind || result.fd<0) {
            if (result.fd>=0) close(result.fd);
            return result.error ? result.error : -EOPNOTSUPP;
        }
        program->fd=result.fd; return 0;
    }
    if (selection->count==MD_SCRIPT_DEPTH+2) return -ELOOP;
    unsigned index=selection->count++;
    long result=acquire_at(context,*path=='/' ? -1 : md_fs_anchor_fd(cwd),
        *path=='/' ? NULL : cwd,path,0,NULL,program,&selection->entries[index].origin);
    memcpy(selection->entries[index].object,program->identity.object,33);
    return result;
}
int md_fs_command_prepare(struct md_fs_context *context, const struct md_fs_request *q,
        struct md_program **proc_image, struct md_command_recipe *recipe, struct md_command_images *images,
        struct md_fs_anchor **image_origin) {
    *images=(struct md_command_images){.program=-1,.loader=-1};
    *image_origin=NULL;
    struct image_selection selection={.context=context,.count=1};
    struct md_program first={.fd=-1};
    int error;
    int owned=0;
    if (*proc_image) {
        if ((*proc_image)->fd>=0) {
            error=acquire_fd(context,(*proc_image)->fd,(*proc_image)->origin,
                (*proc_image)->identity.path,&first,&selection.entries[0].origin);
            owned=1;
        }
        else if ((*proc_image)->identity.object[0]) {
            error=(int)acquire_at(context,-1,NULL,(*proc_image)->identity.path,0,
                (*proc_image)->identity.object,&first,&selection.entries[0].origin);
            owned=1;
        } else error=-EPROTO;
    } else if (!*q->path[0]) {
        char path[64]; snprintf(path,sizeof(path),"/dev/fd/%lld",(long long)q->offset);
        error=acquire_fd(context,q->directory[0],q->origin[0],path,&first,&selection.entries[0].origin);
        owned=1;
    } else {
        error=(int)acquire_at(context,q->directory[0],q->origin[0],q->path[0],q->flags,
            q->mode&MD_EXEC_OBJECT ? q->path[1] : NULL,&first,&selection.entries[0].origin);
        owned=1;
        if (error==-EREMOTE) {
            md_fs_anchor_release(selection.entries[0].origin);
            *proc_image=malloc(sizeof(**proc_image));
            if (!*proc_image) return -ENOMEM;
            **proc_image=first;
            return error;
        }
    }
    memcpy(selection.entries[0].object,first.identity.object,33);
    if (!error) error=md_command_images_prepare(recipe,images,&first,
        q->mode&MD_EXEC_INACCESSIBLE,acquire,&selection);
    /* FD images need no catalogue key: their origin pins the exact inode and
     * mount across CLOEXEC/unlink. Keep the image, not shebang intermediates. */
    for (unsigned i=0;i<selection.count;++i) {
        if (!error && !*image_origin
                && !strcmp(selection.entries[i].object,recipe->image.object)) {
            *image_origin=selection.entries[i].origin;
            selection.entries[i].origin=NULL;
        }
        md_fs_anchor_release(selection.entries[i].origin);
    }
    if (owned && first.fd>=0) close(first.fd);
    return error;
}
