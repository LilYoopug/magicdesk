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
        const char *path, unsigned flags, const char *object, struct md_program *program) {
    memset(program,0,sizeof(*program)); program->fd=-1;
    struct md_fs_request q={.actor=context->actor,.peer=context->peer,
        .operation=object ? MD_FS_OPEN_OBJECT : MD_FS_OPEN_IMAGE,
        .directory={object ? -1 : base,-1},.origin={object ? NULL : origin,NULL},
        .path={object ? object : path,NULL},.flags=object ? O_RDONLY|O_CLOEXEC : flags};
    struct md_fs_result result;
    struct md_fs_anchor *resolved=NULL;
    struct md_fs_output output={.data=&program->identity,.capacity=sizeof(program->identity),.origin=&resolved};
    md_fs_context_execute(context,&q,&result,&output);
    program->mount_flags=md_fs_anchor_policy(resolved);
    md_fs_anchor_release(resolved);
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
static long acquire(void *owner, const char *path, struct md_program *program) {
    struct md_fs_context *context=owner;
    const struct md_fs_anchor *cwd=context->task.cwd;
    if (*path=='/') return acquire_at(context,-1,NULL,path,0,NULL,program);
    if (!cwd) return -ENODATA;
    return acquire_at(context,md_fs_anchor_fd(cwd),cwd,path,0,NULL,program);
}
int md_fs_command_prepare(struct md_fs_context *context, const struct md_fs_request *q,
        struct md_program **proc_image, struct md_command_recipe *recipe, struct md_command_images *images) {
    *images=(struct md_command_images){.program=-1,.loader=-1};
    struct md_program first={.fd=-1};
    int error;
    int owned=0;
    if (*proc_image) {
        if ((*proc_image)->fd>=0) { first=**proc_image; error=0; }
        else if ((*proc_image)->identity.object[0]) {
            error=(int)acquire_at(context,-1,NULL,(*proc_image)->identity.path,0,
                (*proc_image)->identity.object,&first);
            owned=1;
        } else error=-EPROTO;
    } else if (!*q->path[0]) {
        first.fd=q->directory[0];
        first.mount_flags=md_fs_anchor_policy(q->origin[0]);
        snprintf(first.identity.path,sizeof(first.identity.path),"/dev/fd/%lld",(long long)q->offset);
        struct md_fs_request object={.actor=context->actor,.peer=context->peer,
            .operation=MD_FS_OBJECT_ID,.directory={first.fd,-1},.origin={q->origin[0],NULL}};
        struct md_fs_result result;
        struct md_fs_output out={.data=first.identity.object,.capacity=sizeof(first.identity.object)};
        md_fs_context_execute(context,&object,&result,&out);
        error=result.error;
        if (error==-EXDEV && !q->origin[0]) {
            struct stat st;
            /* An anonymous kernel image has no inode-store key. Retain the
             * actual description; normal ELF, execute and noexec checks still
             * apply. Never reinterpret a failed managed-object lookup. */
            if (!fstat(first.fd,&st) && S_ISREG(st.st_mode) && !st.st_nlink
                    && fcntl(first.fd,F_GET_SEALS)>=0) {
                char link[64];
                snprintf(link,sizeof(link),"/proc/self/fd/%d",first.fd);
                ssize_t n=readlink(link,first.identity.path,sizeof(first.identity.path)-1);
                if (n<0) error=-errno;
                else { first.identity.path[n]=0; error=0; }
            }
        }
    } else {
        error=(int)acquire_at(context,q->directory[0],q->origin[0],q->path[0],q->flags,
            q->mode&MD_EXEC_OBJECT ? q->path[1] : NULL,&first);
        owned=1;
        if (error==-EREMOTE) {
            *proc_image=malloc(sizeof(**proc_image));
            if (!*proc_image) return -ENOMEM;
            **proc_image=first;
            return error;
        }
    }
    if (!error) error=md_command_images_prepare(recipe,images,&first,
        q->mode&MD_EXEC_INACCESSIBLE,acquire,context);
    if (owned && first.fd>=0) close(first.fd);
    return error;
}
