#define _GNU_SOURCE
#include "exec_prepare.h"
#include "fs_engine.h"
#include "proc_paths.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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
        /* Current-image and same-table magic links are captured before worker
         * admission. An unresolved magic link must not select the bootstrap
         * or a supervisor descriptor instead of the guest's object. */
        if (md_proc_path(native).kind!=MD_PROC_NONE) return -ENOTSUP;
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
        struct md_command_recipe *recipe, struct md_command_images *images) {
    *images=(struct md_command_images){.program=-1,.loader=-1};
    struct md_program first={.fd=-1};
    int error;
    if (!*q->path[0]) {
        first.fd=q->directory[0];
        first.mount_flags=md_fs_anchor_policy(q->origin[0]);
        snprintf(first.identity.path,sizeof(first.identity.path),"/dev/fd/%lld",(long long)q->offset);
        struct md_fs_request object={.actor=context->actor,.peer=context->peer,
            .operation=MD_FS_OBJECT_ID,.directory={first.fd,-1},.origin={q->origin[0],NULL}};
        struct md_fs_result result;
        struct md_fs_output out={.data=first.identity.object,.capacity=sizeof(first.identity.object)};
        md_fs_context_execute(context,&object,&result,&out);
        error=result.error;
    } else error=(int)acquire_at(context,q->directory[0],q->origin[0],q->path[0],q->flags,
        q->mode&MD_EXEC_OBJECT ? q->path[1] : NULL,&first);
    if (!error) error=md_command_images_prepare(recipe,images,&first,
        q->mode&MD_EXEC_INACCESSIBLE,acquire,context);
    if (*q->path[0] && first.fd>=0) close(first.fd);
    return error;
}
