#define _GNU_SOURCE
#include "fs_engine.h"
#include "posix_acl.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

static void selected(struct md_filesystem *fs, const struct md_fs_request *q,
        int fd, const struct md_fs_anchor *origin, struct md_fs_result *out,
        const struct md_fs_output *output) {
    int list=q->mode==MD_FS_XATTR_LIST, set=q->mode==MD_FS_XATTR_SET;
    int remove=q->mode==MD_FS_XATTR_REMOVE;
    const char *name=q->path[1] ? q->path[1] : "";
    unsigned acl=!strcmp(name,MD_ACL_ACCESS_NAME) ? MD_ACL_ACCESS
        : !strcmp(name,MD_ACL_DEFAULT_NAME) ? MD_ACL_DEFAULT : 0;
    struct md_fs_request local={.directory={fd,-1},.origin={origin,NULL}};
    if (acl) {
        local.operation=set ? MD_FS_SETACL : remove ? MD_FS_REMOVEACL : MD_FS_GETACL;
        local.mode=acl; local.flags=q->flags&3U; local.capacity=q->capacity;
        local.value=q->value; local.value_size=q->value_size;
        if (set && ((q->capacity && q->capacity<4) || q->capacity>MD_ACL_MAX)) {
            out->error=-EINVAL; return;
        }
        md_fs_view_execute(fs,&local,out,output);
        if (out->error!=-EXDEV) return;
    } else if (!strcmp(name,MD_FILE_CAPABILITY_NAME)) {
        local.operation=set ? MD_FS_SETCAP : remove ? MD_FS_REMOVECAP : MD_FS_GETCAP;
        if (set) {
            if (q->value_size>sizeof(local.attributes.capability)) { out->error=-EINVAL; return; }
            local.flags=q->flags&3U; local.capacity=q->value_size;
            if (q->value_size) memcpy(local.attributes.capability,q->value,q->value_size);
        }
        md_fs_view_execute(fs,&local,out,output);
        if (out->error!=-EXDEV) {
            if (!out->error && !set && !remove) {
                out->position=out->size;
                if (!q->capacity) out->size=0;
                else if (q->capacity<out->size) { out->error=-ERANGE; out->size=out->position=0; }
            }
            return;
        }
    }
    /* Logical permission checks and copy-up select the current backing. Native
     * attachments return EXDEV only after checking their readonly policy. */
    local=(struct md_fs_request){.operation=MD_FS_XATTR_OPEN,.directory={fd,-1},
        .origin={origin,NULL},.path={name,NULL},.mode=list ? F_OK : set || remove ? W_OK : R_OK};
    md_fs_view_execute(fs,&local,out,NULL);
    int backing=out->fd;
    if (out->error && out->error!=-EXDEV) return;
    *out=(struct md_fs_result){.fd=-1};
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",backing>=0 ? backing : fd);
    void *data=output ? output->data : NULL;
    size_t capacity=output ? output->capacity : 0;
    ssize_t result;
    if (list) {
        char names[128];
        struct md_fs_output extra={.data=names,.capacity=sizeof(names)};
        local=(struct md_fs_request){.operation=MD_FS_LISTATTR,.directory={fd,-1},.origin={origin,NULL}};
        struct md_fs_result attributes;
        md_fs_view_execute(fs,&local,&attributes,&extra);
        if (attributes.error==-EXDEV || attributes.error==-ENODATA) attributes.size=0;
        else if (attributes.error) { out->error=attributes.error; goto done; }
        result=listxattr(path,NULL,0);
        if (result<0) out->error=-errno;
        else if ((size_t)result>MD_FS_VALUE_MAX-attributes.size) out->error=-E2BIG;
        else if (!q->capacity) out->position=result+attributes.size;
        else if ((size_t)result+attributes.size>q->capacity || capacity<q->capacity) out->error=-ERANGE;
        else {
            result=listxattr(path,data,q->capacity-attributes.size);
            if (result<0) out->error=-errno;
            else if ((size_t)result>q->capacity-attributes.size) out->error=-ERANGE;
            else {
                memcpy((char *)data+result,names,attributes.size);
                out->size=out->position=result+attributes.size;
            }
        }
    } else if (set) out->error=setxattr(path,name,q->value,q->value_size,q->flags&3U) ? -errno : 0;
    else if (remove) out->error=removexattr(path,name) ? -errno : 0;
    else if (q->capacity && (!data || capacity<q->capacity)) out->error=-ERANGE;
    else {
        result=getxattr(path,name,q->capacity ? data : NULL,q->capacity);
        if (result<0) out->error=-errno;
        else { out->position=result; out->size=q->capacity ? result : 0; }
    }
done:
    if (backing>=0) close(backing);
}
void md_fs_xattr(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    *out=(struct md_fs_result){.fd=-1};
    int descriptor=q->operation==MD_FS_FXATTR, path=q->path[0] && *q->path[0];
    int fd=q->directory[0];
    struct md_fs_anchor *opened=NULL;
    const struct md_fs_anchor *origin=q->origin[0];
    if (descriptor) {
        int flags=fcntl(fd,F_GETFL);
        if (flags<0 || (flags&O_PATH)) { out->error=flags<0 ? -errno : -EBADF; return; }
    } else if (path) {
        struct md_fs_request open={.operation=MD_FS_OPEN,.directory={fd,-1},.origin={origin,NULL},
            .path={q->path[0],NULL},.flags=O_PATH|O_CLOEXEC|((q->flags&AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0)};
        struct md_fs_output capture=output ? *output : (struct md_fs_output){0};
        capture.origin=fs->mounts ? &opened : NULL;
        md_fs_view_execute(fs,&open,out,&capture);
        if (out->error) return;
        fd=out->fd; out->fd=-1; origin=opened;
    }
    selected(fs,q,fd,origin,out,output);
    if (path) close(fd);
    md_fs_anchor_release(opened);
}
