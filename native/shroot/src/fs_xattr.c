#define _GNU_SOURCE
#include "fs_engine.h"
#include "fs_continuation.h"
#include "posix_acl.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
    /* The selected inode engine owns the complete operation. Native attachments
     * return EXDEV only after checking their mount's readonly policy. */
    local=*q; local.operation=MD_FS_XATTR_OBJECT;
    local.directory[0]=fd; local.origin[0]=origin;
    local.path[0]=NULL; local.flags&=3U;
    md_fs_view_execute(fs,&local,out,output);
    if (out->error!=-EXDEV) return;
    *out=(struct md_fs_result){.fd=-1};
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    void *data=output ? output->data : NULL;
    size_t capacity=output ? output->capacity : 0;
    ssize_t result;
    if (list) {
        if (q->capacity && (!data || capacity<q->capacity)) out->error=-ERANGE;
        else {
            result=listxattr(path,q->capacity ? data : NULL,q->capacity);
            if (result<0) out->error=-errno;
            else if (result>MD_FS_VALUE_MAX) out->error=-E2BIG;
            else { out->position=result; out->size=q->capacity ? result : 0; }
        }
    } else if (set) out->error=setxattr(path,name,q->value,q->value_size,q->flags&3U) ? -errno : 0;
    else if (remove) out->error=removexattr(path,name) ? -errno : 0;
    else if (q->capacity && (!data || capacity<q->capacity)) out->error=-ERANGE;
    else {
        result=getxattr(path,name,q->capacity ? data : NULL,q->capacity);
        if (result<0) out->error=-errno;
        else { out->position=result; out->size=q->capacity ? result : 0; }
    }
}
static void opened(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_fs_result *open,struct md_fs_anchor **origin,struct md_fs_result *out,
        const struct md_fs_output *output) {
    *out=*open; out->fd=-1;
    if (out->error) return;
    int fd=open->fd>=0 ? open->fd : md_fs_anchor_fd(*origin);
    selected(fs,q,fd,*origin,out,output);
}
static struct md_fs_request open_request(const struct md_fs_request *q) {
    return (struct md_fs_request){.operation=MD_FS_OPEN,.directory={q->directory[0],-1},
        .origin={q->origin[0],NULL},.path={q->path[0],NULL},
        .flags=O_PATH|O_CLOEXEC|((q->flags&AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0)};
}
static void planned(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_fs_result *open,struct md_fs_anchor **origin,struct md_fs_result *out,
        const struct md_fs_output *output) {
    if (open->error!=-EXDEV) { opened(fs,q,open,origin,out,output); return; }
    /* A declined native plan has no effect. Resolve the same operand through
     * its provider, preserving a possible asynchronous path walk. */
    struct md_fs_request request=open_request(q);
    struct md_fs_output capture=output ? *output : (struct md_fs_output){0};
    capture.native_open_plan=0;
    md_fs_view_then(fs,q,&request,out,&capture,opened);
}
static void execute(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    *out=(struct md_fs_result){.fd=-1};
    int descriptor=q->operation==MD_FS_FXATTR, path=q->path[0] && *q->path[0];
    int fd=q->directory[0];
    const struct md_fs_anchor *origin=q->origin[0];
    if (descriptor) {
        int flags=fcntl(fd,F_GETFL);
        if (flags<0 || (flags&O_PATH)) { out->error=flags<0 ? -errno : -EBADF; return; }
    } else if (path) {
        struct md_fs_request open=open_request(q);
        struct md_fs_output capture=output ? *output : (struct md_fs_output){0};
        capture.native_open_plan=!!fs->mounts;
        md_fs_view_then(fs,q,&open,out,&capture,planned); return;
    }
    selected(fs,q,fd,origin,out,output);
}
static void mapped_result(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_fs_result *result,struct md_fs_anchor **origin,struct md_fs_result *out,
        const struct md_fs_output *output) {
    (void)origin;
    *out=*result; result->fd=-1;
    const struct md_identity *id=fs->store->identity;
    const char *name=q->path[1] ? q->path[1] : "";
    if (!out->error && id && id->user_namespace && q->mode==MD_FS_XATTR_GET && out->size
            && (!strcmp(name,MD_ACL_ACCESS_NAME) || !strcmp(name,MD_ACL_DEFAULT_NAME))) {
        if (!output || !md_acl_valid(output->data,out->size)) out->error=-EIO;
        else out->error=md_acl_map(output->data,out->size,id,0);
        if (out->error) out->size=out->position=0;
    }
}
void md_fs_xattr(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    const struct md_identity *id=fs->store->identity;
    const char *name=q->path[1] ? q->path[1] : "";
    int mapped_acl=id && id->user_namespace
        && (!strcmp(name,MD_ACL_ACCESS_NAME) || !strcmp(name,MD_ACL_DEFAULT_NAME));
    struct md_acl *value=NULL;
    struct md_fs_request local;
    if (mapped_acl && q->mode==MD_FS_XATTR_SET && q->value_size) {
        *out=(struct md_fs_result){.fd=-1};
        if (!md_acl_valid(q->value,q->value_size)) {
            uint32_t version=0;
            if (q->value && q->value_size>=4) memcpy(&version,q->value,4);
            out->error=q->value_size>=4 && version!=2 ? -EOPNOTSUPP : -EINVAL; return;
        }
        value=malloc(q->value_size);
        if (!value) { out->error=-ENOMEM; return; }
        memcpy(value,q->value,q->value_size);
        out->error=md_acl_map(value,q->value_size,id,1);
        if (out->error) { free(value); return; }
        local=*q; local.value=value; q=&local;
    }
    md_fs_then(fs,q,q,execute,out,output,mapped_result);
    free(value);
}
