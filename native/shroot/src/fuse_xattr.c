#define _GNU_SOURCE
#include "fuse_xattr.h"
#include "fs_engine.h"
#include "file_permissions.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

int md_fuse_xattr_request(struct md_fuse_session *session,const struct md_identity *id,uint32_t pid,
        uint64_t node,const struct stat *st,const struct md_fs_request *q,struct md_resource_wakeup *wake,
        struct md_fuse_request **out) {
    int list=q->mode==MD_FS_XATTR_LIST,set=q->mode==MD_FS_XATTR_SET,remove=q->mode==MD_FS_XATTR_REMOVE;
    int write=set || remove;
    const char *name=list ? "" : q->path[1];
    if (!name || (!list && !*name) || strlen(name)>255 || q->capacity>MD_FS_VALUE_MAX
            || q->value_size>MD_FS_VALUE_MAX || (set && q->flags&~(XATTR_CREATE|XATTR_REPLACE))) return -EINVAL;
    if (!list && !strncmp(name,"trusted.",8) && !md_identity_capable_in(id,NULL,CAP_SYS_ADMIN))
        return write ? -EPERM : -ENODATA;
    if (!list && !strncmp(name,"user.",5)) {
        if (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode)) return write ? -EPERM : -ENODATA;
        if (write && S_ISDIR(st->st_mode) && (st->st_mode&S_ISVTX) && md_file_noatime(st,id)) return -EPERM;
    }
    if (!list && strncmp(name,"security.",9) && strncmp(name,"system.",7)
            && md_fuse_session_options(session)->default_permissions) {
        int error=md_file_permissions(st,write ? W_OK : R_OK,id);
        if (error) return error;
    }
    size_t namesize=list ? 0 : strlen(name)+1;
    /* SETXATTR_EXT was not negotiated: its legacy header has only two u32s. */
    size_t header=remove ? 0 : 8, size=header+namesize+(set ? q->value_size : 0);
    unsigned char *bytes=malloc(size ? size : 1);
    if (!bytes) return -ENOMEM;
    uint32_t words[]={set ? q->value_size : q->capacity,set ? q->flags : 0};
    if (header) memcpy(bytes,words,header);
    if (namesize) memcpy(bytes+header,name,namesize);
    if (set && q->value_size) memcpy(bytes+header+namesize,q->value,q->value_size);
    unsigned opcode=set ? FUSE_SETXATTR : remove ? FUSE_REMOVEXATTR : list ? FUSE_LISTXATTR : FUSE_GETXATTR;
    size_t capacity=write ? 0 : q->capacity ? q->capacity : sizeof(struct fuse_getxattr_out);
    int error=md_fuse_session_request(session,id,pid,opcode,node,bytes,size,capacity,0,wake,out);
    free(bytes); return error;
}
void md_fuse_xattr_result(struct md_fuse_request *request,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    int write=q->mode==MD_FS_XATTR_SET || q->mode==MD_FS_XATTR_REMOVE;
    struct fuse_getxattr_out size={0};
    void *data=write ? NULL : !q->capacity ? &size : output ? output->data : NULL;
    size_t capacity=write ? 0 : !q->capacity ? sizeof(size) : output ? output->capacity : 0;
    if (!write && q->capacity && (!data || capacity<q->capacity)) { out->error=-ERANGE; return; }
    long n=md_fuse_request_result(request,data,capacity);
    if (n<0) { out->error=n==-ENOSYS ? -EOPNOTSUPP : n; return; }
    if (write) { if (n) out->error=-EPROTO; return; }
    if (!q->capacity) {
        if (n!=sizeof(size)) out->error=-EPROTO;
        else if (size.size>MD_FS_VALUE_MAX) out->error=-E2BIG;
        else out->position=size.size;
        return;
    }
    if ((size_t)n>q->capacity) { out->error=-EPROTO; return; }
    if (q->mode==MD_FS_XATTR_LIST) for (size_t at=0;at<(size_t)n;) {
        size_t length=strnlen((char *)data+at,(size_t)n-at);
        if (!length || length>255 || length==(size_t)n-at) { out->error=-EPROTO; return; }
        at+=length+1;
    }
    out->position=out->size=n;
}
