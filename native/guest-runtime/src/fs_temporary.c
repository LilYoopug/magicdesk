#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

struct options { mode_t mode; uint32_t uid, gid; };
static int number(const char *text, size_t length, unsigned base, uint32_t *value) {
    if (!length) return -EINVAL;
    uint32_t out=0;
    for (size_t i=0;i<length;++i) {
        unsigned digit=(unsigned char)text[i]-'0';
        if (digit>=base || out>(UINT32_MAX-digit)/base) return -EINVAL;
        out=out*base+digit;
    }
    *value=out; return 0;
}
static int parse(const char *text, const struct md_identity *id, struct options *out) {
    *out=(struct options){01777,id->uid.fs,id->gid.fs};
    for (const char *at=text;at && *at;) {
        const char *end=strchr(at,',');
        if (!end) end=at+strlen(at);
        size_t length=(size_t)(end-at);
        int group=-1, mode=0;
        if (length>=5 && !memcmp(at,"mode=",5)) mode=1;
        else if (length>=4 && !memcmp(at,"uid=",4)) group=0;
        else if (length>=4 && !memcmp(at,"gid=",4)) group=1;
        else return -EOPNOTSUPP;
        unsigned prefix=mode ? 5 : 4; uint32_t value;
        int r=number(at+prefix,length-prefix,mode ? 8 : 10,&value);
        if (r) return r;
        if (mode) {
            if (value&~07777U) return -EINVAL;
            out->mode=value;
        } else {
            value=md_user_namespace_into(id->user_namespace,group,value);
            if (value==UINT32_MAX) return -EINVAL;
            if (group) out->gid=value; else out->uid=value;
        }
        at=*end ? end+1 : end;
        if (*end && !*at) return -EINVAL;
    }
    return 0;
}
int md_fs_private_mounts_parent(struct md_inode_store *s) {
    if (mkdirat(s->lifetime->root,"mounts",0700) && errno!=EEXIST) return -errno;
    int fd=openat(s->lifetime->root,"mounts",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -errno;
    struct stat st;
    int r=fstat(fd,&st) ? -errno : st.st_uid!=getuid() || (st.st_mode&0077) ? -EACCES : 0;
    if (r) close(fd);
    return r ? r : fd;
}
int md_fs_mount_temporary(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_mount_source *out) {
    if (q->flags&~(MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC)) return -EOPNOTSUPP;
    const struct md_identity *id=fs->store->identity;
    if (!id) return -EPERM;
    struct options options;
    int r=parse(q->value_size ? q->value : NULL,id,&options);
    if (r) return r;
    int parent=md_fs_private_mounts_parent(fs->store);
    if (parent<0) return parent;
    struct md_inode_store *store=NULL;
    r=md_inode_store_transient(parent,id->user_namespace,&store);
    close(parent);
    int root=-1;
    if (!r) {
        store->lifetime->filesystem_kind=MD_FILESYSTEM_TMPFS;
        root=md_inode_open(store,-1,"/",O_PATH|O_DIRECTORY|O_CLOEXEC,0);
        if (root<0) r=root;
    }
    if (!r) r=md_inode_import_metadata(store,root,options.uid,options.gid,options.mode);
    if (!r) {
        *out=(struct md_mount_source){.fd=root,.backing=MD_MOUNT_INODE,
            .storage=md_inode_lifetime_retain(store->lifetime),.policy=md_fs_mount_flags(q->flags)};
        root=-1;
    }
    if (root>=0) close(root);
    md_inode_store_close(store);
    return r;
}
