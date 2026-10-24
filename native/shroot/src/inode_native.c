#define _GNU_SOURCE
#include "inode_native.h"
#include "posix_acl.h"
#include "file_capability.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

enum { METADATA_MAGIC=0x32464c53, METADATA_MODE=01700 };
struct metadata { uint32_t magic,uid,gid,mode,acl,cap; unsigned char data[]; };
_Static_assert(sizeof(struct metadata)==24,"native leaf metadata layout");
int mdi_native_private_attribute(const char *name) { return !strncmp(name,"user.shroot.",12); }
int mdi_native_eligible(uint32_t uid,uint32_t gid,mode_t mode) {
    return !uid && !gid && !(mode&~0777) && (mode&0600)==0600;
}
static int valid_name(const char *name) {
    return name && *name && strcmp(name,".") && strcmp(name,"..") && !strchr(name,'/');
}
int mdi_native_pin_create(int directory,const char *name,uint32_t uid,uint32_t gid,mode_t mode) {
    if (!mdi_native_eligible(uid,gid,mode)) return -EOPNOTSUPP;
    if (!valid_name(name)) return -EINVAL;
    if (mknodat(directory,name,S_IFREG|mode,0)) {
        int error=errno;
        return error==EPERM || error==EACCES || error==ENOSYS || error==EOPNOTSUPP
            ? -EOPNOTSUPP : -error;
    }
    int pin=openat(directory,name,O_PATH|O_CLOEXEC|O_NOFOLLOW);
    if (pin>=0) return pin;
    int error=errno;
    if (unlinkat(directory,name,0)) return -errno;
    return -error;
}
int mdi_native_create_in(int directory,const char *parent,const char *name,int flags,uint32_t uid,uint32_t gid,mode_t mode) {
    if (!mdi_native_eligible(uid,gid,mode)) return -EOPNOTSUPP;
    if (!valid_name(name)) return -EINVAL;
    if (flags&~(O_ACCMODE|O_CLOEXEC|O_NONBLOCK|O_APPEND|O_SYNC|O_DSYNC|O_DIRECT|O_NOATIME|O_LARGEFILE)
            || (flags&O_ACCMODE)==O_ACCMODE) return -EINVAL;
    char path[NAME_MAX+34];
    if (parent) {
        if (strlen(parent)!=32 || strspn(parent,"0123456789abcdef")!=32) return -EINVAL;
        int n=snprintf(path,sizeof(path),"%s/%s",parent,name);
        if (n<0 || (size_t)n>=sizeof(path)) return -ENAMETOOLONG;
        name=path;
    }
    int fd=openat(directory,name,flags|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode);
    return fd<0 ? -errno : fd;
}
int mdi_native_create(int directory,const char *name,int flags,uint32_t uid,uint32_t gid,mode_t mode) {
    return mdi_native_create_in(directory,NULL,name,flags,uid,gid,mode);
}
static void descriptor_path(int fd,char out[64]) { snprintf(out,64,"/proc/self/fd/%d",fd); }
static int change_mode(int fd,mode_t mode) {
    if (!fchmod(fd,mode)) return 0;
    if (errno!=EBADF) return -errno;
    char path[64]; descriptor_path(fd,path);
    return chmod(path,mode) ? -errno : 0;
}
static ssize_t get(int fd,void *record,size_t size) {
    ssize_t n=fgetxattr(fd,MDI_NATIVE_METADATA,record,size);
    if (n<0 && errno==EBADF) {
        char path[64]; descriptor_path(fd,path); n=getxattr(path,MDI_NATIVE_METADATA,record,size);
    }
    return n<0 ? -errno : n;
}
static size_t bytes(const struct metadata *record) {
    return sizeof(*record)+(size_t)le32toh(record->acl)+le32toh(record->cap);
}
static int set(int fd,const struct metadata *record) {
    int r=fsetxattr(fd,MDI_NATIVE_METADATA,record,bytes(record),0);
    if (r && errno==EBADF) {
        char path[64]; descriptor_path(fd,path); r=setxattr(path,MDI_NATIVE_METADATA,record,bytes(record),0);
    }
    return r ? -errno : 0;
}
static int sync_metadata(int fd) {
    if (!fsync(fd)) return 0;
    if (errno!=EBADF) return -errno;
    char path[64]; descriptor_path(fd,path);
    int copy=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);
    if (copy<0) return -errno;
    int r=fsync(copy) ? -errno : 0;
    close(copy); return r;
}
int mdi_native_prepare(int objects,const char *name,int flags,uint32_t uid,uint32_t gid,mode_t mode) {
    if (uid==UINT32_MAX || gid==UINT32_MAX || (mode&~07777)) return -EINVAL;
    int fd=mdi_native_create(objects,name,flags,0,0,0600);
    if (fd<0) return fd;
    struct metadata record={.magic=htole32(METADATA_MAGIC),.uid=htole32(uid),.gid=htole32(gid),.mode=htole32(mode)};
    int r=change_mode(fd,METADATA_MODE);
    if (!r) r=set(fd,&record);
    /* A crash before publication leaves only an untracked staging backing.
     * After publication, both selector and complete metadata are durable. */
    if (!r) r=sync_metadata(fd);
    if (r) { close(fd); unlinkat(objects,name,0); }
    return r ? r : fd;
}
static int valid_physical(const struct stat *st) {
    if (!S_ISREG(st->st_mode) || st->st_nlink>1) return -EINVAL;
    mode_t mode=st->st_mode&07777;
    return mode==METADATA_MODE || mdi_native_eligible(0,0,mode) ? 0 : -EIO;
}
static int physical(int fd,struct stat *st) {
    return fstat(fd,st) ? -errno : valid_physical(st);
}
struct metadata_buffer {
    struct metadata *record;
    _Alignas(struct metadata) unsigned char local[256];
};
static void release(struct metadata_buffer *buffer) {
    if ((void *)buffer->record!=buffer->local) free(buffer->record);
}
static int load(int fd,const struct stat *st,struct metadata_buffer *buffer) {
    buffer->record=(void *)buffer->local;
    struct metadata *p=buffer->record;
    if (!(st->st_mode&S_ISVTX)) {
        *p=(struct metadata){.magic=htole32(METADATA_MAGIC),.mode=htole32(st->st_mode&07777)};
        return 0;
    }
    /* The complete xattr is one atomic observation. Common ownership/mode and
     * small ACL records need neither a size query nor a heap allocation. */
    ssize_t size=get(fd,p,sizeof(buffer->local));
    if (size==-ERANGE) {
        size=get(fd,NULL,0);
        if (size>0 && size<=65536) {
            p=malloc((size_t)size);
            if (!p) return -ENOMEM;
            buffer->record=p;
            size=get(fd,p,(size_t)size);
        }
    }
    int r=0;
    if (size<(ssize_t)sizeof(*p) || size>65536)
        r=size<0 && size!=-ENODATA ? (int)size : -EIO;
    if (!r) {
        uint32_t acl=le32toh(p->acl),cap=le32toh(p->cap);
        if (le32toh(p->magic)!=METADATA_MAGIC || le32toh(p->uid)==UINT32_MAX
                || le32toh(p->gid)==UINT32_MAX || (le32toh(p->mode)&~07777)
                || bytes(p)!=(size_t)size || acl>MD_ACL_MAX || cap>MD_FILE_CAPABILITY_MAX) r=-EIO;
        if (!r && acl && !md_acl_valid(p->data,acl)) r=-EIO;
        if (!r && cap && !md_file_capability_valid(p->data+acl,cap)) r=-EIO;
    }
    if (r) release(buffer);
    return r;
}
static int publish(int fd,const struct stat *st,const struct metadata *old,const struct metadata *next) {
    mode_t mode=le32toh(next->mode);
    if (!next->acl && !next->cap && mdi_native_eligible(le32toh(next->uid),le32toh(next->gid),mode))
        return change_mode(fd,mode);
    int r=0;
    if (!(st->st_mode&S_ISVTX)) {
        /* Persist the old complete state before its selector can reach disk.
         * The final xattr replacement atomically publishes mode, ACL and caps. */
        r=set(fd,old);
        if (!r) r=sync_metadata(fd);
        if (!r) r=change_mode(fd,METADATA_MODE);
    }
    return r ? r : set(fd,next);
}
int mdi_native_project(int fd,struct stat *st,unsigned *acl) {
    if (acl) *acl=0;
    int r=valid_physical(st);
    if (r) return r;
    if (!(st->st_mode&S_ISVTX)) { st->st_uid=st->st_gid=0; return 0; }
    struct metadata_buffer buffer;
    r=load(fd,st,&buffer);
    if (!r) {
        const struct metadata *p=buffer.record;
        st->st_uid=le32toh(p->uid); st->st_gid=le32toh(p->gid); st->st_mode=S_IFREG|le32toh(p->mode);
        if (acl && p->acl) *acl=MD_ACL_ACCESS;
        release(&buffer);
    }
    return r;
}
int mdi_native_info(int fd,struct stat *st,unsigned *acl) {
    return fstat(fd,st) ? -errno : mdi_native_project(fd,st,acl);
}
int mdi_native_stat(int fd,struct stat *st) { return mdi_native_info(fd,st,NULL); }
static int metadata(int fd,uint32_t uid,uint32_t gid,mode_t mode,int clear_capability) {
    if (uid==UINT32_MAX || gid==UINT32_MAX || (mode&~07777)) return -EINVAL;
    struct stat st;
    int r=physical(fd,&st);
    if (r) return r;
    if (!(st.st_mode&S_ISVTX) && mdi_native_eligible(uid,gid,mode))
        return mode==(st.st_mode&07777) ? 0 : change_mode(fd,mode);
    struct metadata_buffer buffer;
    r=load(fd,&st,&buffer);
    if (r) return r;
    const struct metadata *old=buffer.record;
    if (le32toh(old->uid)==uid && le32toh(old->gid)==gid && le32toh(old->mode)==mode
            && (!clear_capability || !old->cap)) { release(&buffer); return 0; }
    struct metadata *next=malloc(bytes(old));
    if (!next) { release(&buffer); return -ENOMEM; }
    memcpy(next,old,bytes(old)); next->uid=htole32(uid); next->gid=htole32(gid); next->mode=htole32(mode);
    if (clear_capability) next->cap=0;
    if (next->acl) md_acl_chmod((struct md_acl *)next->data,le32toh(next->acl),mode,0);
    r=publish(fd,&st,old,next); free(next); release(&buffer); return r;
}
int mdi_native_metadata(int fd,uint32_t uid,uint32_t gid,mode_t mode) { return metadata(fd,uid,gid,mode,0); }
int mdi_native_chown(int fd,uint32_t uid,uint32_t gid,mode_t mode) { return metadata(fd,uid,gid,mode,1); }
ssize_t mdi_native_attribute(int fd,int capability,void *out,size_t capacity) {
    struct stat st;
    int r=physical(fd,&st);
    if (r) return r;
    if (!(st.st_mode&S_ISVTX)) return -ENODATA;
    struct metadata_buffer buffer;
    r=load(fd,&st,&buffer);
    if (r) return r;
    const struct metadata *p=buffer.record;
    size_t size=le32toh(capability ? p->cap : p->acl),offset=capability ? le32toh(p->acl) : 0;
    if (!size) r=-ENODATA;
    else if (capacity && (!out || capacity<size)) r=-ERANGE;
    else if (capacity) memcpy(out,p->data+offset,size);
    release(&buffer); return r ? r : (ssize_t)size;
}
int mdi_native_attribute_set(int fd,int capability,const void *value,size_t size,mode_t mode) {
    if ((!value && size) || (mode&~07777)) return -EINVAL;
    if (value && !(capability ? md_file_capability_valid(value,size) : md_acl_valid(value,size))) return -EINVAL;
    struct stat st;
    int r=physical(fd,&st);
    if (r) return r;
    struct metadata_buffer buffer;
    r=load(fd,&st,&buffer);
    if (r) return r;
    const struct metadata *old=buffer.record;
    size_t acl=capability ? le32toh(old->acl) : size,cap=capability ? size : le32toh(old->cap);
    if (acl+cap>65536-sizeof(*old)) { release(&buffer); return -E2BIG; }
    struct metadata *next=malloc(sizeof(*next)+acl+cap);
    if (!next) { release(&buffer); return -ENOMEM; }
    *next=*old; next->acl=htole32(acl); next->cap=htole32(cap); next->mode=htole32(mode);
    if (acl) memcpy(next->data,capability ? old->data : value,acl);
    if (cap) memcpy(next->data+acl,capability ? value : old->data+le32toh(old->acl),cap);
    r=bytes(old)==bytes(next) && !memcmp(old,next,bytes(old)) ? 0 : publish(fd,&st,old,next);
    free(next); release(&buffer); return r;
}
