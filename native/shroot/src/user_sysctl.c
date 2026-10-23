#include "user_sysctl.h"
#include "guest_identity.h"
#include "fs_mounts.h"
#include "mount_policy.h"
#include "sysctl_value.h"
#include <errno.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct user_sysctl {
    atomic_uint references;
    struct md_user_namespace *space;
    struct md_fs_anchor *origin;
};
static void *retain(void *context) {
    struct user_sysctl *f=context;
    atomic_fetch_add_explicit(&f->references,1,memory_order_relaxed); return f;
}
static void release(void *context) {
    struct user_sysctl *f=context;
    if (atomic_fetch_sub_explicit(&f->references,1,memory_order_acq_rel)!=1) return;
    md_fs_anchor_release(f->origin); md_user_namespace_release(f->space); free(f);
}
static struct md_fs_anchor *origin(void *context) { return ((struct user_sysctl *)context)->origin; }
static int metadata(void *context,struct stat *out) {
    struct user_sysctl *f=context;
    *out=(struct stat){.st_dev=UINT32_C(0xfffc0000),.st_ino=md_user_namespace_inode(f->space),
        .st_mode=S_IFREG|0644,.st_nlink=1,.st_blksize=getpagesize(),
        .st_uid=md_user_namespace_into(f->space,0,0),.st_gid=md_user_namespace_into(f->space,1,0)};
    return 0;
}
static int file_access(void *context,const struct md_identity *id,unsigned mode) {
    struct user_sysctl *f=context;
    if (mode&~7U) return -EINVAL;
    if (mode&X_OK) return -EACCES;
    if ((mode&W_OK) && (md_fs_anchor_policy(f->origin)&MD_MOUNT_READONLY)) return -EROFS;
    if ((mode&W_OK) && !md_identity_capable_in(id,f->space,CAP_SYS_RESOURCE)) return -EACCES;
    return 0;
}
static long read_value(void *context,const struct md_control_actor *actor,void *out,size_t size,int64_t offset) {
    (void)actor;
    struct user_sysctl *f=context;
    if (offset<0) return -EINVAL;
    char text[32];
    int count=snprintf(text,sizeof(text),"%u\n",md_user_namespace_limit(f->space,MD_USER_NAMESPACES));
    if ((uint64_t)offset>=(unsigned)count) return 0;
    size_t n=(size_t)count-(size_t)offset;
    if (n>size) n=size;
    memcpy(out,text+offset,n); return (long)n;
}
static long write_value(void *context,const struct md_control_actor *actor,const void *data,size_t size,int64_t offset) {
    struct user_sysctl *f=context;
    int error=file_access(f,actor->identity,W_OK);
    if (error || !size) return error;
    if (offset<0) return -EINVAL;
    if (offset) return (long)size;
    uint32_t value=0;
    error=md_sysctl_parse_uint(data,size,&value);
    if (!error) error=md_user_namespace_set_limit(f->space,MD_USER_NAMESPACES,value);
    return error ? error : (long)size;
}
static const struct md_control_file_ops ops={.retain=retain,.release=release,.stat=metadata,
    .access=file_access,.read=read_value,.write=write_value,.origin=origin,.filesystem=PROC_SUPER_MAGIC};
struct md_control_file md_user_sysctl_new(struct md_user_namespace *space,struct md_fs_anchor *anchor) {
    struct user_sysctl *f=calloc(1,sizeof(*f));
    if (!f) return (struct md_control_file){0};
    atomic_init(&f->references,1);
    f->space=md_user_namespace_retain(space); f->origin=md_fs_anchor_retain(anchor);
    return (struct md_control_file){&ops,f};
}
