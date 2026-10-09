#include "network_namespace.h"
#include "guest_identity.h"
#include "fs_mounts.h"
#include "mount_policy.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct network_sysctl {
    atomic_uint references;
    struct md_network_namespace *network;
    enum md_network_parameter parameter;
    struct md_fs_anchor *origin;
};
static void *retain(void *context) {
    struct network_sysctl *f=context;
    atomic_fetch_add_explicit(&f->references,1,memory_order_relaxed); return f;
}
static void release(void *context) {
    struct network_sysctl *f=context;
    if (atomic_fetch_sub_explicit(&f->references,1,memory_order_acq_rel)!=1) return;
    md_fs_anchor_release(f->origin); md_network_namespace_release(f->network); free(f);
}
static int metadata(void *context,struct stat *out) {
    struct network_sysctl *f=context;
    const struct md_user_namespace *owner=md_network_namespace_owner(f->network);
    *out=(struct stat){.st_dev=UINT32_C(0xfffd0000)+(unsigned)f->parameter,
        .st_ino=md_network_namespace_inode(f->network),.st_mode=S_IFREG|0644,
        .st_nlink=1,.st_blksize=getpagesize(),
        .st_uid=md_user_namespace_into(owner,0,0),.st_gid=md_user_namespace_into(owner,1,0)};
    return 0;
}
static int file_access(void *context,const struct md_identity *id,unsigned mode) {
    struct network_sysctl *f=context;
    if (mode&~7U) return -EINVAL;
    if (mode&X_OK) return -EACCES;
    if ((mode&W_OK) && (md_fs_anchor_policy(f->origin)&MD_MOUNT_READONLY)) return -EROFS;
    if ((mode&W_OK) && !md_identity_capable_in(id,md_network_namespace_owner(f->network),CAP_NET_ADMIN))
        return -EACCES;
    return 0;
}
static long read_value(void *context,const struct md_control_actor *actor,void *out,size_t size,int64_t offset) {
    struct network_sysctl *f=context;
    if (offset<0) return -EINVAL;
    uint32_t value[2];
    int error=md_network_parameter_get(f->network,f->parameter,value);
    if (error) return error;
    if (f->parameter==MD_NET_PING_GROUPS) for (unsigned i=0;i<2;++i)
        value[i]=md_identity_visible_id(actor->identity,1,value[i]);
    char text[32];
    int count=f->parameter==MD_NET_UNPRIVILEGED_PORT ? snprintf(text,sizeof(text),"%u\n",value[0])
        : snprintf(text,sizeof(text),"%u\t%u\n",value[0],value[1]);
    if ((uint64_t)offset>=(unsigned)count) return 0;
    size_t n=(size_t)count-(size_t)offset;
    if (n>size) n=size;
    memcpy(out,text+offset,n); return (long)n;
}
static long write_value(void *context,const struct md_control_actor *actor,const void *data,size_t size,int64_t offset) {
    struct network_sysctl *f=context;
    int error=file_access(f,actor->identity,W_OK);
    if (error || !size) return error;
    /* Numeric proc sysctls consume nonzero-offset writes without replacing
     * the value, as with Linux's default sysctl_writes_strict policy. */
    if (offset<0) return -EINVAL;
    if (offset) return (long)size;
    if (size>128) return -E2BIG;
    const unsigned char *p=data,*end=p+size;
    uint32_t value[2]={0};
    unsigned count=f->parameter==MD_NET_UNPRIVILEGED_PORT ? 1 : 2;
    for (unsigned i=0;i<count;++i) {
        while (p<end && isspace(*p)) ++p;
        if (p==end || !isdigit(*p)) return -EINVAL;
        do {
            unsigned digit=*p++-'0';
            if (value[i]>(UINT32_MAX-digit)/10) return -EINVAL;
            value[i]=value[i]*10+digit;
        } while (p<end && isdigit(*p));
        if (p<end && !isspace(*p)) return -EINVAL;
    }
    while (p<end && isspace(*p)) ++p;
    if (p!=end) return -EINVAL;
    if (f->parameter==MD_NET_PING_GROUPS) for (unsigned i=0;i<2;++i) {
        if (value[i]>INT_MAX) return -EINVAL;
        value[i]=md_user_namespace_into(actor->identity->user_namespace,1,value[i]);
    }
    error=md_network_parameter_set(f->network,f->parameter,value);
    return error ? error : (long)size;
}
static const struct md_control_file_ops ops={.retain=retain,.release=release,.stat=metadata,
    .access=file_access,.read=read_value,.write=write_value,.filesystem=PROC_SUPER_MAGIC};
struct md_control_file md_network_sysctl_new(struct md_network_namespace *network,enum md_network_parameter parameter,
        struct md_fs_anchor *origin) {
    uint32_t values[2];
    int error=md_network_parameter_get(network,parameter,values);
    if (error) { errno=-error; return (struct md_control_file){0}; }
    struct network_sysctl *f=calloc(1,sizeof(*f));
    if (!f) return (struct md_control_file){0};
    atomic_init(&f->references,1); f->network=md_network_namespace_retain(network); f->parameter=parameter;
    f->origin=md_fs_anchor_retain(origin);
    return (struct md_control_file){&ops,f};
}
