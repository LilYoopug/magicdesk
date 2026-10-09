#define _GNU_SOURCE
#include "sysfs_view.h"
#include "temporary_directory.h"
#include "guest_identity.h"
#include "file_permissions.h"
#include "fs_anchor.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/magic.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum attribute { DIRECTORY, LINK, IFINDEX, IFLINK, MTU, TYPE, ADDRESS, BROADCAST, FLAGS, OPERSTATE, CARRIER };
static const struct node { const char *path; enum attribute attribute; const char *target; } nodes[]={
    {".",DIRECTORY,NULL}, {"class",DIRECTORY,NULL}, {"class/net",DIRECTORY,NULL},
    {"devices",DIRECTORY,NULL}, {"devices/virtual",DIRECTORY,NULL},
    {"devices/virtual/net",DIRECTORY,NULL}, {"devices/virtual/net/lo",DIRECTORY,NULL},
    {"class/net/lo",LINK,"../../devices/virtual/net/lo"},
    {"devices/virtual/net/lo/subsystem",LINK,"../../../../class/net"},
    {"fs",DIRECTORY,NULL}, {"fs/cgroup",DIRECTORY,NULL},
    {"devices/virtual/net/lo/ifindex",IFINDEX,NULL}, {"devices/virtual/net/lo/iflink",IFLINK,NULL},
    {"devices/virtual/net/lo/mtu",MTU,NULL}, {"devices/virtual/net/lo/type",TYPE,NULL},
    {"devices/virtual/net/lo/address",ADDRESS,NULL}, {"devices/virtual/net/lo/broadcast",BROADCAST,NULL},
    {"devices/virtual/net/lo/flags",FLAGS,NULL}, {"devices/virtual/net/lo/operstate",OPERSTATE,NULL},
    {"devices/virtual/net/lo/carrier",CARRIER,NULL},
};
enum { NODE_COUNT=sizeof(nodes)/sizeof(*nodes) };
struct md_sysfs {
    atomic_uint refs;
    int storage,root;
    struct md_network_namespace *network;
    struct stat identities[NODE_COUNT];
};
struct opened {
    atomic_uint refs;
    struct md_sysfs *view;
    struct md_fs_anchor *origin;
    unsigned node;
};
struct md_sysfs *md_sysfs_retain(struct md_sysfs *v) {
    if (v) atomic_fetch_add_explicit(&v->refs,1,memory_order_relaxed);
    return v;
}
void md_sysfs_release(struct md_sysfs *v) {
    if (!v || atomic_fetch_sub_explicit(&v->refs,1,memory_order_acq_rel)!=1) return;
    if (v->root>=0) close(v->root);
    if (v->storage>=0) md_temporary_directory_release(v->storage);
    md_network_namespace_release(v->network); free(v);
}
struct md_sysfs *md_sysfs_new(int parent,struct md_network_namespace *network,const struct md_identity *id) {
    struct md_network_link link;
    int r=md_network_link_info(network,1,&link);
    if (r) { errno=-r; return NULL; }
    struct md_sysfs *v=calloc(1,sizeof(*v));
    if (!v) return NULL;
    atomic_init(&v->refs,1); v->root=v->storage=-1;
    v->network=md_network_namespace_retain(network);
    v->storage=md_temporary_directory_new(parent);
    if (v->storage<0) { errno=-v->storage; goto failed; }
    if (mkdirat(v->storage,"sys",0700)) goto failed;
    v->root=openat(v->storage,"sys",O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (v->root<0) goto failed;
    for (unsigned i=0;i<NODE_COUNT;++i) {
        const struct node *n=&nodes[i];
        if (n->attribute==DIRECTORY) {
            if (i && mkdirat(v->root,n->path,0700)) goto failed;
        } else if (n->attribute==LINK) {
            if (symlinkat(n->target,v->root,n->path)) goto failed;
        } else {
            int fd=openat(v->root,n->path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
            if (fd<0) goto failed;
            close(fd);
        }
        struct stat *st=&v->identities[i];
        if (fstatat(v->root,n->path,st,AT_SYMLINK_NOFOLLOW)) goto failed;
        st->st_uid=md_user_namespace_into(id->user_namespace,0,0);
        st->st_gid=md_user_namespace_into(id->user_namespace,1,0);
        st->st_mode=n->attribute==DIRECTORY ? S_IFDIR|0755 : n->attribute==LINK ? S_IFLNK|0777 : S_IFREG|0444;
        st->st_size=n->attribute==LINK ? (off_t)strlen(n->target) : n->attribute==DIRECTORY ? 0 : 4096;
        st->st_blocks=0; st->st_blksize=4096;
    }
    return v;
failed:;
    int error=errno; md_sysfs_release(v); errno=error; return NULL;
}
int md_sysfs_root(const struct md_sysfs *v) { return v->root; }
static int node_index(const struct md_sysfs *v,int fd) {
    if (fd<0) return -ENOENT;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    for (unsigned i=0;i<NODE_COUNT;++i)
        if (st.st_dev==v->identities[i].st_dev && st.st_ino==v->identities[i].st_ino) return (int)i;
    return -ESTALE;
}
int md_sysfs_stat(const struct md_sysfs *v,int fd,struct stat *st) {
    int i=node_index(v,fd);
    if (i<0) return i;
    *st=v->identities[i]; return 0;
}
static void *retain_open(void *data) {
    struct opened *o=data; atomic_fetch_add_explicit(&o->refs,1,memory_order_relaxed); return o;
}
static void release_open(void *data) {
    struct opened *o=data;
    if (atomic_fetch_sub_explicit(&o->refs,1,memory_order_acq_rel)!=1) return;
    md_fs_anchor_release(o->origin); md_sysfs_release(o->view); free(o);
}
static int stat_open(void *data,struct stat *st) {
    struct opened *o=data; *st=o->view->identities[o->node]; return 0;
}
static long read_open(void *data,const struct md_control_actor *actor,void *out,size_t size,int64_t offset) {
    (void)actor;
    struct opened *o=data; struct md_network_link info;
    if (offset<0) return -EINVAL;
    int r=md_network_link_info(o->view->network,1,&info);
    if (r) return r;
    char text[64]; int length;
    switch (nodes[o->node].attribute) {
    case IFINDEX: case IFLINK: length=snprintf(text,sizeof(text),"%u\n",info.index); break;
    case MTU: length=snprintf(text,sizeof(text),"%u\n",info.mtu); break;
    case TYPE: length=snprintf(text,sizeof(text),"%u\n",info.type); break;
    case FLAGS: length=snprintf(text,sizeof(text),"0x%x\n",info.flags); break;
    case ADDRESS: case BROADCAST:
        length=snprintf(text,sizeof(text),"%02x:%02x:%02x:%02x:%02x:%02x\n",info.address[0],info.address[1],
            info.address[2],info.address[3],info.address[4],info.address[5]); break;
    case OPERSTATE: length=snprintf(text,sizeof(text),"%s\n",info.state==IF_OPER_DOWN ? "down" : "unknown"); break;
    case CARRIER:
        if (!(info.flags&IFF_UP)) return -EINVAL;
        length=snprintf(text,sizeof(text),"1\n"); break;
    default: return -EINVAL;
    }
    if ((uint64_t)offset>=(unsigned)length) return 0;
    size_t count=(size_t)length-(size_t)offset;
    if (count>size) count=size;
    memcpy(out,text+offset,count); return (long)count;
}
static long write_open(void *data,const struct md_control_actor *actor,const void *in,size_t size,int64_t offset) {
    (void)offset;
    (void)data; (void)actor; (void)in; (void)size; return -EOPNOTSUPP;
}
static int access_open(void *data,const struct md_identity *id,unsigned mode) {
    struct opened *o=data;
    return md_file_permissions(&o->view->identities[o->node],mode,id);
}
static const struct md_control_file_ops ops={.retain=retain_open,.release=release_open,
    .stat=stat_open,.read=read_open,.write=write_open,.access=access_open,.filesystem=SYSFS_MAGIC};
int md_sysfs_open(struct md_sysfs *v,int fd,int flags,const struct md_identity *id,
        struct md_fs_anchor *origin,const struct md_control_file_ops **out,void **context) {
    int i=node_index(v,fd);
    if (i<0) return i;
    const struct stat *st=&v->identities[i];
    if ((flags&O_DIRECTORY) && !S_ISDIR(st->st_mode)) return -ENOTDIR;
    if (!(flags&O_PATH)) {
        if (S_ISLNK(st->st_mode)) return -ELOOP;
        if (flags&(O_ACCMODE|O_TRUNC)) return S_ISDIR(st->st_mode) ? -EISDIR : -EOPNOTSUPP;
        int r=md_file_permissions(st,R_OK,id);
        if (r) return r;
    }
    if (!S_ISREG(st->st_mode)) return 0;
    struct opened *o=calloc(1,sizeof(*o));
    if (!o) return -ENOMEM;
    atomic_init(&o->refs,1); o->view=md_sysfs_retain(v); o->node=(unsigned)i;
    o->origin=md_fs_anchor_retain(origin);
    *out=&ops; *context=o; return 0;
}
