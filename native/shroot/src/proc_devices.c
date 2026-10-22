#include "proc_devices.h"
#include "user_namespace.h"
#include "fs_mounts.h"
#include <errno.h>
#include <linux/magic.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Guest driver families, not Android's hardware inventory. Registration does
 * not grant access to a device: each open still uses its existing provider. */
static const char devices[]=
    "Character devices:\n"
    "  1 mem\n"
    "  5 /dev/tty\n"
    "  5 /dev/ptmx\n"
    " 10 misc\n"
    " 13 input\n"
    "136 pts\n"
    "226 drm\n"
    "\nBlock devices:\n";
struct catalogue {
    atomic_uint references;
    struct md_user_namespace *owner;
    struct md_fs_anchor *origin;
};
static void *retain(void *context) {
    struct catalogue *c=context;
    atomic_fetch_add_explicit(&c->references,1,memory_order_relaxed); return c;
}
static void release(void *context) {
    struct catalogue *c=context;
    if (atomic_fetch_sub_explicit(&c->references,1,memory_order_acq_rel)!=1) return;
    md_fs_anchor_release(c->origin); md_user_namespace_release(c->owner); free(c);
}
static struct md_fs_anchor *origin(void *context) { return ((struct catalogue *)context)->origin; }
static int metadata(void *context,struct stat *st) {
    struct catalogue *c=context;
    *st=(struct stat){.st_dev=UINT32_C(0xfffa0000),.st_ino=1,.st_mode=S_IFREG|0444,
        .st_nlink=1,.st_blksize=4096,.st_uid=md_user_namespace_into(c->owner,0,0),
        .st_gid=md_user_namespace_into(c->owner,1,0)};
    return 0;
}
static int access_mode(void *context,const struct md_identity *id,unsigned mode) {
    (void)context; (void)id;
    return mode&~7U ? -EINVAL : mode&(W_OK|X_OK) ? -EACCES : 0;
}
static long read_value(void *context,const struct md_control_actor *actor,void *out,size_t size,int64_t offset) {
    (void)context; (void)actor;
    if (offset<0) return -EINVAL;
    if ((uint64_t)offset>=sizeof(devices)-1) return 0;
    size_t count=sizeof(devices)-1-(size_t)offset;
    if (count>size) count=size;
    memcpy(out,devices+offset,count); return (long)count;
}
static const struct md_control_file_ops ops={.retain=retain,.release=release,.stat=metadata,
    .access=access_mode,.read=read_value,.origin=origin,.filesystem=PROC_SUPER_MAGIC};
struct md_control_file md_proc_devices_new(struct md_user_namespace *owner,struct md_fs_anchor *anchor) {
    struct catalogue *c=calloc(1,sizeof(*c));
    if (!c) return (struct md_control_file){0};
    atomic_init(&c->references,1);
    c->owner=md_user_namespace_retain(owner); c->origin=md_fs_anchor_retain(anchor);
    return (struct md_control_file){&ops,c};
}
