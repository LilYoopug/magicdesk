#define _GNU_SOURCE
#include "sysfs_uevent.h"
#include "device_events.h"
#include "provider_tree.h"
#include "file_permissions.h"
#include "file_open.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct attribute {
    atomic_uint refs;
    struct md_device_events *events;
    int fd;
    char *path,*subsystem;
};
static void *retain(void *context) {
    struct attribute *a=context; atomic_fetch_add_explicit(&a->refs,1,memory_order_relaxed); return a;
}
static void release(void *context) {
    struct attribute *a=context;
    if (atomic_fetch_sub_explicit(&a->refs,1,memory_order_acq_rel)!=1) return;
    close(a->fd); md_device_events_release(a->events); free(a->path); free(a->subsystem); free(a);
}
static int metadata(void *context,struct stat *st) {
    struct attribute *a=context;
    if (fstat(a->fd,st)) return -errno;
    if (!st->st_nlink) return -ENODEV;
    st->st_uid=st->st_gid=0; st->st_mode=S_IFREG|0644;
    st->st_size=4096; st->st_blocks=0; return 0;
}
static int access_node(void *context,const struct md_identity *id,unsigned mode) {
    struct stat st; int error=metadata(context,&st);
    return error ? error : md_file_permissions(&st,mode,id);
}
static long read_node(void *context,const struct md_control_actor *actor,void *data,size_t size,int64_t offset) {
    (void)actor;
    struct stat st; int error=metadata(context,&st);
    if (error) return error;
    ssize_t n=pread(((struct attribute *)context)->fd,data,size,offset);
    return n<0 ? -errno : n;
}
static int word_char(unsigned char c) {
    return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9');
}
static int synthetic_properties(const char *args,size_t length,char *out,size_t capacity) {
    if (!args) {
        static const char empty[]="SYNTH_UUID=0";
        if (capacity<sizeof(empty)) return -EOVERFLOW;
        memcpy(out,empty,sizeof(empty)); return sizeof(empty);
    }
    if (length<36) return -EINVAL;
    for (size_t i=0;i<36;++i) {
        unsigned char c=args[i];
        if (i==8 || i==13 || i==18 || i==23) { if (c!='-') return -EINVAL; }
        else if (!((c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F'))) return -EINVAL;
    }
    int n=snprintf(out,capacity,"SYNTH_UUID=%.*s",36,args);
    if (n<0 || (size_t)n>=capacity) return -EOVERFLOW;
    size_t used=(size_t)n+1,pos=36;
    while (pos<length) {
        if (args[pos++]!=' ') return -EINVAL;
        size_t key=pos;
        while (pos<length && word_char(args[pos])) ++pos;
        if (pos==key || pos==length || args[pos++]!='=') return -EINVAL;
        size_t value=pos;
        while (pos<length && word_char(args[pos])) ++pos;
        if (pos==value) return -EINVAL;
        n=snprintf(out+used,capacity-used,"SYNTH_ARG_%.*s",(int)(pos-key),args+key);
        if (n<0 || (size_t)n>=capacity-used) return -EOVERFLOW;
        used+=(size_t)n+1;
    }
    return (int)used;
}
static long write_node(void *context,const struct md_control_actor *actor,const void *data,size_t size,int64_t offset) {
    (void)offset;
    struct attribute *a=context;
    int error=access_node(a,actor->identity,W_OK);
    if (error) return error;
    size_t length=size;
    const char *text=data;
    if (length && (text[length-1]=='\n' || !text[length-1])) --length;
    const char *args=memchr(text,' ',length);
    size_t action_length=args ? (size_t)(args-text) : length;
    static const char *const actions[]={"add","remove","change","move","online","offline","bind","unbind"};
    const char *action=NULL;
    for (unsigned i=0;i<sizeof(actions)/sizeof(*actions);++i)
        if (strlen(actions[i])==action_length && !memcmp(text,actions[i],action_length)) { action=actions[i]; break; }
    if (!action) return -EINVAL;
    char properties[4096];
    ssize_t n=pread(a->fd,properties,sizeof(properties),0);
    if (n<0) return -errno;
    if (n==(ssize_t)sizeof(properties)) return -EOVERFLOW;
    /* The immutable sysfs payload uses newlines; netlink uses NUL records. */
    for (ssize_t i=0;i<n;++i) if (properties[i]=='\n') properties[i]=0;
    if (n && properties[n-1]) properties[n++]=0;
    int extra=synthetic_properties(args ? args+1 : NULL,args ? length-action_length-1 : 0,
        properties+n,sizeof(properties)-(size_t)n);
    if (extra<0) return extra;
    n+=extra;
    error=md_device_events_publish(a->events,action,a->path,a->subsystem,properties,(size_t)n);
    return error ? error : (long)size;
}
static const struct md_control_file_ops operations={.retain=retain,.release=release,
    .stat=metadata,.access=access_node,.read=read_node,.write=write_node,.filesystem=SYSFS_MAGIC};
int md_sysfs_uevent(struct md_provider_tree *tree,struct md_device_events *events,int fd,struct md_control_file *out) {
    if (!events || fd<0 || md_provider_tree_filesystem(tree)!=SYSFS_MAGIC) return 0;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISREG(st.st_mode)) return 0;
    int owned=md_provider_tree_private(tree,fd);
    if (owned<=0) return owned;
    char path[PATH_MAX];
    int error=md_provider_tree_path(tree,fd,path,sizeof(path));
    if (error) return error;
    size_t length=strlen(path);
    if (strncmp(path,"/devices/",9) || length<16 || strcmp(path+length-7,"/uevent")) return 0;
    path[length-6]=0;
    if (length+sizeof("subsystem")>sizeof(path)) return -ENAMETOOLONG;
    memcpy(path+length-6,"subsystem",sizeof("subsystem"));
    char subsystem[PATH_MAX];
    ssize_t n=readlinkat(md_provider_tree_root(tree),path+1,subsystem,sizeof(subsystem)-1);
    if (n<0) return -errno;
    if (n==(ssize_t)sizeof(subsystem)-1) return -ENAMETOOLONG;
    subsystem[n]=0;
    char *name=strrchr(subsystem,'/'); name=name ? name+1 : subsystem;
    if (!*name || !strcmp(name,".") || !strcmp(name,"..")) return -EINVAL;
    path[length-7]=0;
    struct attribute *a=calloc(1,sizeof(*a));
    if (!a) return -ENOMEM;
    atomic_init(&a->refs,1); a->fd=-1;
    a->events=md_device_events_retain(events);
    a->path=strdup(path); a->subsystem=strdup(name);
    if (!a->path || !a->subsystem) error=-ENOMEM;
    else { a->fd=md_open_pinned(fd,O_RDONLY|O_CLOEXEC); if (a->fd<0) error=a->fd; }
    if (error) { release(a); return error; }
    *out=(struct md_control_file){&operations,a}; return 1;
}
