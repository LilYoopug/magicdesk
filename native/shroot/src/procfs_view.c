#define _GNU_SOURCE
#include "procfs_view.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "proc_paths.h"
#include "network_namespace.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static pid_t decimal(const char *name,const char **end) {
    unsigned long value=0;
    const char *p=name;
    if (*p<'0' || *p>'9' || (*p=='0' && p[1])) return 0;
    while (*p>='0' && *p<='9') {
        value=value*10+(unsigned)(*p++-'0');
        if (value>INT_MAX) return 0;
    }
    if (end) *end=p;
    else if (*p) return 0;
    return (pid_t)value;
}
static pid_t visible(const struct md_view_mount *mount,pid_t native) {
    if (!mount->pid_namespace) return native;
    struct md_pid_identity *id=md_pid_namespace_find(mount->pid_namespace,native);
    pid_t result=md_pid_identity_number(id,mount->pid_namespace);
    md_pid_identity_release(id); return result;
}
/* Returns a native TGID for a task directory, -1 for the proc root, else zero. */
static pid_t directory(const char *path) {
    if (!strcmp(path,"/proc")) return -1;
    if (strncmp(path,"/proc/",6)) return 0;
    const char *end;
    pid_t pid=decimal(path+6,&end);
    return pid && !strcmp(end,"/task") ? pid : 0;
}
static int process_directory(const char *path) {
    if (strncmp(path,"/proc/",6)) return 0;
    const char *end;
    if (!decimal(path+6,&end)) return 0;
    if (!*end) return 1;
    return !strncmp(end,"/task/",6) && decimal(end+6,&end) && !*end;
}
static int control(const char *path,const char *name) {
    if (process_directory(path))
        return !strcmp(name,"ns") || !strcmp(name,"uid_map") || !strcmp(name,"gid_map")
            || !strcmp(name,"setgroups") || !strcmp(name,"exe") || !strcmp(name,"cmdline")
            || !strcmp(name,"auxv") || !strcmp(name,"fd") || !strcmp(name,"fdinfo")
            || !strcmp(name,"root") || !strcmp(name,"cwd") || !strcmp(name,"mounts")
            || !strcmp(name,"mountinfo") || !strcmp(name,"cgroup");
    return !strcmp(path,"/proc/sys/kernel") || !strcmp(path,"/proc/sys/net/ipv4")
        || (!strcmp(path,"/proc") && !strcmp(name,"cgroups"));
}
static int kernel_global(const char *name) {
    /* A mounted guest proc has no host reboot, raw kernel memory, kernel log
     * or global key inventory provider. Keep lookup and enumeration consistent;
     * never turn unrelated native permission failures into missing files. */
    return !strcmp(name,"sysrq-trigger") || !strcmp(name,"kcore")
        || !strcmp(name,"kmsg") || !strcmp(name,"keys");
}
int md_procfs_step(struct md_filesystem *fs,struct md_view_mount *mount,int fd,
        const char *name,const char *tail,int follow) {
    char path[PATH_MAX], mapped[32];
    int r=md_view_fdpath(fd,path,sizeof(path));
    if (r) return r;
    pid_t group=directory(path);
    if (group==-1 && kernel_global(name)) return -ENOENT;
    if (group==-1 && (!strcmp(name,"self") || !strcmp(name,"thread-self"))) {
        if (follow) {
            if (!fs->actor) return -ESRCH;
            pid_t native=!strcmp(name,"self") ? fs->actor->tgid : fs->actor->tid;
            if (!native || !visible(mount,native)) return -ENOENT;
            snprintf(mapped,sizeof(mapped),"%d",native); name=mapped;
        }
    } else if (group && mount->pid_namespace && decimal(name,NULL)) {
        struct md_pid_identity *id=md_pid_namespace_lookup(mount->pid_namespace,decimal(name,NULL));
        pid_t native=md_pid_identity_native(id);
        if (group>0 && md_pid_identity_group(id)!=group) native=0;
        md_pid_identity_release(id);
        if (!native) return -ENOENT;
        snprintf(mapped,sizeof(mapped),"%d",native); name=mapped;
    }
    struct md_inode_boundary *boundary=fs->store->boundary;
    int content=process_directory(path) && (!strcmp(name,"status") || !strcmp(name,"stat"));
    if ((control(path,name) || content) && boundary && boundary->path) {
        boundary->proc_namespace=md_pid_namespace_inode(mount->pid_namespace);
        int n=snprintf(boundary->path,boundary->capacity,"%s/%s%s",path,name,tail);
        if (n<0 || (size_t)n>=boundary->capacity) return -ENAMETOOLONG;
        /* Namespace-owned controls stay on the worker so their open
         * descriptions can retain the selected mount's live policy. */
        if (!fs->actor || !md_network_namespace_managed(fs->actor->network)
                || !md_proc_network_sysctl(md_proc_path_for(boundary->path,0,0).kind)) return -EREMOTE;
    }
    int next=openat(fd,name,O_PATH|O_NOFOLLOW|O_CLOEXEC);
    return next<0 ? -errno : next;
}
ssize_t md_procfs_readlink(struct md_filesystem *fs,const struct md_view_mount *mount,
        int fd,void *data,size_t capacity) {
    char path[PATH_MAX], value[64];
    int r=md_view_fdpath(fd,path,sizeof(path));
    if (r) return r;
    if (strcmp(path,"/proc/self") && strcmp(path,"/proc/thread-self")) {
        ssize_t n=readlinkat(fd,"",data,capacity); return n<0 ? -errno : n;
    }
    if (!fs->actor) return -ESRCH;
    pid_t group=visible(mount,fs->actor->tgid);
    if (!group) return -ENOENT;
    int n=!strcmp(path,"/proc/self") ? snprintf(value,sizeof(value),"%d",group)
        : snprintf(value,sizeof(value),"%d/task/%d",group,
            visible(mount,fs->actor->tid));
    size_t bytes=(size_t)n<capacity ? (size_t)n : capacity;
    memcpy(data,value,bytes); return (ssize_t)bytes;
}
ssize_t md_procfs_getdents(const struct md_view_mount *mount,int fd,void *data,size_t capacity) {
    char path[PATH_MAX];
    int error=md_view_fdpath(fd,path,sizeof(path));
    if (error) return error;
    pid_t group=directory(path);
    if (!group || (group>0 && !mount->pid_namespace)) {
        ssize_t n=syscall(SYS_getdents64,fd,data,capacity);
        return n<0 ? -errno : n;
    }
    /* Repack into caller storage: a namespace number may have more digits
     * than its native PID. The existing OFD turn owns cursor publication. */
    _Alignas(struct dirent) char input[4096];
    for (;;) {
        off_t cursor=lseek(fd,0,SEEK_CUR);
        if (cursor<0) return -errno;
        ssize_t n=syscall(SYS_getdents64,fd,input,capacity<sizeof(input) ? capacity : sizeof(input));
        if (n<0) return -errno;
        if (!n) return n;
        size_t read=0,written=0;
        while (read<(size_t)n) {
            struct dirent *entry=(struct dirent *)(input+read);
            if (entry->d_reclen<offsetof(struct dirent,d_name)+2 || entry->d_reclen>(size_t)n-read) return -EIO;
            size_t length=entry->d_reclen;
            char mapped[32]; const char *name=entry->d_name;
            pid_t native=mount->pid_namespace ? decimal(entry->d_name,NULL) : 0, number=0;
            if (native) {
                struct md_pid_identity *id=md_pid_namespace_find(mount->pid_namespace,native);
                if (md_pid_identity_group(id)==(group>0 ? group : native))
                    number=md_pid_identity_number(id,mount->pid_namespace);
                md_pid_identity_release(id);
                if (number) {
                    snprintf(mapped,sizeof(mapped),"%d",number); name=mapped;
                }
            }
            if ((!native || number) && !(group==-1 && kernel_global(name))) {
                size_t bytes=strlen(name)+1;
                size_t record=(offsetof(struct dirent,d_name)+bytes+7)&~(size_t)7;
                if (record>capacity-written) {
                    if (lseek(fd,cursor,SEEK_SET)<0) return -errno;
                    return written ? (ssize_t)written : -EINVAL;
                }
                struct dirent *out=(struct dirent *)((char *)data+written);
                memset(out,0,record);
                out->d_ino=entry->d_ino; out->d_off=entry->d_off;
                out->d_reclen=(unsigned short)record; out->d_type=entry->d_type;
                memcpy(out->d_name,name,bytes); written+=record;
            }
            cursor=entry->d_off;
            read+=length;
        }
        if (written) return (ssize_t)written;
        /* Kernel directory cookies advance while omitted entries are skipped;
         * the shared directory turn owns rollback until output publication. */
    }
}
