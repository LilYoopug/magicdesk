#define _GNU_SOURCE
#include "devpts_view.h"
#include "file_permissions.h"
#include "temporary_directory.h"
#include <stdatomic.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

/* Worker-owned directory membership. Kernel PTYs retain all terminal IO and
 * job-control semantics. No master/slave data FD is retained by this view. */
struct entry { struct entry *next; dev_t device; ino_t inode; unsigned number; uid_t uid; gid_t gid; mode_t mode; };
struct md_devpts {
    atomic_uint references;
    struct entry *entries;
    mode_t mode,ptmxmode;
    uid_t uid; gid_t gid;
    int fixed_uid,fixed_gid;
    int storage,root;
};
struct md_devpts *md_devpts_new(int parent,const char *options,const struct md_identity *id) {
    if (!id) { errno=EPERM; return NULL; }
    struct md_devpts *p=calloc(1,sizeof(*p)); if (!p) return NULL;
    atomic_init(&p->references,1); p->mode=0600; p->uid=id->uid.fs; p->gid=id->gid.fs;
    p->storage=p->root=-1;
    for (const char *at=options;at && *at;) {
        const char *end=strchr(at,','); if (!end) end=at+strlen(at);
        size_t n=(size_t)(end-at);
        if (n==11 && !memcmp(at,"newinstance",11)) { at=*end ? end+1 : end; continue; }
        const char *equal=memchr(at,'=',n);
        if (!equal || equal+1==end) { errno=EINVAL; goto failed; }
        unsigned key=(unsigned)(equal-at),base=10,value=0;
        int mode=key==4 && !memcmp(at,"mode",4),ptmx=key==8 && !memcmp(at,"ptmxmode",8);
        int uid=key==3 && !memcmp(at,"uid",3),gid=key==3 && !memcmp(at,"gid",3);
        if (!mode && !ptmx && !uid && !gid) { errno=EOPNOTSUPP; goto failed; }
        if (mode || ptmx) base=8;
        for (const char *digit=equal+1;digit<end;++digit) {
            unsigned d=(unsigned char)*digit-'0';
            if (d>=base || value>(UINT32_MAX-d)/base) { errno=EINVAL; goto failed; }
            value=value*base+d;
        }
        if (mode || ptmx) {
            if (value&~0777U) { errno=EINVAL; goto failed; }
            if (mode) p->mode=value; else p->ptmxmode=value;
        } else {
            value=md_user_namespace_into(id->user_namespace,gid,value);
            if (value==UINT32_MAX) { errno=EINVAL; goto failed; }
            if (uid) { p->uid=value; p->fixed_uid=1; } else { p->gid=value; p->fixed_gid=1; }
        }
        at=*end ? end+1 : end;
    }
    p->storage=md_temporary_directory_new(parent);
    if (p->storage<0) { errno=-p->storage; goto failed; }
    if (mkdirat(p->storage,"pts",0700)) goto failed;
    p->root=openat(p->storage,"pts",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (p->root<0) goto failed;
    int node=openat(p->root,"ptmx",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
    if (node<0) goto failed;
    close(node); return p;
failed:
    { int error=errno;
      if (p->root>=0) close(p->root);
      if (p->storage>=0) md_temporary_directory_release(p->storage);
      free(p); errno=error; return NULL; }
}
int md_devpts_root(struct md_devpts *p) { return p->root; }
struct md_devpts *md_devpts_retain(struct md_devpts *p) {
    if (p) atomic_fetch_add_explicit(&p->references,1,memory_order_relaxed); return p;
}
void md_devpts_release(struct md_devpts *p) {
    if (!p || atomic_fetch_sub_explicit(&p->references,1,memory_order_acq_rel)!=1) return;
    while (p->entries) { struct entry *e=p->entries; p->entries=e->next; free(e); }
    close(p->root); md_temporary_directory_release(p->storage); free(p);
}
static int ptmx(const struct stat *st) { return S_ISCHR(st->st_mode) && major(st->st_rdev)==5 && minor(st->st_rdev)==2; }
static struct entry *find(struct md_devpts *p,const struct stat *st) {
    for (struct entry *e=p->entries;e;e=e->next) if (e->device==st->st_dev && e->inode==st->st_ino) return e;
    return NULL;
}
int md_devpts_name(struct md_devpts *p,int fd,char *name,size_t size) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    struct entry *e=find(p,&st);
    int n=S_ISDIR(st.st_mode) ? snprintf(name,size,".") : ptmx(&st) ? snprintf(name,size,"ptmx")
        : e ? snprintf(name,size,"%u",e->number) : -1;
    return n<0 ? -ENOENT : (size_t)n>=size ? -ENAMETOOLONG : 0;
}
int md_devpts_stat(struct md_devpts *p,int fd,struct stat *st) {
    if (!p) return -EINVAL;
    if (fstat(fd,st)) return -errno;
    if (S_ISDIR(st->st_mode)) { st->st_mode=S_IFDIR|0755; st->st_uid=p->uid; st->st_gid=p->gid; return 0; }
    if (ptmx(st)) { st->st_mode=S_IFCHR|p->ptmxmode; st->st_uid=p->uid; st->st_gid=p->gid; return 0; }
    struct entry *e=find(p,st); if (!e) return -ENOENT;
    st->st_mode=S_IFCHR|e->mode; st->st_uid=e->uid; st->st_gid=e->gid; return 0;
}
int md_devpts_access(struct md_devpts *p,int fd,int mode,const struct md_identity *id) {
    struct stat st; int r=md_devpts_stat(p,fd,&st); return r ? r : md_file_permissions(&st,mode,id);
}
int md_devpts_step(struct md_devpts *p,int directory,const char *name) {
    struct stat directory_stat;
    if (fstat(directory,&directory_stat)) return -errno;
    if (!S_ISDIR(directory_stat.st_mode)) return -ENOTDIR;
    if (strchr(name,'/')) return -EINVAL;
    int fd;
    if (!strcmp(name,".") || !strcmp(name,"..")) fd=openat(p->root,".",O_PATH|O_DIRECTORY|O_CLOEXEC);
    else if (!strcmp(name,"ptmx")) fd=open("/dev/ptmx",O_PATH|O_CLOEXEC);
    else {
        struct entry *e=p->entries;
        char number[32];
        for (;e;e=e->next) { snprintf(number,sizeof(number),"%u",e->number); if (!strcmp(name,number)) break; }
        if (!e) return -ENOENT;
        char path[64]; snprintf(path,sizeof(path),"/dev/pts/%u",e->number);
        fd=open(path,O_PATH|O_NOFOLLOW|O_CLOEXEC);
        struct stat st;
        if (fd>=0 && (fstat(fd,&st) || st.st_dev!=e->device || st.st_ino!=e->inode)) { close(fd); return -ENOENT; }
    }
    if (fd<0) return -errno;
    struct stat st; int r=md_devpts_stat(p,fd,&st);
    if (r) close(fd); return r ? r : fd;
}
int md_devpts_open(struct md_devpts *p,int fd,int flags,const struct md_identity *id) {
    struct stat st; int r=md_devpts_stat(p,fd,&st); if (r) return r;
    if (!(flags&O_PATH)) {
        r=md_file_permissions(&st,(flags&O_ACCMODE)==O_RDWR ? R_OK|W_OK : (flags&O_ACCMODE)==O_WRONLY ? W_OK : R_OK,id);
        if (r) return r;
    }
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    int opened=open(path,(flags&~O_NOFOLLOW)|O_CLOEXEC); if (opened<0) return -errno;
    if (!(flags&O_PATH) && ptmx(&st)) {
        unsigned number;
        if (ioctl(opened,TIOCGPTN,&number)) { r=-errno; goto failed; }
        snprintf(path,sizeof(path),"/dev/pts/%u",number);
        struct stat slave;
        if (stat(path,&slave)) { r=-errno; goto failed; }
        struct entry *e=p->entries;
        while (e && e->number!=number) e=e->next;
        if (!e) {
            e=calloc(1,sizeof(*e)); if (!e) { r=-ENOMEM; goto failed; }
            e->next=p->entries; p->entries=e;
        }
        e->number=number; e->device=slave.st_dev; e->inode=slave.st_ino;
        e->uid=p->fixed_uid ? p->uid : id->uid.fs; e->gid=p->fixed_gid ? p->gid : id->gid.fs; e->mode=p->mode;
        char name[32]; snprintf(name,sizeof(name),"%u",number);
        int node=openat(p->root,name,O_CREAT|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
        if (node<0) { r=-errno; goto failed; }
        close(node);
    }
    return opened;
failed:
    close(opened); return r;
}
int md_devpts_chmod(struct md_devpts *p,int fd,mode_t mode,const struct md_identity *id) {
    struct stat st; int r=md_devpts_stat(p,fd,&st); if (r) return r;
    if (id->uid.fs!=st.st_uid && !md_identity_file_capable(id,st.st_uid,st.st_gid,CAP_FOWNER)) return -EPERM;
    if (S_ISDIR(st.st_mode)) return -EOPNOTSUPP;
    if (ptmx(&st)) p->ptmxmode=mode&0777; else find(p,&st)->mode=mode&0777;
    return 0;
}
int md_devpts_chown(struct md_devpts *p,int fd,uint32_t uid,uint32_t gid,const struct md_identity *id) {
    struct stat st; int r=md_devpts_stat(p,fd,&st); if (r) return r;
    if (uid==UINT32_MAX) uid=st.st_uid;
    if (gid==UINT32_MAX) gid=st.st_gid;
    if (!md_identity_file_capable(id,st.st_uid,st.st_gid,CAP_CHOWN)
            && !(id->uid.fs==st.st_uid && uid==st.st_uid && (gid==st.st_gid || md_identity_in_group(id,gid)))) return -EPERM;
    if (S_ISDIR(st.st_mode) || ptmx(&st)) return -EOPNOTSUPP;
    struct entry *e=find(p,&st); e->uid=uid; e->gid=gid; return 0;
}
ssize_t md_devpts_getdents(struct md_devpts *p,int fd,void *data,size_t capacity) {
    for (;;) {
        ssize_t n=syscall(SYS_getdents64,fd,data,capacity); if (n<=0) return n<0 ? -errno : 0;
        size_t read=0,written=0;
        while (read<(size_t)n) {
            struct dirent *e=(void *)((char *)data+read);
            if (e->d_reclen<offsetof(struct dirent,d_name)+2 || e->d_reclen>(size_t)n-read) return -EIO;
            size_t size=e->d_reclen;
            int next=md_devpts_step(p,fd,e->d_name);
            if (next>=0) {
                struct stat st;
                if (fstat(next,&st)) { int error=-errno; close(next); return error; }
                close(next); e->d_ino=st.st_ino; e->d_type=S_ISDIR(st.st_mode) ? DT_DIR : DT_CHR;
                memmove((char *)data+written,e,size); written+=size;
            }
            else if (next!=-ENOENT) return next;
            read+=size;
        }
        if (written) return (ssize_t)written;
    }
}
