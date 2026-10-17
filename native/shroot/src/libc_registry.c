#define _GNU_SOURCE
#include "libc_registry.h"
#include "cooperative_entry.h"
#include "image_io.h"
#include "image_publish.h"
#include "private_tree.h"
#include "elf.h"
#include "raw.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <unistd.h>

struct entry { struct md_libc_manifest manifest; struct stat identity; int lease; };
struct cached_hash { struct stat identity; char hash[65]; int watch; };
struct md_libc_registry {
    int root, notifier, root_watch;
    struct stat generation;
    unsigned count, cursor;
    struct entry entries[MD_LIBC_REGISTRY_LIMIT];
    struct cached_hash hashes[64];
};
static int hex(const char *s) { return strlen(s)==64 && strspn(s,"0123456789abcdef")==64; }
static int path(const char *s,int absolute) {
    if (!*s || (*s=='/')!=absolute || strchr(s,'\n') || strchr(s,'\r')) return 0;
    for (const char *p=s+absolute; *p;) {
        const char *end=strchr(p,'/'); size_t n=end ? (size_t)(end-p) : strlen(p);
        if (!n || (n==1 && *p=='.') || (n==2 && !memcmp(p,"..",2))) return 0;
        p+=n; if (*p) ++p;
    }
    return s[strlen(s)-1]!='/';
}
static int same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size
        && a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec
        && a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static int file_hash(int fd,char hash[65],struct stat *identity) {
    struct stat before,after;
    if (fstat(fd,&before)) return -errno;
    if (!S_ISREG(before.st_mode) || before.st_size<=0 || before.st_size>MD_LIBC_FILE_LIMIT) return -EFBIG;
    int r=md_image_hash(fd,(uint64_t)before.st_size,hash);
    if (!r && fstat(fd,&after)) r=-errno;
    if (!r && !same(&before,&after)) r=-ESTALE;
    if (!r && identity) *identity=after;
    return r;
}
static int watch_fd(int notifier,int fd,uint32_t mask) {
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    return inotify_add_watch(notifier,path,mask);
}
static void watch_events(struct md_libc_registry *r) {
    /* f2fs timestamps can coincide for two writes in one tick. Invalidation
     * comes from the kernel, not timestamp resolution or a freshness timer. */
    if (r && r->notifier>=0) {
        char events[4096] __attribute__((aligned(8)));
        for (;;) {
            ssize_t size=read(r->notifier,events,sizeof(events));
            if (size<0 && errno==EINTR) continue;
            if (size<=0) {
                if (!size || (errno!=EAGAIN && errno!=EWOULDBLOCK)) {
                    close(r->notifier); r->notifier=-2;
                }
                break;
            }
            for (size_t at=0;at<(size_t)size;) {
                const struct inotify_event *event=(const void *)(events+at);
                if ((event->mask&IN_Q_OVERFLOW) || event->wd==r->root_watch)
                    memset(&r->generation,0,sizeof(r->generation));
                if (event->wd==r->root_watch && (event->mask&IN_IGNORED)) r->root_watch=-1;
                for (unsigned i=0;i<64;++i) {
                    if ((event->mask&IN_Q_OVERFLOW) || r->hashes[i].watch==event->wd) r->hashes[i].hash[0]=0;
                    if (r->hashes[i].watch==event->wd && (event->mask&IN_IGNORED)) r->hashes[i].watch=-1;
                }
                at+=sizeof(*event)+event->len;
            }
        }
    }
}
int md_libc_registry_hash(struct md_libc_registry *r,int fd,char hash[65]) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    watch_events(r);
    if (r && r->notifier>=0) for (unsigned i=0;i<64;++i) if (r->hashes[i].hash[0] && same(&st,&r->hashes[i].identity)) {
        memcpy(hash,r->hashes[i].hash,65); return 0;
    }
    struct cached_hash *h=NULL;
    if (r && r->notifier>=0) {
        for (unsigned i=0;i<64;++i) if (r->hashes[i].identity.st_dev==st.st_dev
                && r->hashes[i].identity.st_ino==st.st_ino) { h=&r->hashes[i]; break; }
        if (!h) h=&r->hashes[r->cursor++%64];
        if (h->watch>=0) inotify_rm_watch(r->notifier,h->watch);
        h->hash[0]=0;
        h->watch=watch_fd(r->notifier,fd,IN_MODIFY|IN_ATTRIB|IN_DELETE_SELF|IN_MOVE_SELF);
        if (h->watch<0) h=NULL;
    }
    int error=file_hash(fd,hash,&st);
    if (!error && h) { h->identity=st; memcpy(h->hash,hash,65); }
    return error;
}
int md_libc_manifest_read(int root,struct md_libc_manifest *m) {
    memset(m,0,sizeof(*m));
    int fd=openat(root,"manifest",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -errno;
    char *text=NULL; int r=md_image_read(fd,4096,&text);
    /* Hash precisely the admitted bytes, not a second read of a mutable builder file. */
    if (!r) r=md_image_hash_bytes(text,strlen(text),m->key);
    close(fd);
    if (r) { free(text); return r; }
    char *at=text,*fields[10];
    for (unsigned i=0;i<10;++i) {
        fields[i]=at; char *end=strchr(at,'\n');
        if (!end) { r=-EINVAL; break; }
        *end=0; at=end+1;
    }
    if (!r && (*at || strcmp(fields[0],"shroot-libc-1"))) r=-EINVAL;
    if (!r) {
        char *end; errno=0;
        unsigned long abi=strtoul(fields[1],&end,10);
        if (errno || !*fields[1] || *end || !abi || abi>UINT32_MAX
                || strspn(fields[1],"0123456789")!=strlen(fields[1])) r=-EINVAL;
        else m->abi=(unsigned)abi;
    }
    if (!r && (strcmp(fields[2],"musl") && strcmp(fields[2],"glibc"))) r=-EINVAL;
    if (!r && (!*fields[3] || strspn(fields[3],"0123456789.-abcdefghijklmnopqrstuvwxyz")!=strlen(fields[3])
            || !hex(fields[4]) || !path(fields[5],1) || !path(fields[6],1)
            || !hex(fields[7]) || !hex(fields[8]) || !path(fields[9],0))) r=-EINVAL;
    char *dest[]={m->family,m->version,m->recipe,m->interpreter,m->libc,
        m->interpreter_hash,m->libc_hash,m->loader};
    size_t sizes[]={sizeof(m->family),sizeof(m->version),sizeof(m->recipe),sizeof(m->interpreter),
        sizeof(m->libc),sizeof(m->interpreter_hash),sizeof(m->libc_hash),sizeof(m->loader)};
    for (unsigned i=0;!r && i<8;++i) {
        if (strlen(fields[i+2])>=sizes[i]) r=-ENAMETOOLONG;
        else strcpy(dest[i],fields[i+2]);
    }
    free(text); return r;
}
void md_libc_registry_close(struct md_libc_registry *r) {
    if (!r) return;
    for (unsigned i=0;i<r->count;++i) if (r->entries[i].lease>=0) close(r->entries[i].lease);
    if (r->root>=0) close(r->root);
    if (r->notifier>=0) close(r->notifier);
    free(r);
}
int md_libc_registry_open(const char *path,struct md_libc_registry **out) {
    *out=NULL;
    if (!path || !*path) return 0;
    if (*path!='/') return -EINVAL;
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return errno==ENOENT ? 0 : -errno;
    struct md_libc_registry *r=calloc(1,sizeof(*r));
    if (!r) { close(fd); return -ENOMEM; }
    r->root=fd;
    r->notifier=inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
    r->root_watch=r->notifier<0 ? -1 : watch_fd(r->notifier,fd,IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE_SELF);
    for (unsigned i=0;i<64;++i) r->hashes[i].watch=-1;
    int error=md_libc_registry_refresh(r);
    if (error) md_libc_registry_close(r); else *out=r;
    return error;
}
static int newest(const void *a,const void *b) {
    const struct entry *left=a,*right=b;
    if (left->identity.st_ctim.tv_sec!=right->identity.st_ctim.tv_sec)
        return left->identity.st_ctim.tv_sec>right->identity.st_ctim.tv_sec ? -1 : 1;
    if (left->identity.st_ctim.tv_nsec!=right->identity.st_ctim.tv_nsec)
        return left->identity.st_ctim.tv_nsec>right->identity.st_ctim.tv_nsec ? -1 : 1;
    return strcmp(left->manifest.key,right->manifest.key);
}
int md_libc_registry_refresh(struct md_libc_registry *r) {
    if (!r) return 0;
    watch_events(r);
    struct stat generation;
    if (fstat(r->root,&generation)) return -errno;
    if (r->notifier>=0 && r->root_watch>=0 && same(&generation,&r->generation)) return 0;
    /* An offline pruner/publisher cannot block guest exec. Keep the previous
     * admitted set while its short directory transaction is in progress. */
    if (flock(r->root,LOCK_SH|LOCK_NB)) return -errno;
    unsigned kept=0;
    for (unsigned i=0;i<r->count;++i) if (r->entries[i].lease>=0) r->entries[kept++]=r->entries[i];
    r->count=kept;
    int copy=openat(r->root,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    DIR *dir=copy<0 ? NULL : fdopendir(copy);
    int error=dir ? 0 : -errno;
    if (!dir && copy>=0) close(copy);
    while (!error && dir) {
        errno=0; struct dirent *e=readdir(dir);
        if (!e) { if (errno) error=-errno; break; }
        if (!hex(e->d_name)) continue;
        int found=0;
        for (unsigned i=0;i<kept;++i) if (!strcmp(r->entries[i].manifest.key,e->d_name)) { found=1; break; }
        if (found) continue;
        if (r->count==MD_LIBC_REGISTRY_LIMIT) { error=-E2BIG; break; }
        int bundle=openat(r->root,e->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (bundle<0) {
            if (errno==ENOENT || errno==ELOOP || errno==ENOTDIR || errno==EACCES) continue;
            error=-errno; break;
        }
        struct entry *entry=&r->entries[r->count]; entry->lease=-1;
        int result=md_libc_manifest_read(bundle,&entry->manifest);
        if (!result && strcmp(entry->manifest.key,e->d_name)) result=-EBADMSG;
        if (!result && fstat(bundle,&entry->identity)) result=-errno;
        close(bundle);
        /* One broken optional artifact must not disable independent builds. */
        if (result) continue;
        ++r->count;
    }
    if (dir) closedir(dir);
    qsort(r->entries,r->count,sizeof(r->entries[0]),newest);
    if (!error) r->generation=generation;
    flock(r->root,LOCK_UN);
    return error;
}
unsigned md_libc_registry_count(const struct md_libc_registry *r) { return r ? r->count : 0; }
const struct md_libc_manifest *md_libc_registry_entry(const struct md_libc_registry *r,unsigned i) {
    return r && i<r->count ? &r->entries[i].manifest : NULL;
}
int md_libc_registry_claim(struct md_libc_registry *r,unsigned i) {
    if (!r || i>=r->count) return -EINVAL;
    struct entry *e=&r->entries[i];
    if (e->lease>=0) return e->lease;
    int fd=openat(r->root,e->manifest.key,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -errno;
    int error=flock(fd,LOCK_SH|LOCK_NB) ? -errno : 0;
    struct stat st,named;
    if (!error && (fstat(fd,&st) || fstatat(r->root,e->manifest.key,&named,AT_SYMLINK_NOFOLLOW))) error=-errno;
    if (!error && (st.st_dev!=e->identity.st_dev || st.st_ino!=e->identity.st_ino
            || st.st_dev!=named.st_dev || st.st_ino!=named.st_ino)) error=-ESTALE;
    if (error) { close(fd); return error; }
    e->lease=fd; return fd;
}

/* Copy, never rename the builder's writable tree: retained builder descriptors
 * must not be able to mutate published artifacts. No hardlink support required. */
static int copy_tree(int source,int target,unsigned depth,unsigned *entries,uint64_t *bytes) {
    if (depth>16) return -ELOOP;
    int fd=openat(source,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) return -errno;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    int r=0;
    for (;;) {
        errno=0; struct dirent *e=readdir(dir);
        if (!e) { if (errno) r=-errno; break; }
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        if (++*entries>4096) { r=-E2BIG; break; }
        struct stat st;
        if (fstatat(source,e->d_name,&st,AT_SYMLINK_NOFOLLOW)) { r=-errno; break; }
        if (S_ISDIR(st.st_mode)) {
            if (mkdirat(target,e->d_name,0700)) { r=-errno; break; }
            int from=openat(source,e->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            int to=openat(target,e->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            r=from<0 || to<0 ? -errno : copy_tree(from,to,depth+1,entries,bytes);
            if (!r && (fchmod(to,0555) || fsync(to))) r=-errno;
            if (from>=0) close(from);
            if (to>=0) close(to);
        } else if (S_ISREG(st.st_mode)) {
            if (st.st_size<0 || st.st_size>MD_LIBC_FILE_LIMIT || (*bytes+=(uint64_t)st.st_size)>512*1024*1024) { r=-EFBIG; break; }
            int from=openat(source,e->d_name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
            int to=openat(target,e->d_name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
            r=from<0 || to<0 ? -errno : 0;
            struct stat opened,after;
            if (!r && fstat(from,&opened)) r=-errno;
            if (!r && !same(&st,&opened)) r=-ESTALE;
            char buffer[65536];
            for (off_t offset=0;!r && offset<st.st_size;) {
                size_t n=st.st_size-offset>(off_t)sizeof(buffer) ? sizeof(buffer) : (size_t)(st.st_size-offset);
                ssize_t got=pread(from,buffer,n,offset);
                if (got<0 && errno==EINTR) continue;
                if (got<=0) { r=got<0 ? -errno : -ESTALE; break; }
                r=md_image_write(to,buffer,(size_t)got); offset+=got;
            }
            if (!r && fstat(from,&after)) r=-errno;
            if (!r && !same(&opened,&after)) r=-ESTALE;
            if (!r && (fchmod(to,(st.st_mode&0111) ? 0555 : 0444) || fsync(to))) r=-errno;
            if (from>=0) close(from);
            if (to>=0) close(to);
        } else r=-EINVAL; /* Builder exports dereferenced runtime libraries only. */
        if (r) break;
    }
    closedir(dir); return r;
}
int md_libc_registry_publish(const char *root,const char *candidate) {
    /* Offline image tools do not enter the bootstrap's raw-runtime startup. */
    if (!md_page_size) md_page_size=(size_t)sysconf(_SC_PAGESIZE);
    if (!root || *root!='/' || !candidate || *candidate!='/') return -EINVAL;
    if (mkdir(root,0700) && errno!=EEXIST) return -errno;
    int source=open(candidate,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (source<0) return -errno;
    struct md_libc_manifest manifest;
    int r=md_libc_manifest_read(source,&manifest);
    if (!r && manifest.abi!=MD_ENTRY_VERSION) r=-EPROTONOSUPPORT;
    char destination[4096];
    if (!r && snprintf(destination,sizeof(destination),"%s/%s",root,manifest.key)>=(int)sizeof(destination)) r=-ENAMETOOLONG;
    struct md_image_publish publish={.parent=-1,.stage=-1};
    if (!r) r=md_image_publish_begin(destination,&publish);
    int target=-1;
    if (!r && mkdir(publish.path,0700)) r=-errno;
    if (!r && (target=open(publish.path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC))<0) r=-errno;
    unsigned entries=0; uint64_t bytes=0;
    if (!r) r=copy_tree(source,target,0,&entries,&bytes);
    struct md_libc_manifest copied;
    if (!r) r=md_libc_manifest_read(target,&copied);
    if (!r && strcmp(copied.key,manifest.key)) r=-ESTALE;
    int loader=-1;
    if (!r && (loader=openat(target,manifest.loader,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC))<0) r=-errno;
    struct stat st;
    if (!r && (fstat(loader,&st) || !S_ISREG(st.st_mode) || !(st.st_mode&0111))) r=-EINVAL;
    if (!r) r=md_elf_validate(loader,1);
    if (loader>=0) close(loader);
    /* Renaming a directory across parents needs owner write permission for
     * '..'. Guest publication is readonly; runtime files remain 0444/0555. */
    if (!r && (fchmod(target,0755) || fsync(target))) r=-errno;
    if (!r) r=md_image_publish_commit(&publish);
    if (target>=0) close(target);
    md_image_publish_close(&publish); close(source);
    if (!r) puts(manifest.key);
    return r;
}
int md_libc_registry_list(const char *root) {
    struct md_libc_registry *r=NULL;
    int error=md_libc_registry_open(root,&r);
    for (unsigned i=0;!error && i<md_libc_registry_count(r);++i) {
        const struct md_libc_manifest *m=md_libc_registry_entry(r,i);
        if (printf("%s\t%s\t%s\t%s\n",m->key,m->family,m->version,m->interpreter)<0) error=-EIO;
    }
    md_libc_registry_close(r); return error;
}
int md_libc_registry_prune(const char *root) {
    int fd=open(root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return errno==ENOENT ? 0 : -errno;
    /* EVENT_WAIT: offline registry mutation lock; cancellation interrupts it. */
    if (flock(fd,LOCK_EX)) { int r=-errno; close(fd); return r; }
    int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    DIR *dir=copy<0 ? NULL : fdopendir(copy);
    int r=dir ? 0 : -errno;
    if (!dir && copy>=0) close(copy);
    while (!r && dir) {
        errno=0; struct dirent *e=readdir(dir);
        if (!e) { if (errno) r=-errno; break; }
        if (!hex(e->d_name)) continue;
        int bundle=openat(fd,e->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (bundle<0) { if (errno==ENOENT) continue; r=-errno; break; }
        if (flock(bundle,LOCK_EX|LOCK_NB)) {
            if (errno!=EWOULDBLOCK) r=-errno;
            close(bundle); continue;
        }
        struct stat a,b;
        if (fstat(bundle,&a) || fstatat(fd,e->d_name,&b,AT_SYMLINK_NOFOLLOW)) r=-errno;
        else if (a.st_ino!=b.st_ino || a.st_dev!=b.st_dev) r=-ESTALE;
        if (!r) r=md_private_tree_discard(fd,e->d_name);
        close(bundle);
    }
    if (dir) closedir(dir);
    if (!r && fsync(fd)) r=-errno;
    close(fd); return r;
}
