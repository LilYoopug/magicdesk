#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <unistd.h>

static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++n;
    closedir(dir); return n;
}
static struct md_fs_result request(struct md_filesystem *fs, const struct md_fs_anchor *origin,
        int fd, unsigned op, const char *path, unsigned flags, uint64_t resolve, struct md_fs_anchor **capture) {
    struct md_fs_request q={.operation=op,.directory={fd,-1},.origin={origin,NULL},
        .path={path,NULL},.flags=flags,.resolve=resolve,.mode=op==MD_FS_FSTAT ? MD_FS_STAT_MOUNT : 0};
    struct md_fs_result out;
    struct md_fs_output output={.origin=capture};
    md_fs_execute(fs,&q,&out,&output); return out;
}
static struct md_fs_anchor *anchor(struct md_filesystem *fs, const char *path) {
    struct md_fs_anchor *p=NULL;
    struct md_fs_result r=request(fs,NULL,-1,MD_FS_OPEN,path,O_PATH,0,&p);
    assert(!r.error && r.fd>=0 && p); close(r.fd); return p;
}
static struct md_fs_result relative(struct md_filesystem *fs, const struct md_fs_anchor *base,
        const char *path, unsigned flags, uint64_t resolve, struct md_fs_anchor **capture) {
    return request(fs,base,md_fs_anchor_fd(base),MD_FS_OPEN,path,flags,resolve,capture);
}
static void opens(struct md_filesystem *fs, const struct md_fs_anchor *base,
        const char *path, unsigned flags, uint64_t resolve, int error) {
    struct md_fs_result r=relative(fs,base,path,flags,resolve,NULL);
    if (r.error!=error) fprintf(stderr,"anchor open %s flags=%u resolve=%llu: %d expected %d\n",
        path,flags,(unsigned long long)resolve,r.error,error);
    assert(r.error==error);
    if (!error) { assert(r.fd>=0); close(r.fd); } else assert(r.fd==-1);
}
static void contents(const char *path) {
    int fd=open(path,O_CREAT|O_RDWR|O_CLOEXEC,0600); assert(fd>=0);
    assert(write(fd,"value",5)==5); close(fd);
}
static void capture_failure(struct md_filesystem *fs) {
    unsigned before=descriptors();
    int stream[2]; assert(!pipe2(stream,O_CLOEXEC));
    int pin=stream[0], control=stream[1];
    struct rlimit original; assert(!getrlimit(RLIMIT_NOFILE,&original));
    struct rlimit limited=original; if (limited.rlim_cur>256) limited.rlim_cur=256;
    assert(!setrlimit(RLIMIT_NOFILE,&limited));
    int held[256]; unsigned count=0;
    for (;;) {
        int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
        if (fd<0) { assert(errno==EMFILE); break; }
        assert(count<256); held[count++]=fd;
    }
    struct md_fs_anchor *p=NULL;
    struct md_fs_output output={.origin=&p};
    struct md_fs_result out={.fd=pin,.open_completion={MD_OPEN_PIPE,control}};
    md_view_capture(fs,fs->mounts,NULL,&out,&output);
    assert(out.error==-EMFILE && out.fd==-1 && !p && out.open_completion.kind==MD_OPEN_READY);
    assert(fcntl(pin,F_GETFD)<0 && errno==EBADF);
    assert(fcntl(control,F_GETFD)<0 && errno==EBADF);
    while (count) close(held[--count]);
    assert(!setrlimit(RLIMIT_NOFILE,&original));
    assert(descriptors()==before);
}
static void empty_views(struct md_inode_store *s) {
    struct md_filesystem fs={.store=s}, copy={.store=s};
    struct md_fs_location root={0}, selected;
    assert(!md_fs_mounts_open(&fs,NULL,0));
    assert(!md_fs_mounts_copy(&fs,&root,&copy.mounts,&selected));
    struct md_fs_anchor *base=anchor(&fs,"/"), *fifo=NULL, *second=NULL;
    assert(!md_inode_mkfifo(s,-1,"/stream",0600));
    int flags=O_RDONLY|O_NONBLOCK|O_CLOEXEC;
    struct md_fs_result r=relative(&copy,base,"stream",flags,0,&fifo);
    assert(!r.error && fifo && r.open_completion.kind==MD_OPEN_PIPE);
    int reader=md_complete_open(r.fd,flags,r.open_completion); assert(reader>=0);
    r=request(&copy,fifo,reader,MD_FS_FSTAT,NULL,0,0,NULL);
    assert(!r.error && S_ISFIFO(r.info.mode) && r.info.mount_id==fs.mounts->root_id);
    flags=O_WRONLY|O_NONBLOCK|O_CLOEXEC;
    r=request(&copy,fifo,reader,MD_FS_REOPEN,NULL,flags,0,&second);
    assert(!r.error && second && r.open_completion.kind==MD_OPEN_PIPE);
    int writer=md_complete_open(r.fd,flags,r.open_completion); assert(writer>=0);
    assert(write(writer,"x",1)==1); char byte; assert(read(reader,&byte,1)==1 && byte=='x');
    close(writer); assert(read(reader,&byte,1)==0); close(reader);
    md_fs_anchor_release(second); md_fs_anchor_release(fifo);
    capture_failure(&fs);
    md_fs_anchor_release(base); md_fs_mounts_close(&copy); md_fs_mounts_close(&fs);
}
void test_fs_anchor(const char *base) {
    unsigned before=descriptors();
    char store[PATH_MAX],host[2][PATH_MAX],path[PATH_MAX],next[PATH_MAX];
    snprintf(store,sizeof(store),"%s/anchor-store",base);
    for (unsigned i=0; i<2; ++i) {
        snprintf(host[i],sizeof(host[i]),"%s/anchor-source-%u",base,i); assert(!mkdir(host[i],0700));
        snprintf(path,sizeof(path),"%s/value",host[i]); contents(path);
    }
    snprintf(path,sizeof(path),"%s/child",host[0]); assert(!mkdir(path,0700));
    snprintf(path,sizeof(path),"%s/relative",host[0]); assert(!symlink("child/value",path));
    snprintf(path,sizeof(path),"%s/absolute",host[0]); assert(!symlink("/mnt/child/value",path));
    snprintf(path,sizeof(path),"%s/confined",host[0]); assert(!symlink("/child/value",path));
    struct md_inode_store *s; assert(!md_inode_store_open(store,1,&s));
    assert(!md_inode_mkdir(s,-1,"/mnt",0700)); assert(!md_inode_mkdir(s,-1,"/jail",0700));
    struct md_filesystem original={.store=s}, current={.store=s};
    struct md_fs_attachment entries[]={{host[0],"/mnt",0},{host[1],"/mnt/child",1}};
    assert(!md_fs_mounts_open(&original,entries,2));
    struct md_fs_location root={0},rebased;
    assert(!md_fs_mounts_copy(&original,&root,&current.mounts,&rebased));
    current.mounts->tree->mounts[0].readonly=1;
    current.mounts->tree->mounts[1].readonly=0;
    struct md_fs_anchor *old_root=anchor(&original,"/"), *old=anchor(&original,"/mnt");
    struct md_fs_anchor *old_child=anchor(&original,"/mnt/child"), *new=anchor(&current,"/mnt");
    opens(&current,old,"value",O_RDWR,0,0);
    opens(&current,new,"value",O_RDWR,0,-EROFS);
    opens(&current,old,"child/value",O_RDWR,0,-EROFS);
    opens(&current,new,"child/value",O_RDWR,0,0);
    opens(&current,old_root,"mnt/child/value",O_RDWR,0,-EROFS);
    opens(&current,old_child,"../value",O_RDWR,0,0);
    opens(&current,old_child,"../../mnt/child/value",O_RDWR,0,-EROFS);
    opens(&current,old,"relative",O_RDWR,0,-EROFS);
    opens(&current,old,"absolute",O_RDWR,0,0);
    opens(&current,old,"/mnt/child/value",O_RDWR,0,0);
    opens(&current,old,"absolute",O_RDONLY,RESOLVE_BENEATH,-EXDEV);
    opens(&current,old,"absolute",O_RDONLY,RESOLVE_NO_XDEV,-EXDEV);
    opens(&current,old_child,"../value",O_RDONLY,RESOLVE_NO_XDEV,-EXDEV);
    opens(&current,old,"confined",O_RDWR,RESOLVE_IN_ROOT,-EROFS);
    opens(&current,old,"/child/value",O_RDWR,RESOLVE_IN_ROOT,-EROFS);
    opens(&current,old,"confined",O_RDONLY,RESOLVE_IN_ROOT|RESOLVE_NO_XDEV,-EXDEV);
    opens(&current,old,"../value",O_RDONLY,RESOLVE_IN_ROOT,0);
    opens(&current,old,"relative",O_RDONLY,RESOLVE_NO_SYMLINKS,-ELOOP);
    /* Resetting a link to another mount is a crossing even within one view. */
    opens(&original,old,"absolute",O_RDONLY,RESOLVE_NO_XDEV,-EXDEV);

    struct md_fs_anchor *file=NULL,*copied=NULL;
    struct md_fs_result r=relative(&current,old,"value",O_RDWR,0,&file); assert(!r.error && file);
    int data=r.fd, duplicate=dup(data); assert(duplicate>=0);
    r=request(&current,file,duplicate,MD_FS_FSTAT,NULL,0,0,NULL);
    assert(!r.error && r.info.mount_id==original.mounts->tree->mounts[0].id);
    r=request(&current,file,duplicate,MD_FS_REOPEN,NULL,O_RDONLY,0,&copied);
    assert(!r.error && copied); close(r.fd);
    r=request(&current,copied,md_fs_anchor_fd(copied),MD_FS_FSTAT,NULL,0,0,NULL);
    assert(!r.error && r.info.mount_id==original.mounts->tree->mounts[0].id);
    md_fs_anchor_release(copied);
    r=relative(&current,old,"absolute",O_RDONLY,0,&copied); assert(!r.error && copied);
    struct md_fs_result metadata=request(&current,copied,r.fd,MD_FS_FSTAT,NULL,0,0,NULL);
    assert(!metadata.error && metadata.info.mount_id==current.mounts->tree->mounts[1].id);
    close(r.fd); md_fs_anchor_release(copied);
    /* Reused descriptor numbers cannot silently select another inode. */
    assert(dup2(md_fs_anchor_fd(old_child),duplicate)==duplicate);
    r=request(&current,file,duplicate,MD_FS_FSTAT,NULL,0,0,NULL); assert(r.error==-ESTALE);
    close(duplicate);
    snprintf(path,sizeof(path),"%s/value",host[0]);
    int other=open(path,O_RDWR|O_CLOEXEC); assert(other>=0);
    assert(!flock(data,LOCK_EX|LOCK_NB));
    assert(flock(other,LOCK_EX|LOCK_NB)<0 && errno==EWOULDBLOCK);
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_len=1};
    assert(!fcntl(data,F_OFD_SETLK,&lock));
    assert(fcntl(other,F_OFD_SETLK,&lock)<0 && (errno==EAGAIN || errno==EACCES));
    close(data); assert(!flock(other,LOCK_EX|LOCK_NB) && !fcntl(other,F_OFD_SETLK,&lock)); close(other);
    r=request(&current,file,md_fs_anchor_fd(file),MD_FS_REOPEN,NULL,O_RDWR,0,NULL);
    assert(!r.error); close(r.fd);

    struct md_fs_request pair={.operation=MD_FS_RENAME,
        .directory={md_fs_anchor_fd(old_root),-1},.origin={old_root,NULL},.path={"jail","/other"}};
    md_fs_execute(&current,&pair,&r,NULL); assert(r.error==-EXDEV);
    pair.path[0]="mnt/value"; pair.path[1]="/mnt/renamed";
    md_fs_execute(&current,&pair,&r,NULL); assert(r.error==-EXDEV);
    pair.operation=MD_FS_LINK; md_fs_execute(&current,&pair,&r,NULL); assert(r.error==-EXDEV);
    int jail=md_inode_open(s,-1,"/jail",O_PATH|O_DIRECTORY,0); assert(jail>=0);
    assert(!md_fs_root_capture(&current,jail,&root)); close(jail);
    assert(!md_fs_root_select(&current,&root));
    opens(&current,old_root,"jail/../mnt/value",O_RDWR,0,0);
    opens(&current,old,"absolute",O_RDONLY,0,-ENOENT);
    r=request(&current,old_root,md_fs_anchor_fd(old_root),MD_FS_FSTAT,NULL,0,0,NULL);
    assert(!r.error && r.info.mount_id==original.mounts->root_id);
    assert(!strcmp(s->root_id,root.object));
    assert(!md_fs_root_select(&current,&(struct md_fs_location){0}));
    snprintf(path,sizeof(path),"%s/child",host[0]);
    snprintf(next,sizeof(next),"%s/moved",host[0]); assert(!rename(path,next));
    opens(&current,old,"moved/value",O_RDWR,0,-EROFS);
    opens(&current,old_child,"../value",O_RDWR,0,0);
    md_fs_mounts_close(&original);
    opens(&current,old,"moved/value",O_RDONLY,0,0);
    struct md_fs_anchor *shared=md_fs_anchor_retain(old);
    md_fs_anchor_release(old); opens(&current,shared,"value",O_RDWR,0,0);
    char bytes[128]; struct md_fs_output output={.data=bytes,.capacity=sizeof(bytes)};
    struct md_fs_request cwd={.operation=MD_FS_PATH,.directory={md_fs_anchor_fd(shared),-1},.origin={shared,NULL}};
    md_fs_execute(&current,&cwd,&r,&output); assert(r.error==-ENOENT);
    /* Foreign store pointers are rejected without touching that store. */
    struct md_filesystem foreign=current; foreign.store=NULL;
    assert(md_view_anchor_check(&foreign,md_fs_anchor_fd(shared),shared)==-ESTALE);
    md_fs_anchor_release(shared); md_fs_anchor_release(old_child); md_fs_anchor_release(old_root); md_fs_anchor_release(new);
    md_fs_anchor_release(file); md_fs_mounts_close(&current);
    empty_views(s); md_inode_store_close(s);
    assert(descriptors()==before);
    puts("PASS explicit path origins across copied views, readonly policy, nested mounts and absolute/relative links");
    puts("PASS origin-aware openat2, cross-view link/rename rejection and root-context restoration");
    puts("PASS captured FD identity, reopen, reused-number rejection, flock/OFD release and source-view lifetime");
    puts("PASS empty-view inode origins, completed FIFO identity/EOF and failed capture descriptor cleanup");
}
