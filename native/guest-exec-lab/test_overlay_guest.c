#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <unistd.h>

static void directory(const char *path) { assert(!mkdir(path,0755)); }
static void file(const char *path, const char *data) {
    int fd=open(path,O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,data,strlen(data))==(ssize_t)strlen(data)); assert(!close(fd));
}
static void contents(int directory, const char *path, const char *expected) {
    int fd=openat(directory,path,O_RDONLY); assert(fd>=0);
    char text[64]; ssize_t n=read(fd,text,sizeof(text));
    assert(n==(ssize_t)strlen(expected) && !memcmp(text,expected,(size_t)n)); close(fd);
}
static void missing(const char *path) { assert(access(path,F_OK)<0 && errno==ENOENT); }
static void no_attribute(const char *path, const char *name) {
    char value[256];
    assert(getxattr(path,name,value,sizeof(value))<0 && errno==ENODATA);
    ssize_t n=listxattr(path,value,sizeof(value)); assert(n>=0);
    assert(listxattr(path,NULL,0)==n);
    for (ssize_t at=0; at<n; at+=(ssize_t)strlen(value+at)+1)
        assert(strcmp(value+at,name));
}
static void writable(void) {
    directory("/tmp/overlay/writable"); directory("/tmp/overlay/work");
    directory("/tmp/overlay/second");
    const char *options="lowerdir=/tmp/overlay/lower,upperdir=/tmp/overlay/writable,workdir=/tmp/overlay/work,userxattr";
    int mounted=mount("overlay","/tmp/overlay/merged","overlay",0,options);
    if (mounted) perror("writable overlay mount");
    assert(!mounted);
    int root=open("/tmp/overlay/merged",O_RDONLY|O_DIRECTORY); assert(root>=0);
    int old=openat(root,"original",O_RDONLY); assert(old>=0);
    int file=openat(root,"original",O_RDWR); assert(file>=0);
    assert(pwrite(file,"upper",5,0)==5 && !ftruncate(file,5));
    contents(AT_FDCWD,"/tmp/overlay/writable/original","upper");
    contents(root,"alias","upper");
    contents(AT_FDCWD,"/tmp/overlay/lower/original","shared body");
    char data[32]; assert(pread(old,data,sizeof(data),0)==11 && !memcmp(data,"shared body",11));
    assert(!linkat(root,"original",root,"new-link",0));
    assert(!renameat(root,"original",root,"moved"));
    assert(renameat(root,"sub",root,"moved-sub")<0 && errno==EXDEV);
    assert(!unlinkat(root,"deleted",0));
    assert(!unlinkat(root,"sub/low",0) && !unlinkat(root,"sub",AT_REMOVEDIR));
    assert(!mkdirat(root,"sub",0700));
    assert(!setxattr("/tmp/overlay/merged/sub","user.changed","yes",3,0));
    assert(getxattr("/tmp/overlay/writable/sub","user.changed",data,sizeof(data))==3 && !memcmp(data,"yes",3));
    no_attribute("/tmp/overlay/merged/sub","user.overlay.opaque");
    assert(getxattr("/tmp/overlay/writable/sub","user.overlay.opaque",data,sizeof(data))==1 && data[0]=='y');
    assert(getxattr("/tmp/overlay/writable/original","user.overlay.whiteout",NULL,0)==0);
    struct statfs info; assert(!fstatfs(root,&info) && info.f_type==0x794c7630 && !(info.f_flags&MS_RDONLY));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        int fd=openat(root,"child",O_CREAT|O_RDWR,0600); assert(fd>=0);
        assert(write(fd,"fork",4)==4); close(fd); _exit(0);
    }
    int status; assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && !WEXITSTATUS(status));
    contents(root,"child","fork"); contents(AT_FDCWD,"/tmp/overlay/writable/child","fork");
    assert(!umount2("/tmp/overlay/merged",MNT_DETACH));
    contents(root,"moved","upper");
    assert(mount("overlay","/tmp/overlay/second","overlay",0,options)<0 && errno==EBUSY);
    close(file); close(old); close(root);
    mounted=mount("overlay","/tmp/overlay/merged","overlay",0,options);
    if (mounted) perror("writable overlay remount after final close");
    assert(!mounted);
    contents(AT_FDCWD,"/tmp/overlay/merged/moved","upper");
    contents(AT_FDCWD,"/tmp/overlay/merged/new-link","upper");
    missing("/tmp/overlay/merged/original"); missing("/tmp/overlay/merged/deleted");
    missing("/tmp/overlay/merged/sub/low");
    assert(!umount2("/tmp/overlay/merged",0));
    const char *bad[]={"lowerdir=/tmp/overlay/lower,upperdir=/tmp/overlay/writable",
        "lowerdir=/tmp/overlay/lower,workdir=/tmp/overlay/work",
        "lowerdir=/tmp/overlay/lower,upperdir=/tmp/overlay/lower,workdir=/tmp/overlay/work",
        "lowerdir=/tmp/overlay/lower,upperdir=/tmp/overlay/writable,workdir=/tmp/overlay/writable"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i) {
        int result=mount("overlay","/tmp/overlay/merged","overlay",0,bad[i]);
        if (result>=0 || errno!=EINVAL) fprintf(stderr,"invalid overlay option %u result=%d errno=%d\n",i,result,errno);
        assert(result<0 && errno==EINVAL);
    }
    puts("PASS guest writable overlay: syscall copy-up, whiteouts, hardlinks, fork, upper xattrs, detached lifetime and remount");
}
void test_overlay_guest(void) {
    setbuf(stdout,NULL); alarm(60);
    directory("/tmp/overlay"); directory("/tmp/overlay/lower");
    directory("/tmp/overlay/top"); directory("/tmp/overlay/merged");
    file("/tmp/overlay/merged/covered","base");
    file("/tmp/overlay/lower/common","low"); file("/tmp/overlay/top/common","high");
    file("/tmp/overlay/lower/deleted","hidden"); file("/tmp/overlay/top/deleted","");
    assert(!setxattr("/tmp/overlay/top/deleted","user.overlay.whiteout","",0,0));
    file("/tmp/overlay/top/not-whiteout","nonempty");
    assert(!setxattr("/tmp/overlay/top/not-whiteout","user.overlay.whiteout","",0,0));
    directory("/tmp/overlay/lower/sub"); directory("/tmp/overlay/top/sub");
    assert(!setxattr("/tmp/overlay/lower/sub","user.lower-only","lower",5,0));
    assert(!setxattr("/tmp/overlay/top/sub","user.top","upper",5,0));
    file("/tmp/overlay/lower/sub/low","lower child"); file("/tmp/overlay/top/sub/high","upper child");
    file("/tmp/overlay/lower/original","shared body");
    assert(!link("/tmp/overlay/lower/original","/tmp/overlay/lower/alias"));
    assert(!symlink("original","/tmp/overlay/top/symlink"));
    directory("/tmp/overlay/lower/opaque"); directory("/tmp/overlay/top/opaque");
    file("/tmp/overlay/lower/opaque/hidden","hidden child");
    file("/tmp/overlay/top/opaque/shown","shown child");
    assert(!setxattr("/tmp/overlay/top/opaque","user.overlay.opaque","y",1,0));
    const char *bad[]={"lowerdir=", "lowerdir=/tmp/overlay/lower:",
        "lowerdir=/tmp/overlay/lower,", ",lowerdir=/tmp/overlay/lower",
        "lowerdir=/tmp/overlay/lower,lowerdir=/tmp/overlay/top"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i) {
        assert(mount("overlay","/tmp/overlay/merged","overlay",0,bad[i])<0 && errno==EINVAL);
        contents(AT_FDCWD,"/tmp/overlay/merged/covered","base");
    }
    const char *options="lowerdir=/tmp/overlay/top:/tmp/overlay/lower,userxattr";
    assert(!mount("overlay","/tmp/overlay/merged","overlay",MS_RDONLY,options));
    int root=open("/tmp/overlay/merged",O_RDONLY|O_DIRECTORY); assert(root>=0);
    contents(root,"common","high"); contents(root,"sub/low","lower child");
    contents(root,"sub/high","upper child"); contents(root,"symlink","shared body");
    contents(root,"not-whiteout","nonempty"); contents(root,"opaque/shown","shown child");
    missing("/tmp/overlay/merged/deleted"); missing("/tmp/overlay/merged/opaque/hidden");
    missing("/tmp/overlay/merged/covered");
    struct stat a,b;
    assert(!fstatat(root,"original",&a,0) && !fstatat(root,"alias",&b,0));
    assert(a.st_ino==b.st_ino && a.st_dev==b.st_dev && a.st_nlink==2);
    struct statfs info; assert(!fstatfs(root,&info) && info.f_type==0x794c7630);
    assert(mount(NULL,"/tmp/overlay/merged",NULL,MS_REMOUNT|MS_BIND,NULL)<0 && errno==EROFS);
    assert(!fstatfs(root,&info) && (info.f_flags&MS_RDONLY));
    no_attribute("/tmp/overlay/merged/sub","user.lower-only");
    no_attribute("/tmp/overlay/merged/not-whiteout","user.overlay.whiteout");
    no_attribute("/tmp/overlay/merged/opaque","user.overlay.opaque");
    char attr[16];
    assert(getxattr("/tmp/overlay/merged/sub","user.top",attr,sizeof(attr))==5 && !memcmp(attr,"upper",5));
    assert(openat(root,"common",O_WRONLY)<0 && errno==EROFS);
    DIR *entries=fdopendir(dup(root)); assert(entries);
    unsigned common=0, count=0;
    for (struct dirent *e; (e=readdir(entries));) {
        common+=!strcmp(e->d_name,"common"); ++count;
        assert(strcmp(e->d_name,"deleted") && strcmp(e->d_name,"covered"));
    }
    assert(common==1 && count==9); closedir(entries);
    assert(!umount2("/tmp/overlay/merged",MNT_DETACH));
    contents(root,"common","high"); contents(root,"alias","shared body");
    contents(AT_FDCWD,"/tmp/overlay/merged/covered","base");
    assert(!mount("overlay","/tmp/overlay/merged","overlay",MS_RDONLY,options));
    contents(root,"sub/low","lower child"); close(root);
    assert(!umount2("/tmp/overlay/merged",0));
    puts("PASS guest overlay: layers, merged directories, whiteout/opaque, hardlinks, enumeration, readonly and retained detached descriptors");
    writable();
}
