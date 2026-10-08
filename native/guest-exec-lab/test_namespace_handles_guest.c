#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

static void directory_handles(void) {
    int fd=open("/proc/self/ns/",O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(fd>=0);
    struct stat st; assert(!fstat(fd,&st) && S_ISDIR(st.st_mode));
    struct statfs fs; assert(!fstatfs(fd,&fs) && fs.f_type==PROC_SUPER_MAGIC);
    char bytes[256];
    assert(read(fd,bytes,sizeof(bytes))<0 && errno==EISDIR);
    assert(syscall(SYS_getdents64,fd,bytes,1)<0 && errno==EINVAL);
    assert(!lseek(fd,0,SEEK_CUR));
    assert(syscall(SYS_getdents64,fd,bytes,24)==24);
    int copy=dup(fd); off_t cursor=copy<0 ? -1 : lseek(copy,0,SEEK_CUR);
    if (copy<0 || cursor!=1) fprintf(stderr,"namespace directory dup=%d cursor=%lld errno=%d\n",copy,(long long)cursor,errno);
    assert(copy>=0 && cursor==1);
    void *bad=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(bad!=MAP_FAILED);
    assert(syscall(SYS_getdents64,copy,bad,24)<0 && errno==EFAULT);
    assert(lseek(fd,0,SEEK_CUR)==1); munmap(bad,4096);
    assert(!lseek(copy,0,SEEK_SET)); close(copy);
    DIR *dir=fdopendir(fd); assert(dir);
    unsigned seen=0, count=0;
    for (struct dirent *e;(e=readdir(dir));) {
        ++count;
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) { assert(e->d_type==DT_DIR); continue; }
        const char *names[]={"user","mnt","uts","ipc","pid","pid_for_children"};
        unsigned bit=0;
        for (unsigned i=0;i<6;++i) if (!strcmp(e->d_name,names[i])) bit=1U<<i;
        assert(bit && !(seen&bit) && e->d_type==DT_LNK); seen|=bit;
        int ns=openat(fd,e->d_name,O_RDONLY|O_CLOEXEC); assert(ns>=0);
        assert(ioctl(ns,NS_GET_NSTYPE)>0); close(ns);
    }
    assert(count==8 && seen==63);
    rewinddir(dir); assert(readdir(dir)); closedir(dir);
    int saved=open(".",O_RDONLY|O_DIRECTORY); assert(saved>=0);
    assert(!chdir("/proc/self/ns"));
    fd=open("user",O_RDONLY|O_CLOEXEC); assert(fd>=0 && ioctl(fd,NS_GET_NSTYPE)==CLONE_NEWUSER); close(fd);
    assert(!fchdir(saved)); close(saved);
    int ready[2], finish[2]; assert(!pipe(ready) && !pipe(finish));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(ready[0]); close(finish[1]);
        assert(write(ready[1],"x",1)==1 && read(finish[0],bytes,1)==1); _exit(0);
    }
    close(ready[1]); close(finish[0]); assert(read(ready[0],bytes,1)==1); close(ready[0]);
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/ns",child);
    fd=open(path,O_RDONLY|O_DIRECTORY); assert(fd>=0);
    assert(write(finish[1],"x",1)==1); close(finish[1]);
    int status;
    /* EVENT_WAIT: owner exit before reading its retained directory; alarm bounds failure. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(syscall(SYS_getdents64,fd,bytes,sizeof(bytes))<0 && errno==ENOENT); close(fd);
}
static void process_directory(void) {
    int fd=open("/proc/self/",O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(fd>=0);
    char bytes[4096];
    assert(syscall(SYS_getdents64,fd,bytes,1)<0 && errno==EINVAL);
    assert(!lseek(fd,0,SEEK_CUR));
    assert(syscall(SYS_getdents64,fd,bytes,24)==24);
    off_t position=lseek(fd,0,SEEK_CUR); assert(position>0);
    int copy=dup(fd); assert(copy>=0 && lseek(copy,0,SEEK_CUR)==position);
    void *bad=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(bad!=MAP_FAILED);
    assert(syscall(SYS_getdents64,copy,bad,sizeof(bytes))<0 && errno==EFAULT);
    assert(lseek(fd,0,SEEK_CUR)==position); munmap(bad,4096);
    assert(!lseek(copy,0,SEEK_SET)); close(copy);
    DIR *dir=fdopendir(fd); assert(dir);
    unsigned seen=0; int native=0;
    const char *names[]={"uid_map","gid_map","setgroups"};
    for (struct dirent *e;(e=readdir(dir));) {
        native+=!strcmp(e->d_name,"status");
        for (unsigned i=0;i<3;++i) if (!strcmp(e->d_name,names[i])) {
            assert(!(seen&(1U<<i)) && e->d_type==DT_REG); seen|=1U<<i;
            struct stat st;
            assert(!fstatat(fd,e->d_name,&st,0) && st.st_ino==e->d_ino);
            int file=openat(fd,e->d_name,O_RDONLY|O_CLOEXEC); assert(file>=0);
            assert(read(file,bytes,sizeof(bytes))>0); close(file);
        }
    }
    assert(seen==7 && native==1);
    rewinddir(dir); assert(readdir(dir));
    int saved=open(".",O_RDONLY|O_DIRECTORY); assert(saved>=0);
    assert(!fchdir(fd));
    int file=open("uid_map",O_RDONLY); assert(file>=0); close(file);
    assert(!fchdir(saved)); close(saved); closedir(dir);
    puts("PASS proc process directory: native entries, map discovery, identity, relative opens and fault-safe shared cursor");
}
static void retained_proc(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        int proc=open("/proc",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(proc>=0);
        int dev=open("/dev",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(dev>=0);
        assert(!unshare(CLONE_NEWNS));
        int overflow=open("/proc/sys/kernel/overflowuid",O_RDONLY); assert(overflow>=0);
        close(overflow);
        assert(!chroot("/"));
        overflow=open("/proc/sys/kernel/overflowuid",O_RDONLY); assert(overflow>=0); close(overflow);
        int ns=openat(proc,"self/ns",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(ns>=0);
        int user=openat(ns,"user",O_RDONLY|O_CLOEXEC); assert(user>=0);
        assert(ioctl(user,NS_GET_NSTYPE)==CLONE_NEWUSER); close(user); close(ns);
        int map=openat(proc,"thread-self/uid_map",O_RDONLY|O_CLOEXEC); assert(map>=0);
        char bytes[128]; assert(read(map,bytes,sizeof(bytes))>0); close(map);
        struct stat st;
        assert(!fstatat(proc,"thread-self/ns",&st,0) && S_ISDIR(st.st_mode));
        int null=openat(dev,"null",O_RDWR|O_CLOEXEC); assert(null>=0);
        assert(write(null,"x",1)==1 && !read(null,bytes,1)); close(null);
        close(dev);
        close(proc); _exit(0);
    }
    int status;
    /* EVENT_WAIT: retained-proc child exits; fixture alarm bounds a stuck lookup. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    puts("PASS retained proc dirfd: scoped root, namespace directory, UID map and metadata");
}
int test_namespace_handles_guest(void) {
    alarm(60);
    directory_handles();
    process_directory();
    retained_proc();
    const char *names[]={"user","mnt","uts","ipc"};
    int types[]={CLONE_NEWUSER,CLONE_NEWNS,CLONE_NEWUTS,CLONE_NEWIPC};
    int fds[4]; struct stat before[4];
    for (unsigned i=0;i<4;++i) {
        char path[128], label[128], expected[128];
        snprintf(path,sizeof(path),"/proc/self/ns/%s",names[i]);
        assert(!stat(path,before+i) && S_ISREG(before[i].st_mode));
        fds[i]=open(path,O_RDONLY|O_CLOEXEC); assert(fds[i]>=0);
        struct stat value; struct statfs fs;
        assert(!fstat(fds[i],&value) && value.st_ino==before[i].st_ino && value.st_dev==before[i].st_dev);
        assert(!fstatfs(fds[i],&fs) && fs.f_type==NSFS_MAGIC);
        assert(!statfs(path,&fs) && fs.f_type==NSFS_MAGIC);
        assert(!lstat(path,&value) && S_ISLNK(value.st_mode));
        ssize_t n=readlink(path,label,sizeof(label)-1); assert(n>0); label[n]=0;
        snprintf(expected,sizeof(expected),"%s:[%llu]",names[i],(unsigned long long)before[i].st_ino);
        assert(!strcmp(label,expected));
        assert(open(path,O_WRONLY)<0 && errno==EACCES);
        assert(open(path,O_RDONLY|O_NOFOLLOW)<0 && errno==ELOOP);
        int type=ioctl(fds[i],NS_GET_NSTYPE);
        if (type!=types[i]) fprintf(stderr,"namespace %s ioctl type=%d errno=%d expected=%d\n",names[i],type,errno,types[i]);
        assert(type==types[i]);
        assert(read(fds[i],label,sizeof(label))<0 && errno==EINVAL);
        assert(lseek(fds[i],0,SEEK_SET)<0 && errno==ESPIPE);
        snprintf(path,sizeof(path),"/proc/self/fd/%d",fds[i]);
        n=readlink(path,label,sizeof(label)-1); assert(n>0); label[n]=0;
        assert(!strcmp(label,expected));
        int copy=open(path,O_RDONLY|O_CLOEXEC); assert(copy>=0);
        assert(ioctl(copy,NS_GET_NSTYPE)==types[i]); close(copy);
    }
    uid_t owner=1234;
    assert(!ioctl(fds[0],NS_GET_OWNER_UID,&owner) && !owner);
    assert(ioctl(fds[1],NS_GET_OWNER_UID,&owner)<0 && errno==EINVAL);
    assert(ioctl(fds[0],NS_GET_PARENT)<0 && errno==EPERM);
    for (unsigned i=1;i<4;++i) {
        int related=ioctl(fds[i],NS_GET_USERNS); assert(related>=0);
        struct stat st; assert(!fstat(related,&st));
        assert(st.st_ino==before[0].st_ino && st.st_dev==before[0].st_dev);
        assert(ioctl(related,NS_GET_NSTYPE)==CLONE_NEWUSER);
        assert(fcntl(related,F_GETFD)&FD_CLOEXEC); close(related);
        assert(ioctl(fds[i],NS_GET_PARENT)<0 && errno==EINVAL);
    }
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC));
        int self=open("/proc/self/ns/user",O_RDONLY); assert(self>=0);
        assert(ioctl(self,NS_GET_PARENT)<0 && errno==EPERM); close(self);
        assert(ioctl(fds[1],NS_GET_USERNS)<0 && errno==EPERM);
        int uts=open("/proc/self/ns/uts",O_RDONLY); assert(uts>=0);
        int owner=ioctl(uts,NS_GET_USERNS); assert(owner>=0);
        struct stat user, related;
        assert(!stat("/proc/self/ns/user",&user) && !fstat(owner,&related));
        assert(user.st_dev==related.st_dev && user.st_ino==related.st_ino);
        close(owner); close(uts);
        for (unsigned i=0;i<4;++i) {
            char path[128]; snprintf(path,sizeof(path),"/proc/self/ns/%s",names[i]);
            struct stat current, retained;
            assert(!stat(path,&current) && current.st_ino!=before[i].st_ino);
            assert(!fstat(fds[i],&retained) && retained.st_ino==before[i].st_ino);
            close(fds[i]);
        }
        _exit(0);
    }
    int status;
    /* EVENT_WAIT: exact child exit, bounded by the fixture alarm. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    for (unsigned i=0;i<4;++i) {
        struct stat value; assert(!fstat(fds[i],&value) && value.st_ino==before[i].st_ino);
        close(fds[i]);
    }
    assert(access("/proc/self/ns/net",F_OK)<0 && errno==ENOENT);
    assert(!access("/proc/self/ns/pid",F_OK));
    puts("PASS guest namespace handles: stable identities, retained resources, metadata, links, ioctls and independent unshare");
    return 0;
}
