#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/time.h>
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
    unsigned seen=0, count=0; ino_t inodes[10];
    for (struct dirent *e;(e=readdir(dir));) {
        assert(count<10);
        for (unsigned i=0;i<count;++i) assert(inodes[i]!=e->d_ino);
        inodes[count]=e->d_ino;
        ++count;
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) { assert(e->d_type==DT_DIR); continue; }
        const char *names[]={"user","mnt","uts","ipc","pid","pid_for_children","net","cgroup"};
        unsigned bit=0;
        for (unsigned i=0;i<8;++i) if (!strcmp(e->d_name,names[i])) bit=1U<<i;
        assert(bit && !(seen&bit) && e->d_type==DT_LNK); seen|=bit;
        int ns=openat(fd,e->d_name,O_RDONLY|O_CLOEXEC); assert(ns>=0);
        assert(ioctl(ns,NS_GET_NSTYPE)>0); close(ns);
    }
    assert(count==10 && seen==255);
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
static void unsupported_namespaces(void) {
    assert(access("/proc/thread-self/ns/time",F_OK)<0 && errno==ENOENT);
    assert(unshare(CLONE_NEWTIME)<0 && errno==EOPNOTSUPP);
    int fd=open("/proc/thread-self/ns/mnt",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    char target[128],source[128];
    snprintf(target,sizeof(target),"/tmp/namespace-bind-%d",getpid());
    int file=open(target,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600); assert(file>=0); close(file);
    assert(mount("/proc/thread-self/ns/mnt",target,NULL,MS_BIND,NULL)<0 && errno==EINVAL);
    snprintf(source,sizeof(source),"/proc/self/fd/%d",fd);
    assert(mount(source,target,NULL,MS_BIND,NULL)<0 && errno==EINVAL);
    assert(mount("/proc/self/uid_map",target,NULL,MS_BIND,NULL)<0 && errno==EOPNOTSUPP);
    for (unsigned i=0;i<2;++i) {
        int control=open("/proc/self/uid_map",i ? O_PATH : O_RDONLY); assert(control>=0);
        snprintf(source,sizeof(source),"/proc/self/fd/%d",control);
        assert(mount(source,target,NULL,MS_BIND,NULL)<0 && errno==EOPNOTSUPP); close(control);
    }
    assert(!unlink(target));
    close(fd);
    puts("PASS unsupported namespaces: absent capability, mount cycle and non-mountable control rejection");
}
static void namespace_mounts(void) {
    assert(!unshare(CLONE_NEWNS));
    char target[128],alias[128],source[128];
    snprintf(target,sizeof(target),"/tmp/ns-mounted-%d",getpid());
    snprintf(alias,sizeof(alias),"/tmp/ns-alias-%d",getpid());
    int fd=open(target,O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0); close(fd);
    fd=open(alias,O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0); close(fd);
    struct stat before,after;
    assert(!stat("/proc/self/ns/net",&before));
    assert(!mount("/proc/thread-self/ns/net",target,NULL,MS_BIND,NULL));
    assert(!stat(target,&after) && S_ISREG(after.st_mode)
        && before.st_ino==after.st_ino && before.st_dev==after.st_dev);
    struct statfs fs; assert(!statfs(target,&fs) && fs.f_type==NSFS_MAGIC);
    fd=open(target,O_RDONLY|O_CLOEXEC); assert(fd>=0);
    assert(ioctl(fd,NS_GET_NSTYPE)==CLONE_NEWNET);
    int owner=ioctl(fd,NS_GET_USERNS); assert(owner>=0); close(owner);
    assert(!fstat(fd,&after) && before.st_ino==after.st_ino);
    assert(!fstatfs(fd,&fs) && fs.f_type==NSFS_MAGIC);
    char bytes[128];
    assert(read(fd,bytes,sizeof(bytes))<0 && errno==EINVAL);
    assert(lseek(fd,0,SEEK_SET)<0 && errno==ESPIPE);
    assert(open(target,O_WRONLY)<0 && errno==EACCES);
    assert(chmod(target,0600)<0 && errno==EOPNOTSUPP);
    assert(open(target,O_DIRECTORY|O_RDONLY)<0 && errno==ENOTDIR);
    int path=open(target,O_PATH|O_CLOEXEC); assert(path>=0);
    snprintf(source,sizeof(source),"/proc/self/fd/%d",path);
    assert(!mount(source,alias,NULL,MS_BIND,NULL));
    int copy=open(source,O_RDONLY|O_CLOEXEC); assert(copy>=0);
    assert(ioctl(copy,NS_GET_NSTYPE)==CLONE_NEWNET);
    assert(!unshare(CLONE_NEWNET));
    assert(!stat("/proc/self/ns/net",&after) && before.st_ino!=after.st_ino);
    assert(!setns(copy,CLONE_NEWNET)); close(copy); close(path);
    assert(!stat("/proc/self/ns/net",&after) && before.st_ino==after.st_ino);
    assert(setns(fd,CLONE_NEWUTS)<0 && errno==EINVAL);
    assert(umount(target)<0 && errno==EBUSY);
    assert(!umount2(target,MNT_DETACH));
    assert(ioctl(fd,NS_GET_NSTYPE)==CLONE_NEWNET);
    assert(!setns(fd,CLONE_NEWNET)); close(fd);
    assert(!stat(alias,&after) && before.st_ino==after.st_ino);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!unshare(CLONE_NEWNS));
        int retained=open(alias,O_RDONLY); assert(retained>=0);
        assert(ioctl(retained,NS_GET_NSTYPE)==CLONE_NEWNET); close(retained);
        assert(!umount(alias)); _exit(0);
    }
    int status;
    /* EVENT_WAIT: copied namespace exits; fixture alarm bounds failure. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!stat(alias,&after) && before.st_ino==after.st_ino);
    assert(!mount(alias,target,NULL,MS_MOVE,NULL));
    assert(!stat(target,&after) && before.st_ino==after.st_ino);
    assert(!mount(target,alias,NULL,MS_MOVE,NULL));
    assert(!mount(alias,target,NULL,MS_BIND,NULL));
    assert(!umount(alias));
    assert(!stat(target,&after) && before.st_ino==after.st_ino);
    assert(!umount(target));
    for (unsigned i=0;i<96;++i) {
        assert(!mount("/proc/self/ns/net",target,NULL,MS_BIND,NULL));
        fd=open(target,O_RDONLY); assert(fd>=0);
        assert(!umount2(target,MNT_DETACH)); close(fd);
    }
    assert(!unlink(target) && !unlink(alias));
    puts("PASS namespace mounts: typed path/FD binds, nsfs identity, setns, copy, lazy retirement and cycle rejection");
}
static void namespace_mount_lifetime(int chrooted) {
    char directory[128],network[160],mountpoint[160],source[128],copy[128];
    snprintf(directory,sizeof(directory),"/tmp/ns-lifetime-%d",getpid());
    snprintf(network,sizeof(network),"%s/net",directory);
    snprintf(mountpoint,sizeof(mountpoint),"%s/mnt",directory);
    snprintf(copy,sizeof(copy),"/tmp/ns-copy-%d",getpid());
    assert(!mkdir(directory,0755) && !mkdir(copy,0755));
    int fd=open(network,O_CREAT|O_EXCL|O_RDWR,0644); assert(fd>=0); close(fd);
    fd=open(mountpoint,O_CREAT|O_EXCL|O_RDWR,0644); assert(fd>=0); close(fd);
    struct stat empty; assert(!stat(mountpoint,&empty));
    int original=open("/proc/self/ns/mnt",O_RDONLY|O_CLOEXEC); assert(original>=0);
    int saved_root=open("/",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(saved_root>=0);
    int ready[2],finish[2]; assert(!pipe(ready) && !pipe(finish));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(ready[0]); close(finish[1]);
        assert(!unshare(CLONE_NEWNS|CLONE_NEWNET));
        assert(write(ready[1],"x",1)==1);
        char byte;
        /* EVENT_WAIT: parent captures both namespaces; fixture alarm bounds failure. */
        assert(read(finish[0],&byte,1)==1); _exit(0);
    }
    close(ready[1]); close(finish[0]);
    char byte; assert(read(ready[0],&byte,1)==1); close(ready[0]);
    snprintf(source,sizeof(source),"/proc/%d/ns/mnt",child);
    struct stat mount_id,network_id,st;
    assert(!stat(source,&mount_id));
    assert(!mount(source,mountpoint,NULL,MS_BIND,NULL));
    snprintf(source,sizeof(source),"/proc/%d/ns/net",child);
    assert(!stat(source,&network_id));
    assert(!mount(source,network,NULL,MS_BIND,NULL));
    assert(write(finish[1],"x",1)==1); close(finish[1]);
    int status;
    /* EVENT_WAIT: namespace owner exits; mounts must retain authority afterwards. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    fd=open(mountpoint,O_RDONLY); assert(fd>=0 && ioctl(fd,NS_GET_NSTYPE)==CLONE_NEWNS);
    assert(!setns(fd,CLONE_NEWNS));
    assert(!stat("/proc/self/ns/mnt",&st) && st.st_ino==mount_id.st_ino);
    assert(!setns(original,CLONE_NEWNS)); close(original); close(fd);
    /* Mount-namespace entry selects its root; restore this fixture's private
     * chroot before resolving the test paths again. */
    assert(!fchdir(saved_root) && !chroot(".") && !chdir("/")); close(saved_root);
    assert(!mount(directory,copy,NULL,MS_BIND|MS_REC,NULL));
    char copied_net[160],copied_mnt[160];
    snprintf(copied_net,sizeof(copied_net),"%s/net",copy);
    snprintf(copied_mnt,sizeof(copied_mnt),"%s/mnt",copy);
    assert(!stat(copied_net,&st) && st.st_ino==network_id.st_ino);
    assert(!stat(copied_mnt,&st) && st.st_ino==mount_id.st_ino);
    /* Imported fixture root is mode 0700 under the real shell UID. Allow the
     * deliberately unmapped user namespace to traverse it for this check. */
    assert(!chmod("/",0755));
    child=fork(); assert(child>=0);
    if (!child) {
        if (chrooted) {
            assert(unshare(CLONE_NEWUSER|CLONE_NEWNS)<0 && errno==EPERM);
            assert(!unshare(CLONE_NEWNS));
        } else assert(!unshare(CLONE_NEWUSER|CLONE_NEWNS));
        assert(!stat(mountpoint,&st) && st.st_ino==empty.st_ino);
        assert(!stat(copied_mnt,&st) && st.st_ino==empty.st_ino);
        fd=open(copied_net,O_RDONLY); assert(fd>=0);
        assert(ioctl(fd,NS_GET_NSTYPE)==CLONE_NEWNET);
        if (chrooted) assert(!setns(fd,CLONE_NEWNET));
        else assert(setns(fd,CLONE_NEWNET)<0 && errno==EPERM);
        close(fd); _exit(0);
    }
    /* EVENT_WAIT: copied namespace/authority check exits; alarm bounds failure. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!umount(copied_net) && !umount(copied_mnt) && !umount(copy));
    assert(!umount(network) && !umount(mountpoint));
    assert(!unlink(network) && !unlink(mountpoint));
    assert(!rmdir(directory) && !rmdir(copy));
    puts("PASS namespace mount lifetime: exited owner, recursive bind, acyclic copy and user authority");
}
int test_namespace_mounts_pid_guest(void) {
    alarm(60);
    assert(!unshare(CLONE_NEWPID));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(getpid()==1 && !unshare(CLONE_NEWNS));
        assert(!mkdir("/tmp/ns-root",0755));
        assert(!mkdir("/tmp/ns-root/proc",0755) && !mkdir("/tmp/ns-root/tmp",0777));
        assert(!chroot("/tmp/ns-root") && !chdir("/"));
        assert(!mount("proc","/proc","proc",0,NULL));
        namespace_mounts(); namespace_mount_lifetime(1); _exit(0);
    }
    int status;
    /* EVENT_WAIT: PID namespace init completes its mounted-proc workflows. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    puts("PASS PID-scoped namespace mounts: mounted proc, self/thread aliases and foreign owners");
    return 0;
}
static void loopback_query(int fd,unsigned flags,int index,const char *name,int expected) {
    union { struct nlmsghdr align; char bytes[128]; } request={0},answer={0};
    struct nlmsghdr *h=(void *)request.bytes;
    *h=(struct nlmsghdr){.nlmsg_len=NLMSG_LENGTH(sizeof(struct ifinfomsg)),
        .nlmsg_type=RTM_GETLINK,.nlmsg_flags=NLM_F_REQUEST|flags,.nlmsg_seq=19};
    ((struct ifinfomsg *)NLMSG_DATA(h))->ifi_index=index;
    if (name) {
        struct rtattr *a=(void *)(request.bytes+h->nlmsg_len);
        a->rta_type=IFLA_IFNAME; a->rta_len=RTA_LENGTH(strlen(name)+1);
        memcpy(RTA_DATA(a),name,strlen(name)+1); h->nlmsg_len+=RTA_ALIGN(a->rta_len);
        a=(void *)(request.bytes+h->nlmsg_len);
        a->rta_type=IFLA_EXT_MASK; a->rta_len=RTA_LENGTH(sizeof(uint32_t));
        uint32_t mask=RTEXT_FILTER_VF; memcpy(RTA_DATA(a),&mask,sizeof(mask));
        h->nlmsg_len+=RTA_ALIGN(a->rta_len);
    }
    struct sockaddr_nl kernel={.nl_family=AF_NETLINK};
    assert(sendto(fd,request.bytes,h->nlmsg_len,0,(void *)&kernel,sizeof(kernel))==h->nlmsg_len);
    ssize_t count=recv(fd,answer.bytes,sizeof(answer.bytes),0); assert(count>0);
    unsigned remaining=(unsigned)count; int links=0,done=0,acks=0;
    for (struct nlmsghdr *a=(void *)answer.bytes;NLMSG_OK(a,remaining);a=NLMSG_NEXT(a,remaining)) {
        assert(a->nlmsg_seq==19);
        if (a->nlmsg_type==NLMSG_ERROR) {
            assert(a->nlmsg_len>=NLMSG_LENGTH(sizeof(struct nlmsgerr)));
            assert(((struct nlmsgerr *)NLMSG_DATA(a))->error==expected); ++acks;
        } else if (a->nlmsg_type==NLMSG_DONE) { assert(!expected); ++done; }
        else {
            assert(!expected && a->nlmsg_type==RTM_NEWLINK);
            struct ifinfomsg *m=NLMSG_DATA(a); assert(m->ifi_index==1); ++links;
            int bytes=(int)a->nlmsg_len-(int)NLMSG_LENGTH(sizeof(*m)),named=0;
            for (struct rtattr *r=IFLA_RTA(m);RTA_OK(r,bytes);r=RTA_NEXT(r,bytes))
                if (r->rta_type==IFLA_IFNAME) {
                    assert(RTA_PAYLOAD(r)==3 && !memcmp(RTA_DATA(r),"lo",3)); ++named;
                }
            assert(!bytes && named==1);
            int control=socket(AF_UNIX,SOCK_DGRAM,0); assert(control>=0);
            struct ifreq interface={0}; memcpy(interface.ifr_name,"lo",3);
            assert(!ioctl(control,SIOCGIFFLAGS,&interface)); close(control);
            assert((m->ifi_flags&0xffff)==(unsigned short)interface.ifr_flags);
        }
    }
    assert(!remaining);
    assert(expected ? (acks==1 && !links && !done)
        : (links==1 && done==((flags&NLM_F_DUMP)==NLM_F_DUMP)
            && acks==(!(flags&NLM_F_DUMP) && !!(flags&NLM_F_ACK))));
}
static void offline_network(void) {
    int host=open("/proc/self/ns/net",O_RDONLY|O_CLOEXEC); assert(host>=0);
    struct stat before,after; assert(!fstat(host,&before));
    int inherited[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM,0,inherited));
    assert(!unshare(CLONE_NEWNET));
    assert(!stat("/proc/self/ns/net",&after) && before.st_ino!=after.st_ino);
    assert(socket(AF_INET,SOCK_STREAM,0)<0 && errno==EPROTONOSUPPORT);
    int route=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE); assert(route>=0);
    struct timeval timeout={.tv_sec=60}, actual={0};
    assert(!setsockopt(route,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)));
    socklen_t length=sizeof(actual);
    int route_copy=dup(route); assert(route_copy>=0);
    assert(!getsockopt(route_copy,SOL_SOCKET,SO_SNDTIMEO,&actual,&length));
    assert(length==sizeof(actual) && actual.tv_sec==60 && !actual.tv_usec);
    timeout.tv_sec=0; timeout.tv_usec=20000;
    assert(!setsockopt(route_copy,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
    char packet[32];
    /* EVENT_WAIT: empty queue receive; the kernel timeout must return EAGAIN. */
    assert(recv(route,packet,sizeof(packet),0)<0 && errno==EAGAIN);
    timeout.tv_usec=1000000;
    assert(setsockopt(route,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0 && errno==EDOM);
    assert(setsockopt(route,SOL_SOCKET,SO_SNDTIMEO,&timeout,1)<0 && errno==EINVAL);
    assert(setsockopt(route,SOL_SOCKET,SO_SNDTIMEO,(void *)1,sizeof(timeout))<0 && errno==EFAULT);
    int bytes=65536;
    assert(!setsockopt(route,SOL_SOCKET,SO_RCVBUF,&bytes,sizeof(bytes)));
    length=sizeof(bytes); bytes=0;
    assert(!getsockopt(route_copy,SOL_SOCKET,SO_RCVBUF,&bytes,&length) && bytes>=65536);
    assert(setsockopt(route,SOL_SOCKET,SO_BINDTODEVICE,"wlan0",6)<0 && errno==EOPNOTSUPP);
    struct sockaddr_nl bound={.nl_family=AF_NETLINK};
    assert(!bind(route,(void *)&bound,sizeof(bound)));
    loopback_query(route,NLM_F_ACK,0,"lo",0);
    loopback_query(route,0,1,NULL,0);
    loopback_query(route,NLM_F_DUMP,0,NULL,0);
    loopback_query(route,0,0,"wlan0",-ENODEV);
    loopback_query(route,0,2,NULL,-ENODEV);
    struct { struct nlmsghdr header; struct ifinfomsg link; } up={
        .header={.nlmsg_len=sizeof(up),.nlmsg_type=RTM_NEWLINK,.nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK},
        .link={.ifi_index=1,.ifi_flags=IFF_UP,.ifi_change=IFF_UP}};
    assert(sendto(route,&up,sizeof(up),0,(void *)&bound,sizeof(bound))==sizeof(up));
    struct { struct nlmsghdr header; struct nlmsgerr result; } ack;
    assert(recv(route,&ack,sizeof(ack),0)==sizeof(ack) && !ack.result.error);
    loopback_query(route,0,1,NULL,0);
    close(route_copy); close(route);
    int control=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0); assert(control>=0);
    struct ifreq interface={0}; memcpy(interface.ifr_name,"lo",3);
    assert(!ioctl(control,SIOCGIFINDEX,&interface) && interface.ifr_ifindex==1);
    memcpy(interface.ifr_name,"wlan0",6);
    assert(ioctl(control,SIOCGIFINDEX,&interface)<0 && errno==ENODEV); close(control);
    int local[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,local));
    assert(write(inherited[0],"a",1)==1);
    char byte; assert(read(inherited[1],&byte,1)==1 && byte=='a');
    assert(write(local[0],"b",1)==1 && read(local[1],&byte,1)==1 && byte=='b');
    int copy=dup(local[0]); assert(copy>=0);
    assert(!setns(host,CLONE_NEWNET));
    assert(!stat("/proc/self/ns/net",&after) && before.st_ino==after.st_ino);
    struct sockaddr_un address={.sun_family=AF_UNIX}; memcpy(address.sun_path+1,"md-offline",10);
    assert(bind(copy,(void *)&address,sizeof(address))<0 && errno==EOPNOTSUPP);
    int enabled=1;
    assert(setsockopt(copy,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled))<0 && errno==EOPNOTSUPP);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!unshare(CLONE_NEWUSER|CLONE_NEWNET));
        assert(setns(host,CLONE_NEWNET)<0 && errno==EPERM);
        assert(bind(copy,(void *)&address,sizeof(address))<0 && errno==EOPNOTSUPP);
        _exit(0);
    }
    int status;
    /* EVENT_WAIT: namespace child exits; fixture alarm bounds a stuck syscall. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(copy); close(host);
    for (unsigned i=0;i<2;++i) { close(local[i]); close(inherited[i]); }
    puts("PASS offline network: retained identity, loopback lookup, inherited IO, anonymous IPC and namespace authority");
}
int test_namespace_handles_guest(void) {
    alarm(60);
    directory_handles();
    process_directory();
    retained_proc();
    unsupported_namespaces();
    namespace_mounts();
    namespace_mount_lifetime(0);
    offline_network();
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
    assert(!access("/proc/self/ns/net",F_OK));
    assert(!access("/proc/self/ns/pid",F_OK));
    puts("PASS guest namespace handles: stable identities, retained resources, metadata, links, ioctls and independent unshare");
    return 0;
}
