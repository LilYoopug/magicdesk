#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

static const char *membership_proc="/proc";
static void read_text(const char *path,char *text,size_t size) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOCTTY);
    if (fd<0) fprintf(stderr,"cgroup open %s: %s\n",path,strerror(errno));
    assert(fd>=0); ssize_t n=read(fd,text,size-1);
    if (n<0) fprintf(stderr,"cgroup read %s: %s\n",path,strerror(errno));
    assert(n>=0); text[n]=0; close(fd);
}
static int writing(const char *path,const char *text) {
    int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOCTTY); assert(fd>=0);
    ssize_t n=write(fd,text,strlen(text)); int error=errno; close(fd); errno=error;
    return (int)n;
}
static void *thread_membership(void *unused) {
    (void)unused;
    char text[8192],pid[32],tid[32];
    snprintf(pid,sizeof(pid),"%d\n",getpid());
    snprintf(tid,sizeof(tid),"%ld\n",syscall(SYS_gettid));
    read_text("/tmp/cgv2/child/cgroup.procs",text,sizeof(text));
    char *first=strstr(text,pid); assert(first && !strstr(first+strlen(pid),pid));
    read_text("/tmp/cgv2/child/cgroup.threads",text,sizeof(text));
    assert(strstr(text,pid) && strstr(text,tid));
    return NULL;
}
int test_cgroup_guest(int pid_namespace) {
    if (pid_namespace) {
        alarm(45); assert(!unshare(CLONE_NEWPID));
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            assert(!unshare(CLONE_NEWNS));
            membership_proc="/tmp/cg-proc";
            assert(!mkdir(membership_proc,0700));
            int mounted=mount("proc",membership_proc,"proc",0,NULL);
            if (mounted) perror("PID cgroup proc mount");
            assert(!mounted);
            int result=test_cgroup_guest(0);
            assert(!umount2(membership_proc,0) && !rmdir(membership_proc));
            _exit(result);
        }
        int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
        puts("PASS guest cgroup: PID namespace membership"); return 0;
    }
    alarm(45); assert(!unshare(CLONE_NEWNS));
    assert(!mkdir("/tmp/cgv2",0700) && !mkdir("/tmp/cgv1",0700));
    int r=mount("none","/tmp/cgv2","cgroup2",MS_NOSUID|MS_NOEXEC|MS_NODEV,NULL);
    if (r) perror("cgroup2 mount"); assert(!r);
    assert(!umount2("/tmp/cgv2",0));
    assert(!mount("none","/tmp/cgv2","cgroup2",MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REC|MS_RELATIME,NULL));
    assert(!mount("none","/tmp/cgv1","cgroup",MS_NOSUID|MS_NOEXEC|MS_NODEV,"devices"));
    struct statfs st; assert(!statfs("/tmp/cgv2",&st) && st.f_type==CGROUP2_SUPER_MAGIC);
    assert(!statfs("/tmp/cgv1",&st) && st.f_type==CGROUP_SUPER_MAGIC);
    char text[8192]; read_text("/tmp/cgv2/cgroup.controllers",text,sizeof(text)); assert(!strcmp(text,"\n"));
    read_text("/tmp/cgv1/devices.list",text,sizeof(text)); assert(!strcmp(text,"a *:* rwm\n"));
    assert(writing("/tmp/cgv1/devices.allow","a *:* rwm")==9);
    assert(writing("/tmp/cgv1/devices.deny","a")<0 && errno==EOPNOTSUPP);
    assert(!mkdir("/tmp/cgv2/child",0700));
    assert(writing("/tmp/cgv2/child/cgroup.procs","0")==1);
    read_text("/proc/self/cgroup",text,sizeof(text)); assert(strstr(text,"0::/child\n"));
    read_text("/tmp/cgv2/child/cgroup.procs",text,sizeof(text));
    char pid[32]; snprintf(pid,sizeof(pid),"%d\n",getpid()); assert(strstr(text,pid));
    pthread_t worker;
    assert(!pthread_create(&worker,NULL,thread_membership,NULL));
    assert(!pthread_join(worker,NULL));
    assert(open("/tmp/cgv2/child/cgroup.procs",O_RDWR|O_CREAT|O_EXCL,0600)<0 && errno==EEXIST);
    int fd=open("/tmp/cgv2/child/cgroup.procs",O_RDWR|O_CLOEXEC); assert(fd>=0);
    assert(!fstatfs(fd,&st) && st.f_type==CGROUP2_SUPER_MAGIC);
    int copy=dup(fd); assert(copy>=0);
    char alias[64]; snprintf(alias,sizeof(alias),"/proc/self/fd/%d",copy);
    read_text(alias,text,sizeof(text)); assert(strstr(text,pid));
    assert(!mkdir("/tmp/cgv2/zombie",0700) && !mkdir("/tmp/cgv1/zombie",0700));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        read_text("/proc/self/cgroup",text,sizeof(text)); assert(strstr(text,"0::/child\n"));
        assert(write(copy,"0",1)==1);
        assert(writing("/tmp/cgv2/zombie/cgroup.procs","0")==1);
        assert(writing("/tmp/cgv1/zombie/cgroup.procs","0")==1); _exit(0);
    }
    /* EVENT_WAIT: retain the exited child until proc inspection; alarm bounds failure. */
    siginfo_t exited={0};
    assert(!waitid(P_PID,child,&exited,WEXITED|WNOWAIT) && exited.si_pid==child);
    char exited_path[64]; snprintf(exited_path,sizeof(exited_path),"%s/%d/cgroup",membership_proc,child);
    read_text(exited_path,text,sizeof(text));
    assert(strstr(text,"0::/zombie\n") && strstr(text,"1:devices:/\n"));
    int membership=open(exited_path,O_RDONLY|O_CLOEXEC); assert(membership>=0);
    assert(!rmdir("/tmp/cgv2/zombie") && !rmdir("/tmp/cgv1/zombie"));
    read_text(exited_path,text,sizeof(text)); assert(strstr(text,"0::/zombie (deleted)\n"));
    ssize_t length=read(membership,text,sizeof(text)-1); assert(length>=0); text[length]=0;
    assert(strstr(text,"0::/zombie (deleted)\n")); close(membership);
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(rmdir("/tmp/cgv2/child")<0 && errno==EBUSY);
    assert(writing("/tmp/cgv2/cgroup.freeze","1")<0 && errno==EOPNOTSUPP);
    assert(writing("/tmp/cgv2/cgroup.subtree_control","+memory")<0 && errno==EOPNOTSUPP);
    assert(!mount(NULL,"/tmp/cgv2",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY,NULL));
    assert(write(copy,"0",1)<0 && errno==EROFS);
    assert(!mount(NULL,"/tmp/cgv2",NULL,MS_BIND|MS_REMOUNT,NULL));
    close(copy); close(fd);
    assert(writing("/tmp/cgv2/cgroup.procs","0")==1);
    assert(!rmdir("/tmp/cgv2/child"));
    for (unsigned i=0;i<32;++i) {
        assert(!mkdir("/tmp/cgv2/reused",0700));
        int retired=open("/tmp/cgv2/reused/cgroup.procs",O_RDONLY|O_CLOEXEC); assert(retired>=0);
        assert(!rmdir("/tmp/cgv2/reused"));
        assert(!mkdir("/tmp/cgv2/reused",0700));
        assert(read(retired,text,sizeof(text))<0 && errno==ENODEV);
        close(retired); assert(!rmdir("/tmp/cgv2/reused"));
    }
    read_text("/proc/cgroups",text,sizeof(text)); assert(strstr(text,"devices\t1\t1\t1"));
    assert(!umount2("/tmp/cgv2",0) && !umount2("/tmp/cgv1",0));
    assert(!rmdir("/tmp/cgv2") && !rmdir("/tmp/cgv1"));
    puts("PASS guest cgroup: membership, fork, typed IO, readonly and permissive devices"); return 0;
}
static void expect_membership(int fd,const char *v2,const char *v1) {
    char text[8192],expected[8192];
    assert(!lseek(fd,0,SEEK_SET));
    ssize_t n=read(fd,text,sizeof(text)-1); assert(n>=0); text[n]=0;
    snprintf(expected,sizeof(expected),"0::%s\n1:devices:%s\n",v2,v1);
    if (strcmp(text,expected)) fprintf(stderr,"membership: got %s expected %s",text,expected);
    assert(!strcmp(text,expected));
}
static void same_directory(const char *a,const char *b) {
    struct stat sa,sb;
    assert(!stat(a,&sa) && !stat(b,&sb));
    assert(sa.st_dev==sb.st_dev && sa.st_ino==sb.st_ino);
}
static void reap_namespace(pid_t child) {
    int status;
    /* EVENT_WAIT: exact child completion; fixture alarm bounds failure. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
}
int test_cgroup_namespace_guest(void) {
    alarm(60);
    /* The imported fixture starts as shell-owned 0700. The unmapped user
     * namespace needs search access, independently of namespace capability. */
    assert(!chmod("/",0755));
    assert(!unshare(CLONE_NEWNS));
    const char *mounts[]={"/tmp/cgn-v2","/tmp/cgn-v1","/tmp/cgn-local","/tmp/cgn-devices","/tmp/cgn-context"};
    for (unsigned i=0;i<5;++i) assert(!mkdir(mounts[i],0700));
    int host=open("/proc/self/ns/cgroup",O_RDONLY|O_CLOEXEC); assert(host>=0);
    struct stat initial; assert(!fstat(host,&initial));
    assert(ioctl(host,NS_GET_NSTYPE)==CLONE_NEWCGROUP);
    assert(ioctl(host,NS_GET_PARENT)<0 && errno==EINVAL);
    int owner=ioctl(host,NS_GET_USERNS); assert(owner>=0);
    struct stat a,b; assert(!fstat(owner,&a) && !stat("/proc/self/ns/user",&b));
    assert(a.st_ino==b.st_ino && a.st_dev==b.st_dev); close(owner);
    assert(!mount("none",mounts[0],"cgroup2",0,NULL));
    assert(!mount("none",mounts[1],"cgroup",0,"devices"));
    assert(!mkdir("/tmp/cgn-v2/child",0700) && !mkdir("/tmp/cgn-v2/sibling",0700));
    assert(!mkdir("/tmp/cgn-v1/device-child",0700));
    assert(writing("/tmp/cgn-v2/child/cgroup.procs","0")==1);
    assert(writing("/tmp/cgn-v1/device-child/cgroup.procs","0")==1);
    int membership=open("/proc/self/cgroup",O_RDONLY|O_CLOEXEC); assert(membership>=0);
    expect_membership(membership,"/child","/device-child");
    int context=syscall(SYS_fsopen,"cgroup2",FSOPEN_CLOEXEC); assert(context>=0);
    assert(!unshare(CLONE_NEWCGROUP));
    assert(!stat("/proc/self/ns/cgroup",&a) && a.st_ino!=initial.st_ino);
    expect_membership(membership,"/","/");
    assert(!mkdir("/tmp/cgn-proc",0755));
    assert(!mount("none","/tmp/cgn-proc","proc",0,NULL));
    int proc_member=open("/tmp/cgn-proc/self/cgroup",O_RDONLY); assert(proc_member>=0);
    expect_membership(proc_member,"/","/");
    char controllers[1024]; read_text("/tmp/cgn-proc/cgroups",controllers,sizeof(controllers));
    assert(strstr(controllers,"devices\t1\t2\t1"));
    int local=open("/proc/thread-self/ns/cgroup",O_RDONLY|O_CLOEXEC); assert(local>=0);
    int copy=dup(local); assert(copy>=0);
    char path[128]; snprintf(path,sizeof(path),"/proc/self/fd/%d",copy);
    int reopened=open(path,O_RDONLY|O_CLOEXEC); assert(reopened>=0); close(copy);
    assert(!fstat(reopened,&b) && a.st_ino==b.st_ino);
    assert(!mount("none",mounts[2],"cgroup2",0,NULL));
    assert(!mount("none",mounts[3],"cgroup",0,"devices"));
    same_directory(mounts[2],"/tmp/cgn-v2/child");
    same_directory(mounts[3],"/tmp/cgn-v1/device-child");
    assert(!mkdir("/tmp/cgn-local/nested",0700));
    same_directory("/tmp/cgn-local/nested","/tmp/cgn-v2/child/nested");
    assert(!syscall(SYS_fsconfig,context,FSCONFIG_CMD_CREATE,NULL,NULL,0));
    int detached=syscall(SYS_fsmount,context,FSMOUNT_CLOEXEC,0); assert(detached>=0); close(context);
    assert(!syscall(SYS_move_mount,detached,"",AT_FDCWD,mounts[4],MOVE_MOUNT_F_EMPTY_PATH)); close(detached);
    same_directory(mounts[4],mounts[0]);
    assert(writing("/tmp/cgn-local/nested/cgroup.procs","0")==1);
    expect_membership(membership,"/nested","/");
    expect_membership(proc_member,"/nested","/");
    pid_t child=syscall(SYS_clone,CLONE_NEWCGROUP|SIGCHLD,0,NULL,0,NULL); assert(child>=0);
    if (!child) {
        int self=open("/proc/self/cgroup",O_RDONLY); assert(self>=0);
        expect_membership(self,"/","/");
        assert(!stat("/proc/self/ns/cgroup",&b) && b.st_ino!=a.st_ino);
        assert(!setns(host,CLONE_NEWCGROUP));
        expect_membership(self,"/child/nested","/device-child"); close(self); _exit(0);
    }
    reap_namespace(child);
    expect_membership(membership,"/nested","/");
    assert(!setns(host,0)); expect_membership(membership,"/child/nested","/device-child");
    assert(!setns(reopened,CLONE_NEWCGROUP)); expect_membership(membership,"/nested","/");
    assert(setns(reopened,CLONE_NEWNET)<0 && errno==EINVAL);
    assert(writing("/tmp/cgn-v2/sibling/cgroup.procs","0")==1);
    expect_membership(membership,"/../sibling","/");
    assert(writing("/tmp/cgn-v2/cgroup.procs","0")==1);
    expect_membership(membership,"/..","/");
    child=fork(); assert(child>=0);
    if (!child) {
        assert(!unshare(CLONE_NEWUSER|CLONE_NEWCGROUP));
        assert(setns(host,CLONE_NEWCGROUP)<0 && errno==EPERM);
        assert(ioctl(host,NS_GET_USERNS)<0 && errno==EPERM);
        int self=open("/proc/self/ns/cgroup",O_RDONLY);
        if (self<0) perror("child cgroup namespace open");
        assert(self>=0);
        owner=ioctl(self,NS_GET_USERNS); assert(owner>=0);
        assert(!fstat(owner,&a) && !stat("/proc/self/ns/user",&b) && a.st_ino==b.st_ino);
        close(owner); close(self); _exit(0);
    }
    reap_namespace(child);
    assert(!setns(host,CLONE_NEWCGROUP));
    int ready[2],finish[2]; assert(!pipe(ready) && !pipe(finish));
    child=fork(); assert(child>=0);
    if (!child) {
        close(ready[0]); close(finish[1]);
        assert(writing("/tmp/cgn-v2/sibling/cgroup.procs","0")==1);
        assert(!unshare(CLONE_NEWCGROUP));
        assert(write(ready[1],"x",1)==1);
        char byte;
        /* EVENT_WAIT: parent captures this namespace; alarm bounds failure. */
        assert(read(finish[0],&byte,1)==1); _exit(0);
    }
    close(ready[1]); close(finish[0]);
    char byte;
    /* EVENT_WAIT: child publishes namespace identity; alarm bounds failure. */
    assert(read(ready[0],&byte,1)==1); close(ready[0]);
    snprintf(path,sizeof(path),"/proc/%d/ns/cgroup",child);
    int retained=open(path,O_RDONLY|O_CLOEXEC); assert(retained>=0);
    assert(write(finish[1],"x",1)==1); close(finish[1]); reap_namespace(child);
    assert(!setns(retained,CLONE_NEWCGROUP)); expect_membership(membership,"/..","/");
    assert(!umount2(mounts[2],0));
    assert(!mount("none",mounts[2],"cgroup2",0,NULL));
    same_directory(mounts[2],"/tmp/cgn-v2/sibling");
    assert(!umount2(mounts[2],0) && !rmdir("/tmp/cgn-v2/sibling"));
    assert(mount("none",mounts[2],"cgroup2",0,NULL)<0 && errno==ENOENT);
    assert(!setns(host,CLONE_NEWCGROUP));
    assert(writing("/tmp/cgn-v1/cgroup.procs","0")==1);
    assert(!rmdir("/tmp/cgn-v2/child/nested") && !rmdir("/tmp/cgn-v2/child"));
    assert(!umount2(mounts[3],0) && !rmdir("/tmp/cgn-v1/device-child"));
    assert(!umount2(mounts[4],0) && !umount2(mounts[0],0) && !umount2(mounts[1],0));
    for (unsigned i=0;i<5;++i) assert(!rmdir(mounts[i]));
    close(retained); close(local); close(reopened); close(membership); close(host);
    close(proc_member); assert(!umount2("/tmp/cgn-proc",0) && !rmdir("/tmp/cgn-proc"));
    puts("PASS guest cgroup namespace: captured roots, membership, clone/setns, lifetime, authority and fsopen");
    return 0;
}
