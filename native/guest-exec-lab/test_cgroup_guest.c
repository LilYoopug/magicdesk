#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

static void read_text(const char *path,char *text,size_t size) {
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd<0) fprintf(stderr,"cgroup open %s: %s\n",path,strerror(errno));
    assert(fd>=0); ssize_t n=read(fd,text,size-1);
    if (n<0) fprintf(stderr,"cgroup read %s: %s\n",path,strerror(errno));
    assert(n>=0); text[n]=0; close(fd);
}
static int writing(const char *path,const char *text) {
    int fd=open(path,O_WRONLY|O_CLOEXEC); assert(fd>=0);
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
        if (!child) _exit(test_cgroup_guest(0));
        int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
        puts("PASS guest cgroup: PID namespace membership"); return 0;
    }
    alarm(45); assert(!unshare(CLONE_NEWNS));
    assert(!mkdir("/tmp/cgv2",0700) && !mkdir("/tmp/cgv1",0700));
    int r=mount("none","/tmp/cgv2","cgroup2",MS_NOSUID|MS_NOEXEC|MS_NODEV,NULL);
    if (r) perror("cgroup2 mount"); assert(!r);
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
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        read_text("/proc/self/cgroup",text,sizeof(text)); assert(strstr(text,"0::/child\n"));
        assert(write(copy,"0",1)==1); _exit(0);
    }
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
