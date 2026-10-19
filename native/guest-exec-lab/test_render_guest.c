#define _GNU_SOURCE
#include <assert.h>
#include <drm/drm.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static void version(int fd) {
    struct stat st; assert(!fstat(fd,&st) && S_ISCHR(st.st_mode) && major(st.st_rdev)==226);
    struct drm_version v={0}; assert(!ioctl(fd,DRM_IOCTL_VERSION,&v) && v.name_len==6);
    char name[8]; memset(name,'x',sizeof(name));
    v.name=name; v.name_len=3;
    assert(!ioctl(fd,DRM_IOCTL_VERSION,&v) && v.name_len==6 && !memcmp(name,"shrxxxxx",8));
    v.name_len=sizeof(name);
    assert(!ioctl(fd,DRM_IOCTL_VERSION,&v) && v.name_len==6 && !memcmp(name,"shrootxx",8));
    v.name=(void *)1; v.name_len=6;
    assert(ioctl(fd,DRM_IOCTL_VERSION,&v)==-1 && errno==EFAULT);
    assert(ioctl(fd,DRM_IOCTL_VERSION,(void *)1)==-1 && errno==EFAULT);
    assert(ioctl(fd,DRM_IOCTL_GET_CAP,&v)==-1 && errno==ENOTTY);
    assert(write(fd,"x",1)==-1 && errno==EINVAL);
}
int main(int argc,char **argv) {
    assert(argc==2);
    int fd=open(argv[1],O_RDWR|O_CLOEXEC); assert(fd>=0);
    struct stat st; assert(!fstat(fd,&st)); unsigned number=minor(st.st_rdev);
    version(fd);
    int alias=fcntl(fd,F_DUPFD_CLOEXEC,0); assert(alias>=0);
    version(alias); assert(!close(alias));
    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,pair));
    char data=1,control[CMSG_SPACE(sizeof(int))]={0};
    struct iovec io={&data,1};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg); c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS;
    c->cmsg_len=CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(c),&fd,sizeof(fd));
    assert(sendmsg(pair[0],&msg,0)==1);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(fd); close(pair[0]);
        memset(control,0,sizeof(control)); assert(recvmsg(pair[1],&msg,MSG_CMSG_CLOEXEC)==1);
        c=CMSG_FIRSTHDR(&msg); assert(c && c->cmsg_type==SCM_RIGHTS);
        int received; memcpy(&received,CMSG_DATA(c),sizeof(received));
        version(received); close(received); close(pair[1]); _exit(0);
    }
    int status; assert(waitpid(child,&status,0)==child && status==0);
    close(pair[0]); close(pair[1]); close(fd);
    char target[]="/tmp/render-bind-XXXXXX";
    fd=mkstemp(target); assert(fd>=0); close(fd);
    assert(!unshare(CLONE_NEWNS));
    assert(!mount(argv[1],target,NULL,MS_BIND,NULL));
    fd=open(target,O_RDWR); assert(fd>=0); version(fd);
    assert(!umount2(target,MNT_DETACH)); version(fd); close(fd); unlink(target);
    assert(!unshare(CLONE_NEWNET));
    assert(!mount("sysfs","/sys","sysfs",0,NULL));
    char path[128]; snprintf(path,sizeof(path),"/sys/dev/char/226:%u/device/drm/renderD%u",number,number);
    assert(!access(path,F_OK));
    snprintf(path,sizeof(path),"/sys/dev/char/226:%u/device/uevent",number);
    char modalias[128]={0}; fd=open(path,O_RDONLY); assert(fd>=0);
    assert(read(fd,modalias,sizeof(modalias)-1)>0 && strstr(modalias,"platform:shroot-gpu")); close(fd);
    assert(!umount2("/sys",MNT_DETACH));
    puts("PASS render ioctl pointers, truncated output, SCM_RIGHTS, fork, bind lifetime and fresh sysfs");
    return 0;
}
