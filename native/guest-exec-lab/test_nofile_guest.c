#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void reaped(pid_t child) {
    int status;
    assert(waitpid(child,&status,0)==child && status==0);
}
static void set_limit(rlim_t soft,rlim_t hard) {
    struct rlimit next={soft,hard};
    int result=setrlimit(RLIMIT_NOFILE,&next);
    if (result) perror("setrlimit nofile");
    assert(!result);
}
static void check_limit(rlim_t soft,rlim_t hard) {
    struct rlimit value;
    assert(!getrlimit(RLIMIT_NOFILE,&value) && value.rlim_cur==soft && value.rlim_max==hard);
    assert(!syscall(SYS_getrlimit,RLIMIT_NOFILE,&value) && value.rlim_cur==soft && value.rlim_max==hard);
    FILE *file=fopen("/proc/self/limits","re"); assert(file);
    char line[256]; unsigned long a,b; int found=0;
    while (fgets(line,sizeof(line),file)) if (sscanf(line,"Max open files %lu %lu",&a,&b)==2) {
        assert(a==soft && b==hard); found=1;
    }
    assert(found && !ferror(file)); fclose(file);
}
static void *worker(void *unused) {
    (void)unused;
    set_limit(129,256);
    return NULL;
}
static void managed_rights(void) {
    int source=open("/proc/sys/fs/nr_open",O_RDONLY|O_CLOEXEC), pair[2];
    assert(source>=0 && !socketpair(AF_UNIX,SOCK_DGRAM,0,pair));
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    char byte='x'; struct iovec io={&byte,1};
    struct msghdr message={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS; header->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header),&source,sizeof(int));
    ssize_t sent=sendmsg(pair[0],&message,0);
    if (sent!=1) perror("send managed rights");
    assert(sent==1);
    memset(&control,0,sizeof(control));
    assert(recvmsg(pair[1],&message,MSG_CMSG_CLOEXEC)==1 && !(message.msg_flags&MSG_CTRUNC));
    header=CMSG_FIRSTHDR(&message);
    assert(header && header->cmsg_level==SOL_SOCKET && header->cmsg_type==SCM_RIGHTS);
    int received; memcpy(&received,CMSG_DATA(header),sizeof(received));
    char expected[64], actual[64];
    ssize_t length=pread(source,expected,sizeof(expected),0);
    assert(length>0 && pread(received,actual,sizeof(actual),0)==length && !memcmp(actual,expected,length));
    close(received); close(source); close(pair[0]); close(pair[1]);
    puts("PASS nofile managed SCM_RIGHTS selector admission");
}
static void scenario(int protected) {
    if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
    FILE *file=fopen("/proc/sys/fs/nr_open","re"); assert(file);
    unsigned long maximum; assert(fscanf(file,"%lu",&maximum)==1); fclose(file);
    set_limit(maximum,maximum);
    check_limit(maximum,maximum);
    managed_rights();
    int high=fcntl(STDOUT_FILENO,F_DUPFD_CLOEXEC,512); assert(high>=512);
    set_limit(128,128);
    check_limit(128,128);
    assert(write(high,"",0)==0);
    errno=0; assert(fcntl(STDOUT_FILENO,F_DUPFD,128)==-1 && errno==EINVAL);
    errno=0; assert(dup3(STDOUT_FILENO,128,0)==-1 && errno==EBADF);
    assert(!close(high));
    set_limit(256,256);
    pthread_t thread; assert(!pthread_create(&thread,NULL,worker,NULL));
    assert(!pthread_join(thread,NULL)); check_limit(129,256);
    struct rlimit next={128,256}, old;
    errno=0;
    assert(syscall(SYS_prlimit64,0,RLIMIT_NOFILE,&next,(void *)1)==-1 && errno==EFAULT);
    check_limit(128,256);
    errno=0; assert(syscall(SYS_setrlimit,RLIMIT_NOFILE,(void *)1)==-1 && errno==EFAULT);
    check_limit(128,256);
    next=(struct rlimit){257,256}; errno=0;
    assert(setrlimit(RLIMIT_NOFILE,&next)==-1 && errno==EINVAL);
    next=(struct rlimit){RLIM_INFINITY,RLIM_INFINITY}; errno=0;
    assert(setrlimit(RLIMIT_NOFILE,&next)==-1 && errno==EPERM);

    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,pair));
    int fds[128], count=0;
    while (count<128) {
        int fd=dup(STDOUT_FILENO);
        if (fd<0) { assert(errno==EMFILE); break; }
        assert(fd<128); fds[count++]=fd;
    }
    assert(count && count<128);
    errno=0; assert(eventfd(0,0)==-1 && errno==EMFILE);
    int pipes[2]; errno=0; assert(pipe(pipes)==-1 && errno==EMFILE);
    errno=0; assert(open("/etc/os-release",O_RDONLY)==-1 && errno==EMFILE);
    errno=0; assert(socket(AF_UNIX,SOCK_STREAM,0)==-1 && errno==EMFILE);
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    char byte='x'; struct iovec io={&byte,1};
    struct msghdr message={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS; header->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header),&pair[0],sizeof(int));
    assert(sendmsg(pair[0],&message,0)==1);
    memset(&control,0,sizeof(control));
    assert(recvmsg(pair[1],&message,0)==1 && (message.msg_flags&MSG_CTRUNC));
    for (int i=0;i<count;++i) assert(!close(fds[i]));
    close(pair[0]); close(pair[1]);
    set_limit(maximum,maximum);
    assert(!getrlimit(RLIMIT_NOFILE,&old) && old.rlim_max==maximum);
    check_limit(maximum,maximum);
    printf("PASS nofile guest: enforcement, existing FD, threads, faults, rights, exhaustion and recovery (protected=%d)\n",protected);
}
static void foreign(void) {
    int ready[2], release[2]; assert(!pipe(ready) && !pipe(release));
    set_limit(256,256);
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_DUMPABLE,0));
        assert(write(ready[1],"r",1)==1);
        char byte; assert(read(release[0],&byte,1)==1);
        check_limit(128,128);
        struct rlimit next={512,512}, old;
        assert(!syscall(SYS_prlimit64,parent,RLIMIT_NOFILE,&next,&old) && old.rlim_cur==256);
        assert(!setgid(23459) && !setuid(23459));
        errno=0; assert(syscall(SYS_prlimit64,parent,RLIMIT_NOFILE,NULL,&old)==-1 && errno==EPERM);
        errno=0; assert(setrlimit(RLIMIT_NOFILE,&next)==-1 && errno==EPERM);
        _exit(0);
    }
    char byte;
    /* EVENT_WAIT: child has disabled dumpability before the foreign update. */
    assert(read(ready[0],&byte,1)==1);
    struct rlimit next={128,128}, old;
    assert(!syscall(SYS_prlimit64,child,RLIMIT_NOFILE,&next,&old) && old.rlim_cur==256);
    assert(write(release[1],"r",1)==1);
    reaped(child); check_limit(512,512);
    close(ready[0]); close(ready[1]); close(release[0]); close(release[1]);
    puts("PASS nofile foreign protected process, credentials and fork copy");
}
static void denied(void) {
    struct rlimit old, after, next={128,128}; assert(!getrlimit(RLIMIT_NOFILE,&old));
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prlimit64,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog filter={sizeof(code)/sizeof(code[0]),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&filter));
    errno=0; assert(syscall(SYS_prlimit64,0,RLIMIT_NOFILE,&next,NULL)==-1 && errno==EPERM);
    assert(!getrlimit(RLIMIT_NOFILE,&after) && after.rlim_cur==old.rlim_cur && after.rlim_max==old.rlim_max);
    puts("PASS nofile application seccomp denial");
}
int main(int argc,char **argv) {
    if (argc==2 && !strcmp(argv[1],"--exec")) {
        check_limit(256,256); puts("PASS nofile exec inheritance"); return 0;
    }
    alarm(60);
    for (int i=0;i<5;++i) {
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            if (i<2) scenario(i);
            else if (i==2) foreign();
            else if (i==3) denied();
            else {
                set_limit(256,256);
                execl(argv[0],argv[0],"--exec",NULL); assert(!"exec failed");
            }
            fflush(stdout); _exit(0);
        }
        reaped(child);
    }
    puts("PASS RLIMIT_NOFILE");
}
