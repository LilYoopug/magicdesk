#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { LISTENER, REPLACE, CHECK, ACK, DONE, STOP, INSTALLED, CONTINUE };
enum scenario { SPLIT, ATOMIC, CANCEL_SPLIT, CANCEL_ATOMIC, PATH_FD, RIGHTS };
struct message { int kind, number, error; long position; };
struct fixture { int control, data, source, replacement, target; enum scenario scenario; };

static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned count=0; while (readdir(dir)) ++count;
    closedir(dir); return count;
}
static void send_message(int socket, struct message value, int fd) {
    struct iovec vector={&value,sizeof(value)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1};
    if (fd>=0) {
        message.msg_control=control.bytes; message.msg_controllen=sizeof(control);
        struct cmsghdr *c=CMSG_FIRSTHDR(&message);
        c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(fd));
        memcpy(CMSG_DATA(c),&fd,sizeof(fd));
    }
    /* EVENT_WAIT: bounded fixture channel; alarm/parent death ends a stuck peer. */
    ssize_t n; do { n=sendmsg(socket,&message,MSG_NOSIGNAL); } while (n<0 && errno==EINTR);
    assert(n==sizeof(value));
}
static struct message receive_message(int socket, int *fd) {
    struct message value;
    struct iovec vector={&value,sizeof(value)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=sizeof(control)};
    /* EVENT_WAIT: explicit peer acknowledgement, not a settling interval. */
    ssize_t n; do { n=recvmsg(socket,&message,MSG_CMSG_CLOEXEC); } while (n<0 && errno==EINTR);
    assert(n==sizeof(value) && !(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC)));
    struct cmsghdr *c=CMSG_FIRSTHDR(&message);
    if (fd) *fd=-1;
    if (c) {
        assert(fd && c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS
            && c->cmsg_len==CMSG_LEN(sizeof(int)) && !CMSG_NXTHDR(&message,c));
        memcpy(fd,CMSG_DATA(c),sizeof(*fd));
    }
    return value;
}
static void signal_handler(int signal) { (void)signal; }
static int listener(void) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getppid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    int fd=syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&program);
    assert(fd>=0); return fd;
}
static void replace(const struct fixture *f, int fd) {
    assert(lseek(fd,0,SEEK_CUR)==11);
    struct stat before, after;
    assert(!fstat(fd,&before));
    assert(dup3(f->replacement,fd,O_CLOEXEC)==fd);
    assert(!fstat(fd,&after));
    /* An inode consistency check cannot distinguish these open descriptions. */
    assert(before.st_dev==after.st_dev && before.st_ino==after.st_ino);
    assert(lseek(fd,0,SEEK_CUR)==29);
}
static void *requester(void *context) {
    struct fixture *f=context;
    if (f->scenario==RIGHTS) {
        int fd=-1;
        struct message value=receive_message(f->data,&fd);
        assert(value.kind==INSTALLED && fd>=0 && lseek(fd,0,SEEK_CUR)==11);
        send_message(f->control,(struct message){.kind=INSTALLED,.number=fd},-1);
        value=receive_message(f->data,NULL); assert(value.kind==CONTINUE);
        assert(lseek(fd,0,SEEK_CUR)==29);
        close(fd);
        send_message(f->control,(struct message){.kind=DONE},-1);
        return NULL;
    }
    int fd=listener();
    send_message(f->control,(struct message){.kind=LISTENER},fd);
    close(fd);
    errno=0;
    long result=syscall(SYS_getppid);
    int error=result<0 ? errno : 0;
    if (f->scenario==SPLIT || f->scenario==ATOMIC) {
        assert(result==f->target);
        if (f->scenario==ATOMIC) replace(f,f->target);
        assert(lseek(f->target,0,SEEK_CUR)==29);
    } else {
        assert(result==-1 && error==(f->scenario==PATH_FD ? ENOTSUP : EINTR));
        assert(lseek(f->target,0,SEEK_CUR)==(f->scenario==CANCEL_SPLIT ? 11 : 47));
    }
    send_message(f->control,(struct message){.kind=DONE,.number=(int)result,.error=error,
        .position=lseek(f->target,0,SEEK_CUR)},-1);
    return NULL;
}
static void child(struct fixture *f, pid_t parent) {
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=parent) _exit(1);
    alarm(20);
    struct sigaction action={.sa_handler=signal_handler}; sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1,&action,NULL));
    pthread_t task; assert(!pthread_create(&task,NULL,requester,f));
    for (;;) {
        struct message value=receive_message(f->control,NULL);
        if (value.kind==STOP) break;
        if (value.kind==REPLACE) replace(f,value.number);
        else assert(value.kind==CHECK && lseek(value.number,0,SEEK_CUR)==value.position);
        send_message(f->control,(struct message){.kind=ACK},-1);
    }
    /* EVENT_WAIT: requester completion; process alarm is a failure bound. */
    assert(!pthread_join(task,NULL));
    _exit(0);
}
static void peer_command(int control, int kind, int fd, long position) {
    send_message(control,(struct message){.kind=kind,.number=fd,.position=position},-1);
    struct message value=receive_message(control,NULL); assert(value.kind==ACK);
}
static void completed(int control) {
    struct message value=receive_message(control,NULL); assert(value.kind==DONE);
}
static int create_file(const char *path, long position) {
    int fd=open(path,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600); assert(fd>=0);
    assert(lseek(fd,position,SEEK_SET)==position); return fd;
}
static void scenario(enum scenario scenario, const char *directory) {
    unsigned before=descriptors();
    int control[2], data[2];
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,control));
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,data));
    char source_path[PATH_MAX], initial_path[PATH_MAX];
    assert(snprintf(source_path,sizeof(source_path),"%s/source",directory)<(int)sizeof(source_path));
    assert(snprintf(initial_path,sizeof(initial_path),"%s/initial",directory)<(int)sizeof(initial_path));
    int source=create_file(source_path,11), initial=create_file(initial_path,47);
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",source);
    int replacement=open(source_path,O_RDWR|O_CLOEXEC); assert(replacement>=0);
    assert(!unlink(source_path) && !unlink(initial_path));
    assert(lseek(replacement,29,SEEK_SET)==29);
    int target=fcntl(initial,F_DUPFD_CLOEXEC,64); assert(target>=64);
    struct fixture f={control[1],data[1],source,replacement,target,scenario};
    pid_t parent=getpid(), pid=fork(); assert(pid>=0);
    if (!pid) { close(control[0]); close(data[0]); child(&f,parent); }
    close(control[1]); close(data[1]);
    if (scenario==RIGHTS) {
        send_message(data[0],(struct message){.kind=INSTALLED},source);
        struct message value=receive_message(control[0],NULL); assert(value.kind==INSTALLED);
        peer_command(control[0],REPLACE,value.number,0);
        send_message(data[0],(struct message){.kind=CONTINUE},-1);
        completed(control[0]);
    } else {
        int notify=-1;
        struct message value=receive_message(control[0],&notify);
        assert(value.kind==LISTENER && notify>=0);
        struct seccomp_notif request={0};
        /* EVENT_WAIT: the exact kernel notification; alarm terminates a stalled case. */
        assert(!ioctl(notify,SECCOMP_IOCTL_NOTIF_RECV,&request));
        assert(request.data.nr==SYS_getppid);
        struct seccomp_notif_addfd add={.id=request.id,.srcfd=source,.newfd=target,
            .flags=SECCOMP_ADDFD_FLAG_SETFD,.newfd_flags=O_CLOEXEC};
        struct seccomp_notif_resp reply={.id=request.id,.val=target};
        if (scenario==SPLIT || scenario==CANCEL_SPLIT) {
            assert(ioctl(notify,SECCOMP_IOCTL_NOTIF_ADDFD,&add)==target);
            assert(!ioctl(notify,SECCOMP_IOCTL_NOTIF_ID_VALID,&request.id));
        }
        if (scenario==SPLIT) {
            peer_command(control[0],REPLACE,target,0);
            assert(!ioctl(notify,SECCOMP_IOCTL_NOTIF_SEND,&reply)); completed(control[0]);
        } else if (scenario==ATOMIC) {
            add.flags|=SECCOMP_ADDFD_FLAG_SEND;
            assert(ioctl(notify,SECCOMP_IOCTL_NOTIF_ADDFD,&add)==target);
            /* The recipient may replace the FD before any later origin publication. */
            completed(control[0]);
        } else if (scenario==PATH_FD) {
            int pinned=open(path,O_PATH|O_CLOEXEC); assert(pinned>=0);
            add.srcfd=pinned;
            assert(ioctl(notify,SECCOMP_IOCTL_NOTIF_ADDFD,&add)==-1 && errno==EBADF);
            close(pinned); reply.val=0; reply.error=-ENOTSUP;
            assert(!ioctl(notify,SECCOMP_IOCTL_NOTIF_SEND,&reply)); completed(control[0]);
        } else {
            assert(!syscall(SYS_tgkill,pid,request.pid,SIGUSR1));
            completed(control[0]);
            assert(ioctl(notify,SECCOMP_IOCTL_NOTIF_ID_VALID,&request.id)==-1 && errno==ENOENT);
            if (scenario==CANCEL_ATOMIC) {
                add.flags|=SECCOMP_ADDFD_FLAG_SEND;
                assert(ioctl(notify,SECCOMP_IOCTL_NOTIF_ADDFD,&add)==-1 && errno==ENOENT);
            } else assert(ioctl(notify,SECCOMP_IOCTL_NOTIF_SEND,&reply)==-1 && errno==ENOENT);
            peer_command(control[0],CHECK,target,scenario==CANCEL_SPLIT ? 11 : 47);
        }
        close(notify);
    }
    send_message(control[0],(struct message){.kind=STOP},-1);
    int status;
    /* EVENT_WAIT: exact fixture child exit, bounded by parent/child alarms. */
    assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && !WEXITSTATUS(status));
    close(control[0]); close(data[0]); close(source); close(replacement); close(initial); close(target);
    assert(descriptors()==before);
}
int main(int argc, char **argv) {
    assert(argc==2 && !mkdir(argv[1],0700));
    alarm(30);
    scenario(SPLIT,argv[1]);
    puts("PASS split ADDFD: CLONE_FILES peer replaces same-inode description before reply");
    scenario(ATOMIC,argv[1]);
    puts("PASS atomic ADDFD_SEND: recipient can reuse FD before later metadata publication");
    scenario(CANCEL_SPLIT,argv[1]);
    puts("PASS cancelled split delivery retains installed FD despite EINTR and stale notification");
    scenario(CANCEL_ATOMIC,argv[1]);
    puts("PASS cancelled atomic delivery leaves prior destination untouched");
    scenario(PATH_FD,argv[1]);
    puts("PASS ADDFD rejects O_PATH without replacing destination");
    scenario(RIGHTS,argv[1]);
    puts("PASS SCM_RIGHTS: shared-table replacement precedes receiver acknowledgement");
    puts("PASS native FD publication boundaries and descriptor cleanup");
    assert(!rmdir(argv[1]));
    return 0;
}
