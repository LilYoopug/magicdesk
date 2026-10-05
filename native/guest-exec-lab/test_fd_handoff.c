#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fd_origins.h"
#include "fd_exchange.h"
#include "fd_receipt.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { LISTENER, REPLACE, CHECK, ACK, DONE, STOP, INSTALLED, CONTINUE };
enum scenario { SPLIT, ATOMIC, CANCEL_SPLIT, CANCEL_ATOMIC, PATH_FD, RIGHTS,
    ORDERED_ATOMIC, ORDERED_RIGHTS };
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
static int ordered(enum scenario scenario) { return scenario==ORDERED_ATOMIC || scenario==ORDERED_RIGHTS; }
static int listener(int order) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getppid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_dup3,0,1),
        BPF_STMT(BPF_RET|BPF_K,order ? SECCOMP_RET_USER_NOTIF : SECCOMP_RET_ALLOW),
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
    if (f->scenario==RIGHTS || f->scenario==ORDERED_RIGHTS) {
        int fd=-1;
        struct message value=receive_message(f->data,&fd);
        assert(value.kind==INSTALLED && fd>=0 && lseek(fd,0,SEEK_CUR)==11);
        send_message(f->control,(struct message){.kind=INSTALLED,.number=fd},-1);
        value=receive_message(f->data,NULL);
        if (value.kind==CHECK) {
            assert(lseek(fd,0,SEEK_CUR)==value.position);
            send_message(f->control,(struct message){.kind=ACK},-1);
            value=receive_message(f->data,NULL);
        }
        assert(value.kind==CONTINUE);
        assert(lseek(fd,0,SEEK_CUR)==29);
        close(fd);
        send_message(f->control,(struct message){.kind=DONE},-1);
        return NULL;
    }
    if (!ordered(f->scenario)) {
        int fd=listener(0);
        send_message(f->control,(struct message){.kind=LISTENER},fd);
        close(fd);
    }
    errno=0;
    long result=syscall(SYS_getppid);
    int error=result<0 ? errno : 0;
    if (f->scenario==SPLIT || f->scenario==ATOMIC || f->scenario==ORDERED_ATOMIC) {
        assert(result==f->target);
        if (f->scenario==ATOMIC || f->scenario==ORDERED_ATOMIC) replace(f,f->target);
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
    if (ordered(f->scenario)) {
        /* Install before creating peers so either peer's dup3 reaches the gate. */
        int fd=listener(1);
        send_message(f->control,(struct message){.kind=LISTENER},fd); close(fd);
    }
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
static struct md_fs_anchor *capture(int fd, struct md_mount_namespace *view) {
    struct md_filesystem fs={.mounts=view};
    struct md_fs_anchor *origin=NULL;
    struct md_fs_result result={.fd=fd};
    struct md_fs_output output={.origin=&origin};
    md_view_capture(&fs,view,NULL,&result,&output);
    assert(!result.error && origin); return origin;
}
static void origin_at(struct md_fd_origins *table, int fd, struct md_fs_anchor *expected) {
    unsigned flags;
    struct md_fs_anchor *actual=md_fd_origins_get(table,fd,&flags);
    assert(actual==expected && flags==(expected ? FD_CLOEXEC : 0)); md_fs_anchor_release(actual);
}
static void ordered_handoff(const struct fixture *f, int control, int data) {
    int notify=-1;
    struct message message=receive_message(control,&notify);
    assert(message.kind==LISTENER && notify>=0);
    struct md_mount_namespace *views[]={md_mount_namespace_new(),md_mount_namespace_new()};
    assert(views[0] && views[1]);
    struct md_fs_anchor *source=capture(f->source,views[0]), *replacement=capture(f->replacement,views[1]);
    struct md_fd_origins *files=md_fd_origins_new(), *other=md_fd_origins_new(); assert(files && other);
    struct md_fd_order install={0}, mutation={0}, independent={0};
    struct md_fd_origin_update update;
    assert(!md_fd_origins_prepare(files,source,FD_CLOEXEC,&update));
    assert(md_fd_order_begin(files,&install,NULL)==1 && !md_fd_order_start(&install));
    int target=f->target;
    if (f->scenario==ORDERED_RIGHTS) {
        send_message(data,(struct message){.kind=INSTALLED},f->source);
        message=receive_message(control,NULL); assert(message.kind==INSTALLED);
        target=message.number;
        send_message(control,(struct message){.kind=REPLACE,.number=target},-1);
    } else {
        struct seccomp_notif q={0};
        /* EVENT_WAIT: exact publication request; fixture alarms bound failure. */
        assert(!ioctl(notify,SECCOMP_IOCTL_NOTIF_RECV,&q) && q.data.nr==SYS_getppid);
        struct seccomp_notif_addfd add={.id=q.id,.srcfd=f->source,.newfd=target,
            .flags=SECCOMP_ADDFD_FLAG_SETFD|SECCOMP_ADDFD_FLAG_SEND,.newfd_flags=O_CLOEXEC};
        assert(ioctl(notify,SECCOMP_IOCTL_NOTIF_ADDFD,&add)==target);
    }
    struct seccomp_notif q={0};
    /* EVENT_WAIT: the competing mutation reaches its kernel admission stop;
     * no timing assumption about when the receiver begins using the FD. */
    assert(!ioctl(notify,SECCOMP_IOCTL_NOTIF_RECV,&q) && q.data.nr==SYS_dup3);
    assert((int)q.data.args[0]==f->replacement && (int)q.data.args[1]==target);
    assert(md_fd_order_begin(files,&mutation,NULL)==0 && md_fd_order_start(&mutation)==-EINVAL);
    if (f->scenario==ORDERED_RIGHTS) {
        send_message(data,(struct message){.kind=CHECK,.position=11},-1);
        message=receive_message(control,NULL); assert(message.kind==ACK);
    } else peer_command(control,CHECK,target,11);
    assert(md_fd_order_begin(other,&independent,NULL)==1 && !md_fd_order_start(&independent));
    assert(!md_fd_order_complete(&independent));
    md_fd_origins_finish(&update,target);
    assert(!md_fd_order_complete(&install) && md_fd_order_state(&mutation)==MD_RESOURCE_ORDER_READY);
    origin_at(files,target,source);
    assert(!md_fd_order_start(&mutation));
    assert(!md_fd_origins_prepare(files,replacement,FD_CLOEXEC,&update));
    struct seccomp_notif_resp reply={.id=q.id,.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE};
    assert(!ioctl(notify,SECCOMP_IOCTL_NOTIF_SEND,&reply));
    if (f->scenario==ORDERED_RIGHTS) {
        message=receive_message(control,NULL); assert(message.kind==ACK);
    } else completed(control);
    /* This fixture acknowledgement follows the actual dup3 result. Production
     * integration needs its syscall-exit event, not notification SEND success. */
    md_fd_origins_finish(&update,target);
    assert(!md_fd_order_complete(&mutation));
    origin_at(files,target,replacement);
    if (f->scenario==ORDERED_RIGHTS) {
        send_message(data,(struct message){.kind=CONTINUE},-1); completed(control);
        assert(!md_fd_origins_close_range(files,(unsigned)target,(unsigned)target,0));
        assert(!md_fd_origins_get(files,target,NULL));
    }
    md_fd_origins_release(files); md_fd_origins_release(other);
    md_fs_anchor_release(source); md_fs_anchor_release(replacement);
    md_mount_namespace_release(views[0]); md_mount_namespace_release(views[1]);
    close(notify);
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
    if (ordered(scenario)) ordered_handoff(&f,control[0],data[0]);
    else if (scenario==RIGHTS) {
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
struct receipt_child { int socket, receipt, truncated; pid_t parent; };
static int receive_and_exit(void *opaque) {
    struct receipt_child *f=opaque;
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=f->parent) _exit(1);
    struct md_fd_receipt *receipt=mmap(NULL,sizeof(*receipt),PROT_READ|PROT_WRITE,MAP_SHARED,f->receipt,0);
    assert(receipt!=MAP_FAILED);
    md_fd_receipt_reset(receipt);
    if (f->truncated) receipt->message.msg_controllen=CMSG_LEN(sizeof(int));
    syscall(SYS_recvmsg,f->socket,&receipt->message,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
    /* No publication/FD-number acknowledgement from the receiver. */
    _exit(0);
}
static void retained_receipt(const char *directory, unsigned count, int truncated) {
    unsigned before=descriptors();
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/receipt",directory);
    int source=create_file(path,11); assert(!unlink(path));
    struct md_mount_namespace *view=md_mount_namespace_new(); assert(view);
    struct md_fs_anchor *origin=capture(source,view);
    struct md_fd_origins *files=md_fd_origins_new(); assert(files);
    struct md_fd_exchanges *exchanges=md_fd_exchanges_create(); assert(exchanges);
    struct md_fd_exchange *exchange=NULL;
    int bases[2]={-1,-1};
    assert(!md_fd_exchange_begin(exchanges,getpid(),files,bases,&exchange));
    assert(!md_fd_exchange_offer(exchange,origin,count ? count : 1));
    int fd=md_fd_exchange_receipt(exchange); assert(fd>=0);
    struct md_fd_receipt *receipt=mmap(NULL,sizeof(*receipt),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    assert(receipt!=MAP_FAILED);
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,sockets));
    if (count) {
        unsigned char byte=1;
        struct iovec io={&byte,sizeof(byte)};
        union { struct cmsghdr align; char bytes[CMSG_SPACE(2*sizeof(int))]; } control={0};
        struct msghdr message={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,
            .msg_controllen=CMSG_SPACE(count*sizeof(int))};
        control.align=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS,.cmsg_len=CMSG_LEN(count*sizeof(int))};
        int sources[2]={source,source}; memcpy(CMSG_DATA(&control.align),sources,count*sizeof(int));
        assert(sendmsg(sockets[0],&message,MSG_NOSIGNAL)==1);
    }
    struct md_fd_order turn={0};
    assert(md_fd_order_begin(files,&turn,NULL)==1 && !md_fd_order_start(&turn));
    size_t stack_size=65536;
    void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    struct receipt_child context={sockets[1],fd,truncated,getpid()};
    pid_t child=clone(receive_and_exit,(char *)stack+stack_size,CLONE_FILES|SIGCHLD,&context);
    assert(child>0);
    int status;
    /* EVENT_WAIT: actual receiver death; the fixture alarm bounds failure. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(md_fd_order_cancel(&turn)==1);
    assert(!md_fd_exchange_received(exchange));
    assert(!md_fd_order_complete(&turn));
    int received[2];
    int actual=md_fd_receipt_read(receipt,received);
    assert(actual==(int)(truncated ? 1 : count));
    assert(!!(receipt->message.msg_flags&MSG_CTRUNC)==!!truncated);
    for (int i=0;i<actual;++i) {
        assert(lseek(received[i],0,SEEK_CUR)==11);
        assert(fcntl(received[i],F_GETFD)==FD_CLOEXEC);
        origin_at(files,received[i],i ? NULL : origin);
        close(received[i]);
    }
    munmap(stack,stack_size); munmap(receipt,sizeof(*receipt));
    close(sockets[0]); close(sockets[1]); close(source);
    md_fd_exchange_close(exchanges,exchange); md_fd_exchanges_destroy(exchanges);
    md_fd_origins_release(files); md_fs_anchor_release(origin); md_mount_namespace_release(view);
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
    scenario(ORDERED_ATOMIC,argv[1]);
    puts("PASS ordered ADDFD_SEND: origin published before an intercepted shared-table replacement");
    scenario(ORDERED_RIGHTS,argv[1]);
    puts("PASS ordered SCM_RIGHTS: exact origins follow kernel completion, independent table progresses");
    retained_receipt(argv[1],0,0);
    retained_receipt(argv[1],1,0);
    retained_receipt(argv[1],2,0);
    retained_receipt(argv[1],2,1);
    puts("PASS retained kernel receipt after CLONE_FILES receiver death: no delivery, one/two FDs and truncated delivery");
    puts("PASS native FD publication boundaries and descriptor cleanup");
    assert(!rmdir(argv[1]));
    return 0;
}
