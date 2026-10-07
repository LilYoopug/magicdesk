#define _GNU_SOURCE
#include "fd_return.h"
#include "fd_channel.h"
#include "fs_mount_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { COUNT=253, LIMIT=4096 };
enum output { NORMAL, HEADER_FAULT, WORD_FAULT, MESSAGE_FAULT, CANCELLED, EMPTY_CONTROL, QUOTA, NO_QUOTA, PEEK,
    KILLED_BEFORE, KILLED_AFTER, BAD_ACK };
struct child { int channel, endpoint, protected, cloexec; enum output output; pid_t parent; };

static int wait_child(pid_t child) {
    /* EVENT_WAIT: exact ptrace stop/exit; fixture alarm bounds failure. */
    int status; pid_t result;
    do { result=waitpid(child,&status,__WALL); } while (result<0 && errno==EINTR);
    assert(result==child); return status;
}
static void send_fds(int socket, int fd, unsigned count) {
    char byte=1;
    struct iovec io={&byte,1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(COUNT*sizeof(int))]; } control={0};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,
        .msg_controllen=CMSG_SPACE(count*sizeof(int))};
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
    c->cmsg_len=CMSG_LEN(count*sizeof(int)); c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS;
    for (unsigned i=0;i<count;++i) memcpy(CMSG_DATA(c)+i*sizeof(int),&fd,sizeof(fd));
    assert(sendmsg(socket,&msg,MSG_NOSIGNAL|MSG_DONTWAIT)==1);
}
static int receive_fd(int socket) {
    char byte;
    struct iovec io={&byte,1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    assert(recvmsg(socket,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC)==1);
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
    assert(c && c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS && c->cmsg_len==CMSG_LEN(sizeof(int)));
    int fd; memcpy(&fd,CMSG_DATA(c),sizeof(fd)); return fd;
}
static void membership(DIR *directory, unsigned char *present) {
    memset(present,0,LIMIT); rewinddir(directory); errno=0;
    struct dirent *entry;
    while ((entry=readdir(directory))) {
        if (entry->d_name[0]=='.') continue;
        char *end; long fd=strtol(entry->d_name,&end,10);
        assert(!*end && fd>=0 && fd<LIMIT); present[fd]=1;
    }
    if (errno) fprintf(stderr,"proc membership: %s\n",strerror(errno));
    assert(!errno);
}
static unsigned descriptors(void) {
    DIR *directory=opendir("/proc/self/fd"); assert(directory);
    unsigned char present[LIMIT]; membership(directory,present); unsigned count=0;
    for (unsigned i=0;i<LIMIT;++i) count+=present[i];
    assert(!closedir(directory)); return count;
}
struct capture { int channel, tid; pid_t owner; };
static int capture_directory(void *opaque) {
    struct capture *c=opaque;
    if (c->channel) assert(!syscall(SYS_close_range,0,c->channel-1,0));
    assert(!syscall(SYS_close_range,c->channel+1,~0U,0));
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/fd",c->owner);
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(fd>=0);
    send_fds(c->channel,fd,1);
    syscall(SYS_exit,0); __builtin_unreachable();
}
static void export_directory(int channel) {
    /* Same-TGID capture, private file table: the caller acquires no temporary
     * FD. The retained directory refers to the caller, not this short helper. */
    size_t size=65536;
    void *stack=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    struct capture c={.channel=channel,.owner=(pid_t)syscall(SYS_gettid)};
    int flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID;
    assert(clone(capture_directory,(char *)stack+size,flags,&c,&c.tid,NULL,&c.tid)>0);
    /* EVENT_WAIT: exact clear-child-tid; fixture alarm fails a missing exit. */
    int tid;
    while ((tid=__atomic_load_n(&c.tid,__ATOMIC_ACQUIRE))) {
        long result=syscall(SYS_futex,&c.tid,FUTEX_WAIT,tid,NULL,NULL,0);
        assert(!result || (result<0 && (errno==EINTR || errno==EAGAIN)));
    }
    assert(!munmap(stack,size));
}
static int receiver(void *opaque) {
    struct child *c=opaque;
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=c->parent) _exit(1);
    assert(!ptrace(PTRACE_TRACEME,0,0,0));
    if (c->protected) assert(!prctl(PR_SET_DUMPABLE,0));
    export_directory(c->channel);
    raise(SIGSTOP);
    if (c->output==KILLED_BEFORE) { kill(getpid(),SIGKILL); __builtin_unreachable(); }
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *memory=mmap(NULL,3*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED);
    uint64_t token;
    struct iovec io={&token,sizeof(token)};
    struct msghdr *msg=(void *)(memory+2*page);
    *msg=(struct msghdr){.msg_iov=&io,.msg_iovlen=1,.msg_control=memory,
        .msg_controllen=CMSG_SPACE(COUNT*sizeof(int))};
    if (c->output==HEADER_FAULT) {
        msg->msg_control=memory+page-CMSG_LEN(0);
        assert(!mprotect(memory,page,PROT_READ));
    } else if (c->output==WORD_FAULT) {
        msg->msg_control=memory+page-CMSG_LEN(3*sizeof(int));
        assert(!mprotect(memory+page,page,PROT_NONE));
    } else if (c->output==MESSAGE_FAULT) assert(!mprotect(msg,page,PROT_READ));
    else if (c->output==EMPTY_CONTROL) msg->msg_controllen=0;
    if (c->output==QUOTA || c->output==NO_QUOTA) {
        struct rlimit limit; assert(!getrlimit(RLIMIT_NOFILE,&limit));
        unsigned available=c->output==QUOTA ? 3 : 0;
        for (rlim_t fd=0;fd<limit.rlim_cur;++fd) {
            if (fcntl((int)fd,F_GETFD)>=0) continue;
            assert(errno==EBADF);
            if (available) { --available; continue; }
            limit.rlim_cur=fd; assert(!setrlimit(RLIMIT_NOFILE,&limit)); break;
        }
    }
    if (c->output!=CANCELLED) {
        ssize_t result=syscall(SYS_recvmsg,c->endpoint,msg,MSG_DONTWAIT
            |(c->cloexec ? MSG_CMSG_CLOEXEC : 0)|(c->output==PEEK ? MSG_PEEK : 0));
        assert(c->output==MESSAGE_FAULT ? result==-1 && errno==EFAULT : result==(long)sizeof(token));
    }
    if (c->output==KILLED_AFTER) { kill(getpid(),SIGKILL); __builtin_unreachable(); }
    /* No FD-number or control-buffer acknowledgement. */
    _exit(0);
}
static void run(int shared, int protected, int cloexec, enum output output) {
    unsigned original=descriptors();
    int channel[2],pipefd[2];
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel));
    assert(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK));
    struct md_fd_channel *return_channel=NULL; assert(!md_fd_channel_new(&return_channel));
    int endpoint=fcntl(md_fd_channel_endpoint(return_channel),F_DUPFD_CLOEXEC,0); assert(endpoint>=0);
    struct md_fd_origins *files=md_fd_origins_new(); assert(files);
    struct md_fd_origin_update channel_update;
    assert(!md_fd_origins_prepare_channel(files,return_channel,FD_CLOEXEC,&channel_update));
    md_fd_origins_finish(&channel_update,endpoint);
    struct md_mount_namespace *view=md_mount_namespace_new(); assert(view);
    struct md_filesystem fs={.mounts=view};
    struct md_fs_anchor *anchor=NULL;
    struct md_fs_result source={.fd=pipefd[1]};
    struct md_fs_output captured={.origin=&anchor};
    md_view_capture(&fs,view,NULL,&source,&captured); assert(!source.error && anchor);
    struct md_fs_anchor *origins[COUNT]; int sources[COUNT],numbers[COUNT];
    struct md_fd_origin_update updates[COUNT];
    for (unsigned i=0;i<COUNT;++i) { sources[i]=pipefd[1]; origins[i]=i%3 ? anchor : NULL; }
    struct child context={channel[1],endpoint,protected,cloexec,output,getpid()};
    size_t stack_size=1024*1024;
    void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK,-1,0);
    assert(stack!=MAP_FAILED);
    pid_t child=clone(receiver,(char *)stack+stack_size,SIGCHLD|(shared ? CLONE_FILES : 0),&context);
    assert(child>0);
    int status=wait_child(child); assert(WIFSTOPPED(status) && WSTOPSIG(status)==SIGSTOP);
    assert(!ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACEEXIT|PTRACE_O_EXITKILL));
    int fd=receive_fd(channel[0]);
    DIR *directory=fdopendir(fd); assert(directory);
    unsigned char before[LIMIT],after[LIMIT];
    membership(directory,before);
    struct md_fd_table_observation observation={0};
    struct md_fd_return_publication publication={.origins=origins,.updates=updates,.numbers=numbers,
        .observation=&observation,.directory=fd,.flags=cloexec ? FD_CLOEXEC : 0};
    struct md_fd_return operation={0};
    assert(!md_fd_return_vector_begin(&operation,files,sources,COUNT,&publication,NULL));
    assert(md_fd_return_progress(&operation,NULL)==MD_FD_RETURN_READY);
    struct md_fd_order successor={0}; assert(!md_fd_order_begin(files,&successor,NULL));
    assert(!ptrace(PTRACE_CONT,child,0,0));
    status=wait_child(child);
    assert(WIFSTOPPED(status) && (unsigned)status>>16==PTRACE_EVENT_EXIT);
    membership(directory,after);
    int installed[COUNT]; unsigned count=0;
    for (int i=0;i<LIMIT;++i) {
        assert(!before[i] || after[i]);
        if (!before[i] && after[i]) { assert(count<COUNT); installed[count++]=i; }
    }
    unsigned expected=output==CANCELLED || output==EMPTY_CONTROL || output==NO_QUOTA || output==KILLED_BEFORE ? 0
        : output==WORD_FAULT || output==QUOTA ? 3 : COUNT;
    assert(count==expected);
    assert(md_fd_order_state(&successor)==MD_RESOURCE_ORDER_QUEUED);
    if (output==NORMAL) assert(!md_fd_return_finish(&operation,sizeof(uint64_t),operation.request));
    else if (output==BAD_ACK) assert(md_fd_return_finish(&operation,sizeof(uint64_t),operation.request+1)==-EPROTO);
    else if (count && output%2) assert(md_fd_return_finish(&operation,-EFAULT,0)==-EFAULT);
    else assert(!md_fd_return_cancel(&operation));
    assert(!operation.files.table && !operation.delivery.capacity);
    assert(md_fd_order_state(&successor)==MD_RESOURCE_ORDER_READY && !md_fd_order_cancel(&successor));
    for (unsigned i=0;i<count;++i) {
        assert(numbers[i]==installed[i]);
        unsigned flags=~0U;
        struct md_fs_anchor *actual=md_fd_origins_get(files,numbers[i],&flags);
        assert(actual==origins[i] && flags==(actual && cloexec ? FD_CLOEXEC : 0));
        md_fs_anchor_release(actual);
        if (shared) assert(fcntl(numbers[i],F_GETFD)==(cloexec ? FD_CLOEXEC : 0));
    }
    assert(!ptrace(PTRACE_CONT,child,0,0));
    status=wait_child(child);
    assert(output==KILLED_BEFORE || output==KILLED_AFTER ? WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL
        : WIFEXITED(status) && !WEXITSTATUS(status));
    int absent[COUNT]; for (unsigned i=0;i<COUNT;++i) absent[i]=-19;
    assert(md_fd_table_observation_read(&observation,absent)==-ENOENT && absent[0]==-19);
    if (shared) for (unsigned i=0;i<count;++i) close(installed[i]);
    close(channel[0]); close(channel[1]); close(endpoint); close(pipefd[1]);
    md_fd_channel_release(return_channel); md_fd_origins_release(files);
    char byte; assert(read(pipefd[0],&byte,1)==0);
    close(pipefd[0]); closedir(directory); md_fs_anchor_release(anchor); md_mount_namespace_release(view);
    assert(!munmap(stack,stack_size));
    assert(descriptors()==original);
    printf("PASS FD table observation shared=%d protected=%d cloexec=%d output=%d installed=%u\n",shared,protected,cloexec,output,count);
}
static void rejected_observation(void) {
    unsigned before=descriptors();
    int directory=open("/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(directory>=0);
    struct md_fd_table_observation o={0};
    int output[3]={-19,-19,-19};
    assert(md_fd_table_observation_read(&o,output)==-EINVAL);
    assert(!md_fd_table_observation_begin(&o,directory,3));
    assert(md_fd_table_observation_begin(&o,directory,3)==-EBUSY);
    assert(dup3(directory,o.candidates[1],O_CLOEXEC)==o.candidates[1]);
    assert(md_fd_table_observation_read(&o,output)==-EPROTO);
    assert(output[0]==-19 && output[1]==-19 && output[2]==-19);
    close(o.candidates[1]); close(directory);
    assert(md_fd_table_observation_read(&o,output)==-EBADF && output[0]==-19);
    assert(descriptors()==before);
    puts("PASS FD observation rejection: unarmed, duplicate arm, non-prefix mutation and lost directory leave output unchanged");
}
int main(void) {
    setvbuf(stdout,NULL,_IOLBF,0); alarm(30);
    rejected_observation();
    for (int shared=0;shared<2;++shared) for (int protected=0;protected<2;++protected) for (int cloexec=0;cloexec<2;++cloexec)
        for (enum output output=NORMAL;output<=BAD_ACK;++output) run(shared,protected,cloexec,output);
    puts("PASS native FD table observation and terminal custody");
    return 0;
}
