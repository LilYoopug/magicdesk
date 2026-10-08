#define _GNU_SOURCE
#include "namespace_broker.h"
#include "fs_mounts.h"
#include "task_resources.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_int cancel_pid;
static int signal_pipe[2];
static void interrupted(int signal) {
    (void)signal;
    int saved=errno;
    if (write(signal_pipe[1],"s",1)!=1) _exit(98);
    errno=saved;
}
ssize_t __real_process_vm_writev(pid_t,const struct iovec *,unsigned long,
        const struct iovec *,unsigned long,unsigned long);
ssize_t __wrap_process_vm_writev(pid_t pid,const struct iovec *local,unsigned long count,
        const struct iovec *remote,unsigned long remote_count,unsigned long flags) {
    ssize_t result=__real_process_vm_writev(pid,local,count,remote,remote_count,flags);
    int expected=pid;
    if (result>0 && atomic_compare_exchange_strong(&cancel_pid,&expected,0)) {
        assert(!kill(pid,SIGUSR1));
        /* EVENT_WAIT: the child's handler proves notification cancellation
         * before SEND; the fixture alarm fails an abandoned acknowledgement. */
        char byte;
        assert(read(signal_pipe[0],&byte,1)==1 && byte=='s');
    }
    return result;
}
static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned count=0;
    for (struct dirent *entry; (entry=readdir(dir));)
        if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++count;
    assert(!closedir(dir)); return count;
}
static int listener(void) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getdents64,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    int fd=(int)syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&program);
    assert(fd>=0); return fd;
}
static void send_listener(int socket,int fd) {
    char byte='l',control[CMSG_SPACE(sizeof(fd))]={0};
    struct iovec vector={&byte,1};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control,.msg_controllen=sizeof(control)};
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS;
    header->cmsg_len=CMSG_LEN(sizeof(fd)); memcpy(CMSG_DATA(header),&fd,sizeof(fd));
    assert(sendmsg(socket,&message,0)==1);
}
static int receive_listener(int socket) {
    char byte,control[CMSG_SPACE(sizeof(int))]={0};
    struct iovec vector={&byte,1};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control,.msg_controllen=sizeof(control)};
    /* EVENT_WAIT: child publishes its actual seccomp listener; alarm bounds failure. */
    assert(recvmsg(socket,&message,MSG_CMSG_CLOEXEC)==1 && byte=='l'
        && !(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC)));
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    assert(header && header->cmsg_level==SOL_SOCKET && header->cmsg_type==SCM_RIGHTS
        && header->cmsg_len==CMSG_LEN(sizeof(int)));
    int fd; memcpy(&fd,CMSG_DATA(header),sizeof(fd)); return fd;
}
static void reader(int socket,int directory,int cancel,pid_t parent) {
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=parent) _exit(99);
    alarm(25);
    struct sigaction action={.sa_handler=interrupted};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGUSR1,&action,NULL));
    int fd=listener(); send_listener(socket,fd); assert(!close(fd));
    char byte;
    /* EVENT_WAIT: parent publishes registry and broker before directory reads. */
    assert(read(socket,&byte,1)==1 && byte=='r');
    char data[384]; unsigned seen[96]={0},count=0;
    if (cancel) {
        long n=syscall(SYS_getdents64,directory,data,sizeof(data));
        assert(n==-1 && errno==EINTR);
    }
    assert(syscall(SYS_getdents64,directory,(void *)1,sizeof(data))==-1 && errno==EFAULT);
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *partial=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(partial!=MAP_FAILED && !mprotect(partial+page,page,PROT_NONE));
    assert(syscall(SYS_getdents64,directory,partial+page-16,sizeof(data))==-1 && errno==EFAULT);
    assert(!munmap(partial,page*2));
    for (;;) {
        long n=syscall(SYS_getdents64,directory,data,sizeof(data)); assert(n>=0);
        if (!n) break;
        for (size_t at=0;at<(size_t)n;) {
            struct md_inode_dirent *entry=(void *)(data+at);
            assert(entry->size>offsetof(struct md_inode_dirent,name) && at+entry->size<=(size_t)n);
            if (strcmp(entry->name,".") && strcmp(entry->name,"..")) {
                unsigned index=96;
                assert(sscanf(entry->name,"entry-%u",&index)==1 && index<96 && !seen[index]++);
                ++count;
            }
            at+=entry->size;
        }
    }
    if (count!=96) fprintf(stderr,"directory entries: expected=96 actual=%u cancelled=%d\n",count,cancel);
    _exit(count==96 ? 0 : 97);
}
static void unexpected_delegate(const struct seccomp_notif *request) {
    fprintf(stderr,"unexpected broker fallback: nr=%d pid=%u\n",request->data.nr,request->pid);
    assert(0);
}
static void run(const char *store,const char *native,int directory,int cancel) {
    unsigned before=descriptors();
    assert(lseek(directory,0,SEEK_SET)==0);
    int channel[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel));
    assert(!pipe2(signal_pipe,O_CLOEXEC));
    pid_t parent=getpid(),child=fork(); assert(child>=0);
    if (!child) { close(channel[0]); close(signal_pipe[0]); reader(channel[1],directory,cancel,parent); }
    close(channel[1]); close(signal_pipe[1]);
    int fd=receive_listener(channel[0]);
    struct md_task_registry *tasks=md_task_registry_create(); assert(tasks);
    struct md_fs_worker *worker=NULL;
    char endpoint[80]; snprintf(endpoint,sizeof(endpoint),"md-dir-broker-%d-%d",parent,child);
    struct md_fs_attachment attachment={.source=native,.target="/native"};
    assert(!md_fs_worker_start(store,endpoint,NULL,tasks,NULL,native ? &attachment : NULL,
        native ? 1 : 0,0,NULL,&worker));
    struct md_task_resources resources={.fs=md_domain_new(),.files=md_fd_origins_new(),
        .mounts=md_fs_worker_mounts(worker)};
    assert(resources.fs && resources.files);
    struct md_identity identity=md_identity_new(0,0);
    assert(!md_task_registry_publish(tasks,child,child,&identity,&resources));
    struct md_namespace_broker *broker=md_broker_create(worker,1,unexpected_delegate); assert(broker);
    assert(!md_broker_task(broker,child,1,0,0));
    atomic_store(&cancel_pid,cancel ? child : 0);
    md_broker_listen(broker,fd);
    assert(write(channel[0],"r",1)==1);
    /* EVENT_WAIT: reader completion, bounded by the child and fixture alarms. */
    int status; assert(waitpid(child,&status,0)==child);
    assert(!md_fs_worker_error(worker));
    md_broker_forget(broker,child);
    assert(!md_fs_worker_stop(worker)); md_broker_destroy(broker);
    md_task_registry_destroy(tasks); md_identity_release(&identity);
    md_domain_release(resources.fs); md_fd_origins_release(resources.files);
    assert(!close(fd) && !close(channel[0]) && !close(signal_pipe[0]));
    assert(!atomic_load(&cancel_pid) && descriptors()==before);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    printf("PASS broker directory publication: native=%d cancelledAfterCopy=%d faultAndPartialCopy=1 complete=96 noDescriptorLeak=1\n",native!=NULL,cancel);
}
void md_test_namespace_broker(const char *root) {
    setbuf(stdout,NULL); alarm(60);
    assert(!mkdir(root,0700));
    char store[4096],native[4096];
    snprintf(store,sizeof(store),"%s/store",root); snprintf(native,sizeof(native),"%s/native",root);
    assert(!mkdir(native,0700));
    struct md_inode_store *s=NULL; assert(!md_inode_store_open(store,1,&s));
    assert(!md_inode_mkdir(s,-1,"/entries",0755));
    assert(!md_inode_mkdir(s,-1,"/native",0755));
    int directory=md_inode_open(s,-1,"/entries",O_RDONLY|O_DIRECTORY|O_CLOEXEC,0);
    int attached=open(native,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(directory>=0 && attached>=0);
    for (unsigned i=0;i<96;++i) {
        char name[32]; snprintf(name,sizeof(name),"entry-%03u",i);
        int fd=md_inode_open(s,directory,name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
        assert(fd>=0 && !close(fd));
        fd=openat(attached,name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600); assert(fd>=0 && !close(fd));
    }
    md_inode_store_close(s);
    for (int cancelled=0;cancelled<2;++cancelled) {
        run(store,NULL,directory,cancelled);
        run(store,native,attached,cancelled);
    }
    assert(!close(directory) && !close(attached)); alarm(0);
    puts("PASS broker directory notification ownership");
}
