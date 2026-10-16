#define _GNU_SOURCE
#include "namespace_broker.h"
#include "fs_mounts.h"
#include "task_resources.h"
#include "fs_native.h"
#include "inode_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
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
static int listener(int nr) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,nr,0,1),
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
    int fd=listener(SYS_getdents64); send_listener(socket,fd); assert(!close(fd));
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
    struct md_fs_worker_launch launch={.attachments=native ? &attachment : NULL,.attachment_count=native ? 1 : 0};
    assert(!md_fs_worker_start(store,endpoint,NULL,tasks,NULL,&launch,&worker));
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
extern char result_return[];
extern long result_call(unsigned long,unsigned long,unsigned long,unsigned long,unsigned long,unsigned long,long);
__asm__(".text\n.balign 4\n.global result_call\nresult_call:\n"
    "mov x8,x6\nsvc #0\n.global result_return\nresult_return:\nret\n");
static void completed_result(const char *store,int nr) {
    unsigned before=descriptors();
    struct seccomp_data call={.nr=nr,.arch=AUDIT_ARCH_AARCH64,.instruction_pointer=(uintptr_t)result_return,
        .args={6,11,22,33,44,55}};
    if (nr==SYS_gettid) memset(call.args+1,0,5*sizeof(call.args[0]));
    int source=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(source>=0);
    int channel[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel));
    pid_t parent=getpid(),child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
        if (getppid()!=parent) _exit(99);
        alarm(25); close(channel[0]); close(source);
        int fd=listener(nr); send_listener(channel[1],fd); close(fd);
        char byte;
        /* EVENT_WAIT: parent publishes this exact result before admission. */
        assert(read(channel[1],&byte,1)==1 && byte=='r');
        for (unsigned i=0;i<6;++i) {
            call.args[i]^=1;
            assert(result_call(call.args[0],call.args[1],call.args[2],call.args[3],call.args[4],call.args[5],nr)==-EPERM);
            call.args[i]^=1;
        }
        long result=result_call(call.args[0],call.args[1],call.args[2],call.args[3],call.args[4],call.args[5],nr);
        assert(result>=0 && fcntl(result,F_GETFD)==FD_CLOEXEC && read(result,&byte,1)==0);
        assert(result_call(call.args[0],call.args[1],call.args[2],call.args[3],call.args[4],call.args[5],nr)==-EPERM);
        assert(write(channel[1],&result,sizeof(result))==sizeof(result));
        /* EVENT_WAIT: result retirement is acknowledged before receiver exit. */
        assert(read(channel[1],&byte,1)==1 && byte=='f');
        assert(!close(result)); _exit(0);
    }
    close(channel[1]);
    int fd=receive_listener(channel[0]);
    struct md_task_registry *tasks=md_task_registry_create(); assert(tasks);
    struct md_fs_worker *worker=NULL;
    char endpoint[80]; snprintf(endpoint,sizeof(endpoint),"md-result-broker-%d-%d",parent,child);
    assert(!md_fs_worker_start(store,endpoint,NULL,tasks,NULL,NULL,&worker));
    struct md_fd_origins *files=md_fd_origins_new(); assert(files);
    struct md_namespace_broker *broker=md_broker_create(worker,1,unexpected_delegate); assert(broker);
    assert(!md_broker_task(broker,child,0,0,0));
    long value=-123;
    assert(!md_broker_result_finish(broker,child,&value) && value==-123);
    assert(!md_broker_result_begin(broker,child,&call,files,source,NULL,O_CLOEXEC));
    assert(md_broker_result_begin(broker,child,&call,files,source,NULL,O_CLOEXEC)==-EBUSY);
    md_broker_listen(broker,fd);
    assert(write(channel[0],"r",1)==1);
    long result;
    /* EVENT_WAIT: child confirms successful admission and rejected replay. */
    assert(read(channel[0],&result,sizeof(result))==sizeof(result));
    assert(md_broker_result_finish(broker,child,&value)==1 && value==result);
    value=-123; assert(!md_broker_result_finish(broker,child,&value) && value==-123);
    assert(write(channel[0],"f",1)==1);
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!md_fs_worker_error(worker)); md_broker_forget(broker,child);
    assert(!md_fs_worker_stop(worker)); md_broker_destroy(broker);
    md_task_registry_destroy(tasks); md_fd_origins_release(files);
    assert(!close(source) && !close(fd) && !close(channel[0]) && descriptors()==before);
    printf("PASS completed FD result: carrier=%d exact arguments, rejected replay, confirmed result and no FD leak\n",nr);
}
static unsigned native_provider_released;
static void native_provider_release(struct md_fd_object *object) {
    (void)object; ++native_provider_released;
}
static void managed_proc_reads(const char *store) {
    unsigned before=descriptors();
    struct md_task_registry *tasks=md_task_registry_create(); assert(tasks);
    struct md_task_resources resources={.fs=md_domain_new(),.files=md_fd_origins_new()};
    assert(resources.fs && resources.files);
    struct md_identity id=md_identity_new(1000,1000);
    assert(!md_task_registry_publish(tasks,getpid(),getpid(),&id,&resources));
    struct md_task_snapshot actor={.tid=getpid()+100000,.tgid=getpid()+100000,
        .identity=id,.fs=resources.fs};
    struct md_inode_store *s=NULL; assert(!md_inode_store_open(store,0,&s));
    struct md_filesystem fs={.store=s,.actor=&actor,.tasks=tasks};
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets));
    char path[96],data[256],expected[256];
    snprintf(path,sizeof(path),"/proc/%d/fd/%d",getpid(),sockets[0]);
    ssize_t length=readlink(path,expected,sizeof(expected)); assert(length>0);
    struct stat native; assert(!fstat(sockets[0],&native));
    struct md_inode_boundary boundary={.path=path,.capacity=sizeof(path)};
    struct md_fs_output output={.data=data,.capacity=sizeof(data)};
    struct md_fd_order busy={0};
    const struct md_fd_object_type provider={.destroy=native_provider_release};
    struct md_fd_object typed;
    md_fd_object_init(&typed,&provider);
    int dumpable=prctl(PR_GET_DUMPABLE); assert(dumpable>=0);
    assert(!prctl(PR_SET_DUMPABLE,1));
    for (unsigned scenario=0;scenario<7;++scenario) {
        if (scenario==1) {
            assert(md_fd_order_begin(resources.files,&busy,NULL)==1);
            assert(!md_fd_order_start(&busy));
        }
        if (scenario==2) actor.identity.uid.effective=1001;
        if (scenario==3) {
            struct md_fd_origin_update update;
            assert(!md_fd_origins_prepare_object(resources.files,&typed,0,&update));
            md_fd_origins_finish(&update,sockets[0]);
        }
        if (scenario==4) {
            assert(!close(sockets[0]));
            int fd=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(fd>=0);
            if (fd!=sockets[0]) { assert(dup2(fd,sockets[0])==sockets[0]); close(fd); }
            assert(!fstat(sockets[0],&native));
            length=readlink(path,expected,sizeof(expected)); assert(length>0);
        }
        if (scenario==5) {
            /* A native service owner is authenticated in this registry but has
             * no guest file table. Its proc observations retain kernel policy. */
            assert(!md_task_registry_publish(tasks,getpid(),getpid(),&id,NULL));
            actor.identity.uid.effective=1001;
        }
        if (scenario==6) assert(!prctl(PR_SET_DUMPABLE,0));
        for (unsigned op=0;op<3;++op) {
            struct md_fs_request q={.operation=op==2 ? MD_FS_READLINK : MD_FS_STAT,
                .flags=op==1 ? AT_SYMLINK_NOFOLLOW : 0};
            struct md_fs_result out={.fd=-1,.error=-EREMOTE};
            md_fs_native_boundary(&fs,&boundary,&q,&out,&output);
            if ((scenario>=1 && scenario<=3) || scenario==6) { assert(out.error==-EREMOTE); continue; }
            assert(!out.error && !out.host_path && out.fd==-1);
            if (op==2) assert(out.size==(size_t)length && !memcmp(data,expected,out.size));
            else if (op==1) assert(S_ISLNK(out.info.mode));
            else assert(out.info.inode==native.st_ino && out.info.mode==native.st_mode);
        }
        if (scenario==1) assert(!md_fd_order_complete(&busy));
        if (scenario==2) actor.identity.uid.effective=1000;
        if (scenario==3) assert(!md_fd_origins_close_range(resources.files,sockets[0],sockets[0],0));
    }
    assert(!prctl(PR_SET_DUMPABLE,dumpable));
    assert(!close(sockets[0]) && !close(sockets[1]));
    md_task_registry_destroy(tasks); md_fd_origins_release(resources.files);
    md_domain_release(resources.fs); md_identity_release(&id);
    md_fd_object_release(&typed); assert(native_provider_released==1);
    md_inode_store_close(s);
    assert(descriptors()==before);
    puts("PASS managed proc observations: socket identity, descriptor reuse, credentials, busy table and typed provider fallback, no FD leak");
}
void md_test_namespace_broker(const char *root) {
    setbuf(stdout,NULL); alarm(60);
    extern void md_test_notification_result(void);
    md_test_notification_result();
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
        /* A native description without a guest bind uses the same cursor
         * publication contract, not an adapter replay after copying. */
        run(store,NULL,attached,cancelled);
    }
    assert(!close(directory) && !close(attached));
    completed_result(store,SYS_fstat); completed_result(store,SYS_gettid);
    managed_proc_reads(store); alarm(0);
    puts("PASS broker directory notification ownership");
}
