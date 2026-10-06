#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"ipc-credentials line=%d %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
static void peer(int fd, pid_t pid, uid_t uid, gid_t gid) {
    struct ucred c; socklen_t n=sizeof(c);
    CHECK(!getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&c,&n));
    if (c.pid!=pid || c.uid!=uid || c.gid!=gid) fprintf(stderr,"peer actual=%d:%u:%u expected=%d:%u:%u\n",c.pid,c.uid,c.gid,pid,uid,gid);
    CHECK(n==sizeof(c) && c.pid==pid && c.uid==uid && c.gid==gid);
}
static void done(pid_t pid) {
    int s;
    /* EVENT_WAIT: child exit; the guest launch deadline bounds a stuck fixture. */
    CHECK(waitpid(pid,&s,0)==pid && WIFEXITED(s) && WEXITSTATUS(s)==0);
}
static void stream(int abstract) {
    int server=socket(AF_UNIX,SOCK_STREAM,0); CHECK(server>=0);
    struct sockaddr_un a={.sun_family=AF_UNIX};
    snprintf(a.sun_path+abstract,sizeof(a.sun_path)-abstract,"%smd-ipc-%d",abstract?"":"/tmp/",getpid());
    socklen_t n=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+abstract+strlen(a.sun_path+abstract)+(abstract?0:1));
    CHECK(!bind(server,(void *)&a,n));
    if (!abstract) CHECK(!chmod(a.sun_path,0777));
    CHECK(!listen(server,4));
    int ready[2]; CHECK(!pipe(ready));
    pid_t parent=getpid(), child=fork(); CHECK(child>=0);
    if (!child) {
        CHECK(!setgid(2345) && !setuid(1234));
        int client=socket(AF_UNIX,SOCK_STREAM,0); CHECK(client>=0);
        CHECK(!connect(client,(void *)&a,n));
        peer(client,parent,0,0);
        errno=0; CHECK(connect(client,(void *)&a,n)==-1 && errno==EISCONN);
        peer(client,parent,0,0);
        struct sockaddr_un local; socklen_t length=sizeof(local);
        CHECK(!getsockname(client,(void *)&local,&length)); CHECK(length==offsetof(struct sockaddr_un,sun_path));
        CHECK(write(ready[1],"r",1)==1);
        char b; CHECK(read(client,&b,1)==1 && b=='q');
        close(client); _exit(0);
    }
    close(ready[1]); char b;
    /* EVENT_WAIT: connect has captured the listener credentials, before accept. */
    CHECK(read(ready[0],&b,1)==1);
    int client=accept(server,NULL,NULL); CHECK(client>=0);
    peer(client,child,1234,2345);
    CHECK(!setresuid(0,2000,0)); peer(client,child,1234,2345); CHECK(!setresuid(0,0,0));
    int copy=dup(client); CHECK(copy>=0); close(client); peer(copy,child,1234,2345);
    CHECK(write(copy,"q",1)==1); done(child);
    peer(copy,child,1234,2345);
    close(copy); close(server); close(ready[0]); if (!abstract) CHECK(!unlink(a.sun_path));
}
static void send_identity(int fd, uid_t uid, int right, int success) {
    char data='m'; struct iovec io={&data,1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(sizeof(int))]; } c={0};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=c.bytes,
        .msg_controllen=CMSG_SPACE(sizeof(struct ucred))+(right>=0?CMSG_SPACE(sizeof(int)):0)};
    struct cmsghdr *h=CMSG_FIRSTHDR(&m);
    *h=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(struct ucred)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_CREDENTIALS};
    struct ucred cred={getpid(),uid,getgid()}; memcpy(CMSG_DATA(h),&cred,sizeof(cred));
    if (right>=0) {
        h=(void *)(c.bytes+CMSG_SPACE(sizeof(cred)));
        *h=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
        memcpy(CMSG_DATA(h),&right,sizeof(right));
    }
    if (success) CHECK(sendmsg(fd,&m,0)==1);
    else { errno=0; CHECK(sendmsg(fd,&m,0)==-1 && errno==EPERM); }
}
static void receive_identity(int fd, pid_t pid, uid_t uid, int flags, int batch, int rights) {
    char data; struct iovec io={&data,1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(sizeof(int))]; } c={0};
    struct mmsghdr m={.msg_hdr={.msg_iov=&io,.msg_iovlen=1,.msg_control=c.bytes,
        .msg_controllen=CMSG_SPACE(sizeof(struct ucred))+(rights?CMSG_SPACE(sizeof(int)):0)}};
    CHECK((batch?recvmmsg(fd,&m,1,flags,NULL):recvmsg(fd,&m.msg_hdr,flags))==1 && data=='m');
    int seen=0, descriptors=0;
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&m.msg_hdr);h;h=CMSG_NXTHDR(&m.msg_hdr,h)) {
        CHECK(h->cmsg_level==SOL_SOCKET);
        if (h->cmsg_type==SCM_CREDENTIALS) {
            struct ucred value; memcpy(&value,CMSG_DATA(h),sizeof(value));
            CHECK(value.pid==pid && value.uid==uid && value.gid==0); seen++;
        } else {
            CHECK(h->cmsg_type==SCM_RIGHTS && h->cmsg_len==CMSG_LEN(sizeof(int)));
            int right; memcpy(&right,CMSG_DATA(h),sizeof(right));
            peer(right,getpid(),0,0); close(right); descriptors++;
        }
    }
    CHECK(seen==1 && descriptors==rights && !(m.msg_hdr.msg_flags&MSG_CTRUNC));
}
static volatile sig_atomic_t broken_count, broken_code, broken_pid;
static void broken_pipe(int signal, siginfo_t *info, void *context) {
    (void)context;
    if (signal==SIGPIPE) { ++broken_count; broken_code=info->si_code; broken_pid=info->si_pid; }
}
static void send_signals(int mode) {
    int pair[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    CHECK(!shutdown(pair[1],SHUT_WR));
    struct sigaction action={.sa_sigaction=broken_pipe,.sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGPIPE,&action,NULL));
    if (mode==2) {
        sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGPIPE);
        CHECK(!sigprocmask(SIG_BLOCK,&mask,NULL));
    }
    char byte='s'; struct iovec io={&byte,1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred))]; } control={0};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    control.align=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(struct ucred)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_CREDENTIALS};
    struct ucred cred={getpid(),getuid(),getgid()}; memcpy(CMSG_DATA(&control.align),&cred,sizeof(cred));
    if (mode==3) {
        struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_sendmsg,0,4),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)pair[1],0,2),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(uintptr_t)&m,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPIPE)
        };
        struct sock_fprog program={sizeof(code)/sizeof(*code),code};
        CHECK(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) && !prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program));
    }
    CHECK(sendmsg(pair[1],&m,mode==1 ? MSG_NOSIGNAL : 0)==-1 && errno==EPIPE);
    if (mode==2) {
        sigset_t pending; CHECK(!sigpending(&pending));
        CHECK(!broken_count && sigismember(&pending,SIGPIPE));
        sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGPIPE);
        CHECK(!sigprocmask(SIG_UNBLOCK,&mask,NULL));
    }
    CHECK(broken_count==((mode==0 || mode==2) ? 1 : 0));
    if (broken_count) CHECK(broken_pid==getpid() && broken_code==SI_USER);
    close(pair[0]); close(pair[1]);
    printf("PASS credential send SIGPIPE mode=%d\n",mode);
}
static void send_inputs(int protected, int full) {
    int pair[2], one=1; CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)));
    CHECK(!prctl(PR_SET_DUMPABLE,0)); peer(pair[1],getpid(),0,0);
    CHECK(!prctl(PR_SET_DUMPABLE,!protected));
    int held[256], count=0;
    if (full) {
        struct rlimit limits; CHECK(!getrlimit(RLIMIT_NOFILE,&limits));
        limits.rlim_cur=128; CHECK(!setrlimit(RLIMIT_NOFILE,&limits));
        int fd;
        while ((fd=dup(pair[0]))>=0) { CHECK(count<256); held[count++]=fd; }
        CHECK(errno==EMFILE);
        send_identity(pair[1],0,pair[0],1);
        for (int i=0;i<count;++i) close(held[i]);
        receive_identity(pair[0],getpid(),0,MSG_CMSG_CLOEXEC,0,1);
    } else {
        /* A private token must not fill an invalid application input slot. */
        close(0);
        char byte='b'; struct iovec io={&byte,1};
        union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(sizeof(int))]; } control={0};
        struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
        control.align=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(struct ucred)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_CREDENTIALS};
        struct ucred cred={getpid(),0,0}; memcpy(CMSG_DATA(&control.align),&cred,sizeof(cred));
        struct cmsghdr *h=(void *)(control.bytes+CMSG_SPACE(sizeof(cred)));
        *h=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
        int invalid=0; memcpy(CMSG_DATA(h),&invalid,sizeof(invalid));
        CHECK(sendmsg(pair[1],&m,MSG_NOSIGNAL)==-1 && errno==EBADF);
        CHECK(recv(pair[0],&byte,1,MSG_DONTWAIT)==-1 && errno==EAGAIN);
        CHECK(fcntl(0,F_GETFD)==-1 && errno==EBADF);
    }
    close(pair[0]); close(pair[1]);
    printf("PASS credential send inputs protected=%d full=%d\n",protected,full);
}
enum { SEND_LIFETIME_BYTES=1024*1024 };
struct paused_send { int socket, right, protected; };
static int paused_sender(void *opaque) {
    struct paused_send *p=opaque;
    CHECK(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (p->protected) CHECK(!prctl(PR_SET_DUMPABLE,0));
    char *bytes=malloc(SEND_LIFETIME_BYTES); CHECK(bytes); memset(bytes,'m',SEND_LIFETIME_BYTES);
    struct iovec io={bytes,SEND_LIFETIME_BYTES};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(sizeof(int))]; } control={0};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    control.align=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(struct ucred)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_CREDENTIALS};
    struct ucred cred={getpid(),0,0}; memcpy(CMSG_DATA(&control.align),&cred,sizeof(cred));
    struct cmsghdr *h=(void *)(control.bytes+CMSG_SPACE(sizeof(cred)));
    *h=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
    memcpy(CMSG_DATA(h),&p->right,sizeof(p->right));
    CHECK(sendmsg(p->socket,&m,MSG_NOSIGNAL)==SEND_LIFETIME_BYTES);
    free(bytes);
    return 0;
}
static void send_lifetime(int protected, int cancel) {
    int pair[2], right[2], unrelated[2], one=1, capacity=4096;
    CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,right));
    CHECK(!pipe2(unrelated,O_CLOEXEC|O_NONBLOCK));
    CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)));
    CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_SNDBUF,&capacity,sizeof(capacity)));
    CHECK(!prctl(PR_SET_DUMPABLE,0)); peer(pair[0],getpid(),0,0); CHECK(!prctl(PR_SET_DUMPABLE,1));
    size_t size=1024*1024; void *stack=malloc(size); CHECK(stack);
    int before[256]; for (unsigned i=0;i<256;++i) before[i]=fcntl(i,F_GETFD);
    struct paused_send context={pair[1],right[0],protected};
    pid_t child=clone(paused_sender,(char *)stack+size,CLONE_FILES|SIGCHLD,&context); CHECK(child>0);
    /* EVENT_WAIT: the first payload byte proves the helper entered sendmsg.
     * Its bounded socket cannot accept the remaining megabyte until we drain it.
     * The enclosing launch deadline bounds missing delivery/cleanup. */
    receive_identity(pair[0],child,0,MSG_CMSG_CLOEXEC,0,1);
    CHECK(!close(unrelated[1])); before[unrelated[1]]=-1;
    char byte; CHECK(read(unrelated[0],&byte,1)==0);
    /* Table turns must be released and only captured inputs retained while
     * the syscall is blocked. Reusing the original slot cannot retarget it. */
    CHECK(dup3(unrelated[0],pair[1],O_CLOEXEC)==pair[1]);
    if (cancel) CHECK(!kill(child,SIGKILL));
    size_t received=1;
    char bytes[8192]; ssize_t n;
    while ((n=read(pair[0],bytes,sizeof(bytes)))>0) {
        received+=(size_t)n;
        for (ssize_t i=0;i<n;++i) CHECK(bytes[i]=='m');
    }
    CHECK(!n && (cancel ? received<SEND_LIFETIME_BYTES : received==SEND_LIFETIME_BYTES));
    int status; CHECK(waitpid(child,&status,0)==child);
    CHECK(cancel ? WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL : WIFEXITED(status) && !WEXITSTATUS(status));
    for (unsigned i=0;i<256;++i) CHECK(fcntl(i,F_GETFD)==before[i]);
    CHECK(!close(pair[0]) && !close(pair[1]) && !close(right[0]) && !close(right[1]));
    CHECK(!close(unrelated[0])); free(stack);
    printf("PASS credential send lifecycle protected=%d cancel=%d\n",protected,cancel);
}
static void send_contract(void) {
    for (int mode=0;mode<4;++mode) {
        pid_t child=fork(); CHECK(child>=0);
        if (!child) { send_signals(mode); exit(0); }
        done(child);
    }
    for (int protected=0;protected<2;++protected) for (int full=0;full<2;++full) {
        pid_t child=fork(); CHECK(child>=0);
        if (!child) { send_inputs(protected,full); exit(0); }
        done(child);
    }
    for (int protected=0;protected<2;++protected) for (int cancel=0;cancel<2;++cancel) send_lifetime(protected,cancel);
}
struct paused_receive { int socket, protected; };
static int paused_receiver(void *opaque) {
    struct paused_receive *p=opaque;
    CHECK(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (p->protected) CHECK(!prctl(PR_SET_DUMPABLE,0));
    char *bytes=malloc(2*SEND_LIFETIME_BYTES); CHECK(bytes);
    struct iovec io={bytes,2*SEND_LIFETIME_BYTES};
    union { struct cmsghdr align; char bytes[128]; } control={0};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    CHECK(recvmsg(p->socket,&m,MSG_WAITALL)==2*SEND_LIFETIME_BYTES);
    CHECK(!m.msg_controllen);
    for (unsigned i=0;i<2*SEND_LIFETIME_BYTES;++i) CHECK(bytes[i]=='r');
    free(bytes); return 0;
}
static void receive_lifetime(int protected, int cancel) {
    int pair[2], unrelated[2], capacity=4096;
    CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    CHECK(!pipe2(unrelated,O_CLOEXEC|O_NONBLOCK));
    CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_SNDBUF,&capacity,sizeof(capacity)));
    CHECK(!prctl(PR_SET_DUMPABLE,0)); peer(pair[0],getpid(),0,0); CHECK(!prctl(PR_SET_DUMPABLE,1));
    size_t size=1024*1024; void *stack=malloc(size); CHECK(stack);
    int before[256]; for (unsigned i=0;i<256;++i) before[i]=fcntl(i,F_GETFD);
    struct paused_receive context={pair[0],protected};
    pid_t child=clone(paused_receiver,(char *)stack+size,CLONE_FILES|SIGCHLD,&context); CHECK(child>0);
    char *bytes=malloc(SEND_LIFETIME_BYTES); CHECK(bytes); memset(bytes,'r',SEND_LIFETIME_BYTES);
    /* EVENT_WAIT: a megabyte cannot fit in the bounded send buffer. Successful
     * send proves the receiver entered MSG_WAITALL and drained its first half.
     * Launch deadline bounds both the receive and exact cancellation/reaping. */
    CHECK(send(pair[1],bytes,SEND_LIFETIME_BYTES,MSG_NOSIGNAL)==SEND_LIFETIME_BYTES);
    CHECK(!close(unrelated[1])); before[unrelated[1]]=-1;
    char byte; CHECK(read(unrelated[0],&byte,1)==0);
    CHECK(dup3(unrelated[0],pair[0],O_CLOEXEC)==pair[0]);
    if (cancel) CHECK(!kill(child,SIGKILL));
    else CHECK(send(pair[1],bytes,SEND_LIFETIME_BYTES,MSG_NOSIGNAL)==SEND_LIFETIME_BYTES);
    int status; CHECK(waitpid(child,&status,0)==child);
    CHECK(cancel ? WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL : WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(send(pair[1],"x",1,MSG_NOSIGNAL)==-1 && errno==EPIPE);
    for (unsigned i=0;i<256;++i) CHECK(fcntl(i,F_GETFD)==before[i]);
    CHECK(!close(pair[0]) && !close(pair[1]) && !close(unrelated[0])); free(bytes); free(stack);
    printf("PASS receive lifecycle protected=%d cancel=%d\n",protected,cancel);
}
static void messages(void) {
    int pair[2], transferred[2];
    CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,pair) && !socketpair(AF_UNIX,SOCK_STREAM,0,transferred));
    int one=1; CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)));
    pid_t child=fork(); CHECK(child>=0);
    if (!child) {
        send_identity(pair[1],0,transferred[0],1);
        CHECK(!setuid(1234));
        send_identity(pair[1],0,-1,0);
        send_identity(pair[1],1234,-1,1);
        _exit(0);
    }
    done(child); // Credentials must describe send-time identity after sender exit.
    receive_identity(pair[0],child,0,MSG_PEEK|MSG_CMSG_CLOEXEC,0,1);
    receive_identity(pair[0],child,0,MSG_CMSG_CLOEXEC,1,1);
    receive_identity(pair[0],child,1234,0,0,0);
    close(pair[0]); close(pair[1]); close(transferred[0]); close(transferred[1]);
    puts("PASS explicit message credentials: queued identity, rejected forgery, peek, recv batch, SCM_RIGHTS");
}
static void truncation(void) {
    int p[2], one=1; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,p));
    CHECK(!setsockopt(p[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)));
    const size_t capacities[]={1,sizeof(struct cmsghdr),CMSG_LEN(sizeof(struct ucred))-1,CMSG_SPACE(sizeof(struct ucred))};
    for (unsigned i=0;i<sizeof(capacities)/sizeof(*capacities);i++) {
        send_identity(p[1],0,-1,1);
        union { struct cmsghdr align; char bytes[128]; } control={0};
        char data; struct iovec io={&data,1};
        struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=capacities[i]};
        CHECK(recvmsg(p[0],&m,MSG_CMSG_CLOEXEC)==1 && data=='m');
        CHECK(m.msg_controllen<=capacities[i]);
        CHECK(!!(m.msg_flags&MSG_CTRUNC)==(capacities[i]<CMSG_LEN(sizeof(struct ucred))));
        for (struct cmsghdr *h=CMSG_FIRSTHDR(&m);h;h=CMSG_NXTHDR(&m,h))
            CHECK(h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDENTIALS);
    }
    for (unsigned passcred=0;passcred<2;passcred++) {
        CHECK(!setsockopt(p[0],SOL_SOCKET,SO_PASSCRED,&passcred,sizeof(passcred)));
        for (unsigned batch=0;batch<2;batch++) {
            send_identity(p[1],0,-1,1);
            char data; struct iovec io={&data,1};
            struct mmsghdr m={.msg_hdr={.msg_iov=&io,.msg_iovlen=1}};
            CHECK((batch?recvmmsg(p[0],&m,1,0,NULL):recvmsg(p[0],&m.msg_hdr,0))==1 && data=='m');
            CHECK(!m.msg_hdr.msg_controllen && !!(m.msg_hdr.msg_flags&MSG_CTRUNC)==passcred);
        }
    }
    close(p[0]); close(p[1]);
    puts("PASS ancillary truncation: no hidden descriptor publication");
}
static void bound_reuse(void) {
    int listener=socket(AF_UNIX,SOCK_STREAM,0); CHECK(listener>=0);
    struct sockaddr_un target={.sun_family=AF_UNIX}, local={.sun_family=AF_UNIX};
    snprintf(target.sun_path+1,sizeof(target.sun_path)-1,"md-ipc-reuse-server-%d",getpid());
    snprintf(local.sun_path+1,sizeof(local.sun_path)-1,"md-ipc-reuse-client-%d",getpid());
    socklen_t tn=offsetof(struct sockaddr_un,sun_path)+1+strlen(target.sun_path+1);
    socklen_t ln=offsetof(struct sockaddr_un,sun_path)+1+strlen(local.sun_path+1);
    CHECK(!bind(listener,(void *)&target,tn) && !listen(listener,4));
    int retained[2];
    for (unsigned i=0;i<2;i++) {
        CHECK(!setresuid(0,i?1234:0,0));
        int client=socket(AF_UNIX,SOCK_STREAM,0); CHECK(client>=0);
        CHECK(!bind(client,(void *)&local,ln) && !connect(client,(void *)&target,tn));
        CHECK(!setresuid(0,0,0));
        retained[i]=accept(listener,NULL,NULL); CHECK(retained[i]>=0);
        peer(retained[i],getpid(),i?1234:0,0); close(client);
    }
    peer(retained[0],getpid(),0,0); peer(retained[1],getpid(),1234,0);
    close(retained[0]); close(retained[1]); close(listener);
    puts("PASS bound-name reuse retains old connection identity");
}
static void external(const char *name,pid_t server) {
    int fd=socket(AF_UNIX,SOCK_STREAM,0); CHECK(fd>=0);
    struct sockaddr_un address={.sun_family=AF_UNIX};
    CHECK(strlen(name)<sizeof(address.sun_path)-1);
    memcpy(address.sun_path+1,name,strlen(name));
    CHECK(!connect(fd,(void *)&address,offsetof(struct sockaddr_un,sun_path)+1+strlen(name)));
    peer(fd,server,2000,2000);
    send_identity(fd,0,-1,0);
    /* The actual kernel credentials remain authoritative outside this store. */
    CHECK(!setgid(2000)); send_identity(fd,2000,-1,1);
    close(fd);
}
static void peer_full_table(int protected, unsigned count) {
    gid_t *groups=malloc(65536*sizeof(*groups)), *actual=malloc(65536*sizeof(*actual));
    CHECK(groups && actual);
    for (unsigned i=0;i<count;++i) groups[i]=2*i+1;
    CHECK(!setgroups(count,groups));
    int p[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,p));
    CHECK(!setgroups(0,NULL));
    if (protected) CHECK(!prctl(PR_SET_DUMPABLE,0));
    /* Admit the table-owned input channel before exhausting application slots. */
    peer(p[0],getpid(),0,0);
    struct rlimit old, limit; CHECK(!getrlimit(RLIMIT_NOFILE,&old));
    limit=old; limit.rlim_cur=64; CHECK(!setrlimit(RLIMIT_NOFILE,&limit));
    int owned[64], used=0, fd;
    while ((fd=fcntl(p[0],F_DUPFD_CLOEXEC,0))>=0) { CHECK(used<64); owned[used++]=fd; }
    CHECK(errno==EMFILE);
    long page=sysconf(_SC_PAGESIZE);
    void *bad=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); CHECK(bad!=MAP_FAILED);
    for (unsigned repeat=0;repeat<12;++repeat) {
        peer(p[0],getpid(),0,0);
        socklen_t n=count*sizeof(*groups);
        CHECK(!getsockopt(p[0],SOL_SOCKET,SO_PEERGROUPS,actual,&n));
        CHECK(n==count*sizeof(*groups) && !memcmp(actual,groups,n));
        n=0;
        int r=getsockopt(p[0],SOL_SOCKET,SO_PEERGROUPS,bad,&n);
        CHECK(count ? r==-1 && errno==ERANGE && n==count*sizeof(*groups) : !r && !n);
        n=sizeof(struct ucred);
        CHECK(getsockopt(p[0],SOL_SOCKET,SO_PEERCRED,bad,&n)==-1 && errno==EFAULT);
        CHECK(getsockopt(p[0],SOL_SOCKET,SO_PEERCRED,actual,bad)==-1 && errno==EFAULT);
        n=(socklen_t)-1;
        CHECK(getsockopt(p[0],SOL_SOCKET,SO_PEERCRED,actual,&n)==-1 && errno==EINVAL);
        n=0; CHECK(!getsockopt(p[0],SOL_SOCKET,SO_PEERCRED,bad,&n) && !n);
        if (count) {
            n=count*sizeof(*groups);
            CHECK(getsockopt(p[0],SOL_SOCKET,SO_PEERGROUPS,bad,&n)==-1 && errno==EFAULT);
        }
        for (int i=0;i<used;++i) CHECK(fcntl(owned[i],F_GETFD)==FD_CLOEXEC);
        CHECK(fcntl(p[0],F_DUPFD_CLOEXEC,0)==-1 && errno==EMFILE);
    }
    CHECK(!munmap(bad,page));
    for (int i=0;i<used;++i) CHECK(!close(owned[i]));
    CHECK(!setrlimit(RLIMIT_NOFILE,&old));
    close(p[0]); close(p[1]); free(groups); free(actual);
    printf("PASS peer identity full-table: protected=%d groups=%u, snapshot and output faults\n",protected,count);
}
struct custody { int socket, receive, protected, guest; };
static int custody_child(void *argument) {
    struct custody *c=argument;
    CHECK(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (c->protected) CHECK(!prctl(PR_SET_DUMPABLE,0));
    char byte=c->receive ? 0 : 'm'; struct iovec io={&byte,1};
    union { struct cmsghdr align; char data[128]; } control={0};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.data,
        .msg_controllen=c->receive ? sizeof(control.data) : CMSG_SPACE(sizeof(struct ucred))};
    struct cmsghdr *h=CMSG_FIRSTHDR(&m);
    *h=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(struct ucred)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_CREDENTIALS};
    struct ucred cred={getpid(),getuid(),getgid()}; memcpy(CMSG_DATA(h),&cred,sizeof(cred));
    struct sock_filter send_filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_sendmsg,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)c->socket,0,2),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(uintptr_t)&m,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_THREAD)
    };
    struct sock_filter receive_filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,c->receive==1 ? SYS_fstat : SYS_sendmsg,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_THREAD),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog filter={.len=c->receive ? sizeof(receive_filter)/sizeof(*receive_filter)
        : sizeof(send_filter)/sizeof(*send_filter),.filter=c->receive ? receive_filter : send_filter};
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) && !prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter));
    struct mmsghdr batch={.msg_hdr=m};
    ssize_t n=c->receive==3 ? recvmmsg(c->socket,&batch,1,MSG_CMSG_CLOEXEC,NULL)
        : c->receive ? recvmsg(c->socket,&m,MSG_CMSG_CLOEXEC) : sendmsg(c->socket,&m,0);
    if (c->receive==3) m=batch.msg_hdr;
    CHECK(n==1 || (c->guest && n==-1 && errno==ECANCELED));
    /* The export-kill cases must reach native receive, not merely reject the
     * operation at entry. Its original payload is shared with the helper. */
    if (c->receive>=2) CHECK(byte=='m' && (!c->guest || n==-1));
    if (c->receive && n==1) for (h=CMSG_FIRSTHDR(&m);h;h=CMSG_NXTHDR(&m,h))
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
            const int *fds=(const void *)CMSG_DATA(h);
            for (unsigned i=0;i<(h->cmsg_len-CMSG_LEN(0))/sizeof(int);++i) CHECK(!close(fds[i]));
        }
    return 0;
}
static void custody(int guest, int receive, int protected) {
    int pair[2], transferred[2], one=1;
    CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,transferred));
    CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)));
    if (guest) {
        int dumpable=prctl(PR_GET_DUMPABLE);
        CHECK(dumpable>=0 && !prctl(PR_SET_DUMPABLE,0));
        peer(pair[0],getpid(),getuid(),getgid());
        CHECK(!prctl(PR_SET_DUMPABLE,dumpable));
    }
    if (receive) send_identity(pair[1],getuid(),transferred[0],1);
    int before[256];
    for (unsigned i=0;i<256;++i) before[i]=fcntl(i,F_GETFD);
    struct custody c={receive ? pair[0] : pair[1],receive,protected,guest};
    size_t size=1024*1024; void *stack=malloc(size); CHECK(stack);
    pid_t child=clone(custody_child,(char *)stack+size,CLONE_FILES|SIGCHLD,&c); CHECK(child>0);
    int status;
    /* EVENT_WAIT: exact caller exit; the launch deadline bounds missing cleanup. */
    CHECK(waitpid(child,&status,0)==child);
    CHECK((WIFEXITED(status) && !WEXITSTATUS(status)) || (guest && WIFSIGNALED(status) && WTERMSIG(status)==SIGSYS));
    unsigned changed=0;
    for (unsigned i=0;i<256;++i) {
        int flags=fcntl(i,F_GETFD);
        if (flags==before[i]) continue;
        char path[64], target[256]; snprintf(path,sizeof(path),"/proc/self/fd/%u",i);
        ssize_t n=readlink(path,target,sizeof(target)-1); target[n<0 ? 0 : n]=0;
        fprintf(stderr,"custody receive=%d protected=%d fd=%u before=%d after=%d target=%s\n",
            receive,protected,i,before[i],flags,target); ++changed;
    }
    CHECK(!changed);
    free(stack); close(pair[0]); close(pair[1]); close(transferred[0]); close(transferred[1]);
    printf("PASS IPC caller custody receive=%d protected=%d guest=%d\n",receive,protected,guest);
}
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    if (argc==4 && (!strcmp(argv[1],"--custody") || !strcmp(argv[1],"--custody-native"))) {
        alarm(20);
        custody(!strcmp(argv[1],"--custody"),atoi(argv[2]),atoi(argv[3])); return 0;
    }
    CHECK(getuid()==0);
    if (argc==4 && !strcmp(argv[1],"--external")) { external(argv[2],(pid_t)atoi(argv[3])); return 0; }
    CHECK(argc==1);
    send_contract();
    for (int protected=0;protected<2;++protected) for (int cancel=0;cancel<2;++cancel)
        receive_lifetime(protected,cancel);
    for (unsigned protected=0;protected<2;++protected) for (unsigned size=0;size<3;++size) {
        pid_t child=fork(); CHECK(child>=0);
        if (!child) { peer_full_table(protected,size==0 ? 0 : size==1 ? 3 : 65536); exit(0); }
        done(child);
    }
    gid_t groups[]={7,11,19}; CHECK(!setgroups(3,groups));
    int p[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,p));
    peer(p[0],getpid(),0,0); peer(p[1],getpid(),0,0);
    gid_t actual[3]; socklen_t n=sizeof(actual);
    CHECK(!getsockopt(p[0],SOL_SOCKET,SO_PEERGROUPS,actual,&n));
    CHECK(n==sizeof(actual) && !memcmp(actual,groups,sizeof(groups)));
    n=sizeof(gid_t); errno=0;
    CHECK(getsockopt(p[0],SOL_SOCKET,SO_PEERGROUPS,actual,&n)==-1 && errno==ERANGE && n==sizeof(actual));
    struct ucred short_value={0}; n=sizeof(pid_t);
    CHECK(!getsockopt(p[0],SOL_SOCKET,SO_PEERCRED,&short_value,&n) && n==sizeof(pid_t) && short_value.pid==getpid());
    CHECK(!setgroups(0,NULL)); peer(p[0],getpid(),0,0);
    n=sizeof(actual); CHECK(!getsockopt(p[0],SOL_SOCKET,SO_PEERGROUPS,actual,&n) && n==sizeof(actual));
    close(p[0]); close(p[1]);
    stream(0); stream(1);
    messages();
    truncation();
    bound_reuse();
    puts("PASS connection snapshots: pair, groups, pathname, abstract, fork, drop, dup, peer exit");
    return 0;
}
