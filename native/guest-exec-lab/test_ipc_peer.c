#define _GNU_SOURCE
#include "ipc_peer.h"
#include "ipc_peer_wire.h"
#include "fs_wire.h"
#include "launch_peer.h"
#include "event_wait.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail_calloc=-1;
void test_ipc_allocations(int budget) { fail_calloc=budget; }
void test_launch_peers(const char *);
void test_message_routes(const char *);
int test_message_route_child(int, char **);
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t count, size_t size) {
    if (!fail_calloc) { fail_calloc=-1; errno=ENOMEM; return NULL; }
    if (fail_calloc>0) --fail_calloc;
    return __real_calloc(count,size);
}
static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (entry->d_name[0]!='.') ++n;
    assert(!closedir(dir)); return n;
}
static struct md_ipc_credentials *authority(const char *path) {
    struct md_ipc_credentials *s=NULL;
    assert(!md_ipc_credentials_open(path,MD_IPC_TRANSPORT_ORIGINS_V1,&s)); return s;
}
static void pair(struct md_ipc_credentials *s, int type, int fd[2]) {
    assert(!socketpair(AF_UNIX,type|SOCK_CLOEXEC,0,fd));
    struct md_identity identity=md_identity_new(0,0);
    struct md_fs_request q={.operation=MD_FS_IPC,.flags=MD_IPC_PAIR,.directory={fd[0],fd[1]},.peer=getpid()};
    struct md_fs_result r;
    md_ipc_credentials_execute(s,&identity,&q,&r,NULL);
    md_identity_release(&identity); assert(!r.error);
}
static void control(int fd[2]) { assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,fd)); }
static struct md_ipc_peer *open_peer(struct md_ipc_credentials *s, int app, int ctl, uint64_t caps, uint64_t required) {
    struct md_ipc_peer *p=NULL;
    unsigned before=descriptors();
    assert(!md_ipc_peer_open(s,app,ctl,caps,required,&p) && p);
    assert(descriptors()==before); return p;
}
static uint64_t agreed(struct md_ipc_peer *p, unsigned side) {
    const struct md_ipc_binding *binding=NULL; uint64_t features=UINT64_MAX;
    assert(!md_ipc_peer_agreement(p,&binding,&features) && binding && binding->scope);
    assert(binding->connection.side==side && !md_ipc_peer_events(p)); return features;
}
static void handshake(struct md_ipc_peer *a, struct md_ipc_peer *b) {
    int first=0, second=0;
    /* Both endpoints are local: alternating bounded nonblocking steps needs no
     * timing assumption or readiness polling. A stalled state is a test defect. */
    for (unsigned i=0;i<4 && (!first || !second);++i) {
        first=md_ipc_peer_step(a); second=md_ipc_peer_step(b); assert(first>=0 && second>=0);
    }
    assert(first==1 && second==1);
}
static void wait_peer(struct md_ipc_peer *p) {
    int r;
    while (!(r=md_ipc_peer_step(p))) {
        struct pollfd fd={.fd=md_ipc_peer_fd(p),.events=md_ipc_peer_events(p)};
        assert(fd.fd>=0 && fd.events);
        /* EVENT_WAIT: private control readiness; timeout fails the handshake,
         * never turns an incomplete offer into an agreement. */
        assert(poll(&fd,1,5000)==1);
    }
    assert(r==1);
}
static void success(struct md_ipc_credentials *s, int type, int unsupported) {
    unsigned before=descriptors(); int app[2], ctl[2]; pair(s,type,app); control(ctl);
    struct md_ipc_peer *a=open_peer(s,app[0],ctl[0],MD_IPC_PEER_ORIGINS,0);
    struct md_ipc_peer *b=open_peer(s,app[1],ctl[1],unsupported ? 0 : MD_IPC_PEER_ORIGINS,0);
    const struct md_ipc_binding *binding=NULL; uint64_t features=UINT64_MAX;
    assert(md_ipc_peer_agreement(a,&binding,&features)==-EAGAIN && !binding && features==UINT64_MAX);
    /* Application data and pending rights keep their own kernel queue. */
    int pipefd[2]; assert(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK));
    assert(md_fs_send(app[0],"untouched",9,&(struct md_fs_rights){.count=1,.fd={pipefd[1]}})==9);
    assert(!close(pipefd[1]));
    handshake(a,b);
    assert(agreed(a,0)==(unsupported ? 0 : MD_IPC_PEER_ORIGINS) && agreed(b,1)==agreed(a,0));
    assert(md_ipc_peer_step(a)==1 && md_ipc_peer_step(b)==1);
    struct md_fs_rights rights={0}; char data[16];
    assert(md_fs_receive(app[1],data,sizeof(data),&rights)==9 && !memcmp(data,"untouched",9) && rights.count==1);
    assert(read(pipefd[0],data,1)<0 && errno==EAGAIN);
    md_fs_close_rights(&rights); assert(!read(pipefd[0],data,1)); close(pipefd[0]);
    /* Agreement stops consuming control packets; subsequent protocol owns them. */
    assert(send(ctl[0],"next",4,MSG_NOSIGNAL)==4 && md_ipc_peer_step(b)==1);
    assert(recv(ctl[1],data,sizeof(data),0)==4 && !memcmp(data,"next",4));
    md_ipc_peer_close(a); md_ipc_peer_close(b); close(app[0]); close(app[1]);
    assert(descriptors()==before);
    printf("PASS peer agreement type=%d unsupported=%d: exact sides, negotiated features, untouched bytes/rights and bounded progress\n",type,unsupported);
}
static void admission(struct md_ipc_credentials *s) {
    unsigned before=descriptors(); int app[2], ctl[2], native[2];
    pair(s,SOCK_SEQPACKET,app); control(ctl); control(native);
    struct md_ipc_peer *p=NULL;
    assert(md_ipc_peer_open(s,app[0],ctl[0],0,1,&p)==-EINVAL && !p);
    assert(md_ipc_peer_open(s,app[0],ctl[0],2,0,&p)==-EINVAL && !p);
    assert(md_ipc_peer_open(s,native[0],ctl[0],1,0,&p)==-ENODATA && !p);
    assert(!fcntl(app[1],F_SETFL,O_NONBLOCK));
    assert(md_ipc_peer_open(s,app[0],app[1],1,0,&p)==-EINVAL && !p);
    assert(!fcntl(ctl[0],F_SETFD,0));
    assert(md_ipc_peer_open(s,app[0],ctl[0],1,0,&p)==-EINVAL && !p);
    assert(!fcntl(ctl[0],F_SETFD,FD_CLOEXEC));
    assert(!fcntl(ctl[0],F_SETFL,0));
    assert(md_ipc_peer_open(s,app[0],ctl[0],1,0,&p)==-EINVAL && !p);
    assert(!fcntl(ctl[0],F_SETFL,O_NONBLOCK));
    fail_calloc=0; assert(md_ipc_peer_open(s,app[0],ctl[0],1,0,&p)==-ENOMEM && !p && fail_calloc==-1);
    char byte; assert(recv(ctl[1],&byte,1,MSG_DONTWAIT)<0 && errno==EAGAIN);
    assert(fcntl(ctl[0],F_GETFD)==FD_CLOEXEC);
    close(ctl[0]); close(ctl[1]); close(app[0]); close(app[1]); close(native[0]); close(native[1]);
    int stream[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,stream));
    assert(md_ipc_peer_open(s,-1,stream[0],1,0,&p)==-EPROTOTYPE && !p);
    close(stream[0]); close(stream[1]); assert(descriptors()==before);
    puts("PASS peer admission: native/registered-control rejection, flags, unsupported requests, allocation rollback and no early IO");
}
static struct md_ipc_peer_packet offer(struct md_ipc_peer *p, int other) {
    assert(md_ipc_peer_step(p)==0 && md_ipc_peer_events(p)==POLLIN);
    struct md_ipc_peer_packet packet; struct md_fs_rights rights;
    assert(md_fs_receive(other,&packet,sizeof(packet),&rights)==sizeof(packet) && !rights.count);
    assert(packet.kind==MD_IPC_PEER_OFFER); packet.side^=1; return packet;
}
static void failure(struct md_ipc_peer *p, int expected) {
    assert(md_ipc_peer_step(p)==expected && md_ipc_peer_step(p)==expected);
    assert(md_ipc_peer_fd(p)==-1 && !md_ipc_peer_events(p));
    const struct md_ipc_binding *binding=NULL; uint64_t features=UINT64_MAX;
    assert(md_ipc_peer_agreement(p,&binding,&features)==expected && !binding && features==UINT64_MAX);
    md_ipc_peer_close(p);
}
static void malformed(struct md_ipc_credentials *s) {
    unsigned before=descriptors();
    for (unsigned case_id=0;case_id<11;++case_id) {
        int app[2], ctl[2]; pair(s,SOCK_STREAM,app); control(ctl);
        struct md_ipc_peer *p=open_peer(s,app[0],ctl[0],1,0);
        struct md_ipc_peer_packet packet=offer(p,ctl[1]); int error=-EPROTO;
        size_t size=sizeof(packet); struct md_fs_rights rights={0}; int pipefd[2]={-1,-1};
        switch (case_id) {
        case 0: ++packet.magic; break;
        case 1: ++packet.version; error=-EPROTONOSUPPORT; break;
        case 2: packet.side^=1; error=-EXDEV; break;
        case 3: ++packet.link[0]; error=-EXDEV; break;
        case 4: packet.kind=MD_IPC_PEER_CONFIRM; break;
        case 5: ++packet.echo[0]; break;
        case 6: packet.required=2; break;
        case 7: packet.supported=packet.required=2; error=-ENOTSUP; break;
        case 8: --size; break;
        case 9: assert(!close(ctl[1])); ctl[1]=-1; error=-ECONNRESET; break;
        case 10:
            assert(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK)); rights=(struct md_fs_rights){.count=1,.fd={pipefd[1]}};
            break;
        }
        if (ctl[1]>=0) assert(md_fs_send(ctl[1],&packet,size,&rights)==(long)size);
        if (pipefd[1]>=0) close(pipefd[1]);
        failure(p,error);
        if (pipefd[0]>=0) { char byte; assert(!read(pipefd[0],&byte,1)); close(pipefd[0]); }
        close(app[0]); close(app[1]); if (ctl[1]>=0) close(ctl[1]);
        assert(descriptors()==before);
    }
    puts("PASS peer malformed/version/side/link/feature/EOF rejection, sticky errors and unexpected-rights cleanup");
}
static void truncated(struct md_ipc_credentials *s) {
    unsigned before=descriptors();
    for (unsigned ancillary=0;ancillary<2;++ancillary) {
        int app[2], ctl[2], pipefd[2]; pair(s,SOCK_STREAM,app); control(ctl);
        assert(!pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        struct md_ipc_peer *p=open_peer(s,app[0],ctl[0],1,0);
        struct { struct md_ipc_peer_packet packet; char extra; } bytes={.packet=offer(p,ctl[1])};
        int fds[]={pipefd[1],pipefd[1],pipefd[1]};
        union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(fds))]; } rights={0};
        rights.align=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS,.cmsg_len=CMSG_LEN(sizeof(fds))};
        memcpy(CMSG_DATA(&rights.align),fds,sizeof(fds));
        struct iovec io={&bytes,sizeof(bytes.packet)+(ancillary ? 0 : 1)};
        struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=rights.data,.msg_controllen=sizeof(rights)};
        assert(sendmsg(ctl[1],&msg,MSG_NOSIGNAL)==(ssize_t)io.iov_len && !close(pipefd[1]));
        failure(p,-EPROTO);
        char byte; assert(!read(pipefd[0],&byte,1)); close(pipefd[0]);
        close(ctl[1]); close(app[0]); close(app[1]); assert(descriptors()==before);
    }
    puts("PASS peer packet/control truncation closes every installed or kernel-discarded right");
}
static void backpressure(struct md_ipc_credentials *s) {
    unsigned before=descriptors(); int app[2], ctl[2]; pair(s,SOCK_STREAM,app); control(ctl);
    int size=1024; assert(!setsockopt(ctl[0],SOL_SOCKET,SO_SNDBUF,&size,sizeof(size)));
    struct md_ipc_peer *a=open_peer(s,app[0],ctl[0],1,0);
    unsigned queued=0;
    while (send(ctl[0],"q",1,MSG_DONTWAIT|MSG_NOSIGNAL)==1) assert(++queued<1024);
    assert(errno==EAGAIN && queued);
    assert(md_ipc_peer_step(a)==0 && md_ipc_peer_events(a)==POLLOUT);
    char byte;
    for (unsigned i=0;i<queued;++i) assert(recv(ctl[1],&byte,1,MSG_DONTWAIT)==1 && byte=='q');
    struct md_ipc_peer *b=open_peer(s,app[1],ctl[1],1,0); handshake(a,b);
    assert(agreed(a,0)==1 && agreed(b,1)==1);
    md_ipc_peer_close(a); md_ipc_peer_close(b); close(app[0]); close(app[1]);
    assert(descriptors()==before);
    puts("PASS peer full control queue: nonblocking pending state, readiness resumption and no duplicate offer");
}
static void confirmations(struct md_ipc_credentials *s) {
    unsigned before=descriptors();
    for (unsigned case_id=0;case_id<5;++case_id) {
        int app[2], ctl[2]; pair(s,SOCK_STREAM,app); control(ctl);
        struct md_ipc_peer *p=open_peer(s,app[0],ctl[0],1,0);
        struct md_ipc_peer_packet original=offer(p,ctl[1]), packet=original;
        memset(packet.nonce,0xab,sizeof(packet.nonce));
        assert(md_fs_send(ctl[1],&packet,sizeof(packet),&(struct md_fs_rights){0})==sizeof(packet));
        assert(md_ipc_peer_step(p)==0);
        struct md_ipc_peer_packet reply; struct md_fs_rights rights;
        assert(md_fs_receive(ctl[1],&reply,sizeof(reply),&rights)==sizeof(reply) && !rights.count);
        assert(reply.kind==MD_IPC_PEER_CONFIRM && !memcmp(reply.echo,packet.nonce,sizeof(reply.echo)));
        packet.kind=MD_IPC_PEER_CONFIRM; memcpy(packet.echo,original.nonce,sizeof(packet.echo));
        switch (case_id) {
        case 0: ++packet.echo[0]; break;
        case 1: ++packet.nonce[0]; break;
        case 2: packet.supported=0; break;
        case 3: packet.required=1; break;
        case 4: packet.kind=MD_IPC_PEER_OFFER; break;
        }
        assert(md_fs_send(ctl[1],&packet,sizeof(packet),&(struct md_fs_rights){0})==sizeof(packet));
        failure(p,-EPROTO); close(ctl[1]); close(app[0]); close(app[1]);
        assert(descriptors()==before);
    }
    puts("PASS peer confirmation: nonce/echo binding, changed agreement and duplicate offer rejection");
}
static void required(struct md_ipc_credentials *s) {
    int app[2], ctl[2]; pair(s,SOCK_STREAM,app); control(ctl);
    struct md_ipc_peer *a=open_peer(s,app[0],ctl[0],1,1), *b=open_peer(s,app[1],ctl[1],0,0);
    assert(md_ipc_peer_step(a)==0);
    failure(b,-ENOTSUP); failure(a,-ENOTSUP);
    close(app[0]); close(app[1]);
    puts("PASS incompatible required feature fails both peers without application framing");
}
static void kernel_lifetime(struct md_ipc_credentials *s) {
    int app[2], ctl[2]; pair(s,SOCK_STREAM,app); control(ctl);
    struct md_ipc_peer *p=open_peer(s,app[0],ctl[0],1,0);
    assert(!close(app[0])); char byte;
    assert(recv(app[1],&byte,1,MSG_DONTWAIT)==0);
    md_ipc_peer_close(p); assert(recv(ctl[1],&byte,1,MSG_DONTWAIT)==0);
    close(app[1]); close(ctl[1]);
    puts("PASS peer pins metadata only: application EOF and cancellation remain kernel-owned");
}
static void epoch(const char *path) {
    unsigned before=descriptors();
    struct md_ipc_credentials *s=authority(path); int app[2], ctl[2]; pair(s,SOCK_STREAM,app); control(ctl);
    struct md_ipc_connection old; assert(!md_ipc_credentials_connection(s,app[0],&old));
    struct md_ipc_peer *a=open_peer(s,app[0],ctl[0],1,0), *b=open_peer(s,app[1],ctl[1],1,0);
    md_ipc_credentials_close(s); handshake(a,b);
    int maintenance=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(maintenance>=0);
    assert(flock(maintenance,LOCK_EX|LOCK_NB)<0 && errno==EWOULDBLOCK);
    s=authority(path); struct md_ipc_connection current;
    assert(!md_ipc_credentials_connection(s,app[0],&current) && !memcmp(old.link,current.link,sizeof(old.link)));
    md_ipc_credentials_close(s); md_ipc_peer_close(a);
    s=authority(path); assert(!md_ipc_credentials_connection(s,app[0],&current)); md_ipc_credentials_close(s);
    md_ipc_peer_close(b);
    assert(!flock(maintenance,LOCK_EX|LOCK_NB));
    struct md_ipc_credentials *denied=NULL;
    assert(md_ipc_credentials_open(path,MD_IPC_TRANSPORT_ORIGINS_V1,&denied)==-EBUSY && !denied);
    assert(!close(maintenance));
    s=authority(path); assert(md_ipc_credentials_connection(s,app[0],&current)==-ENODATA);
    md_ipc_credentials_close(s); close(app[0]); close(app[1]); assert(descriptors()==before);
    puts("PASS peer epoch survives all SQLite owners, excludes store maintenance, retires on last binding and never retains application sockets");
}
static void independent(const char *path, struct md_ipc_credentials *s) {
    unsigned before=descriptors(); int app[2], ready[2]; pair(s,SOCK_STREAM,app);
    assert(!pipe2(ready,O_CLOEXEC));
    struct md_launch_registration registration;
    assert(!md_launch_register(&registration,path,"/peer-client","/",0));
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        close(app[0]); close(ready[0]); md_ipc_credentials_close(s);
        char application[16], channel[16];
        snprintf(application,sizeof(application),"%d",app[1]); snprintf(channel,sizeof(channel),"%d",ready[1]);
        assert(!fcntl(app[1],F_SETFD,0) && !fcntl(ready[1],F_SETFD,0));
        execl("/proc/self/exe","ipc-peer","--child",path,application,channel,(char *)NULL);
        _exit(91);
    }
    close(app[1]); close(ready[1]);
    char id[33];
    /* EVENT_WAIT: independent launch publishes its discovery ID; expiry fails. */
    assert(!md_event_wait_fd(ready[0],POLLIN,md_event_now()+5000000000LL));
    assert(read(ready[0],id,sizeof(id))==sizeof(id)); close(ready[0]);
    int channel=md_launch_peer_connect(&registration,id); assert(channel>=0);
    struct md_ipc_peer *p=open_peer(s,app[0],channel,1,1); close(app[0]);
    wait_peer(p); assert(agreed(p,0)==1);
    /* EVENT_WAIT: exact independent peer exit; fixture alarm bounds failure. */
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    md_ipc_peer_close(p); md_launch_unregister(&registration); assert(descriptors()==before);
    puts("PASS independent exec peer discovery, live launch verification and application agreement without inherited control channel");
}
int main(int argc, char **argv) {
    int route=test_message_route_child(argc,argv);
    if (route>=0) return route;
    if (argc==5 && !strcmp(argv[1],"--child")) {
        /* EVENT_WAIT: child handshake failure bound, independent of parent. */
        alarm(15);
        int application=atoi(argv[3]), ready=atoi(argv[4]);
        assert(!fcntl(application,F_SETFD,FD_CLOEXEC));
        struct md_launch_registration registration;
        assert(!md_launch_register(&registration,argv[2],"/peer-server","/",0));
        int listener=md_launch_peer_listen(&registration); assert(listener>=0);
        assert(write(ready,registration.id,sizeof(registration.id))==sizeof(registration.id)); close(ready);
        int64_t deadline=md_event_now()+5000000000LL;
        /* EVENT_WAIT: private connection and discovery hello; expiry rejects admission. */
        assert(!md_event_wait_fd(listener,POLLIN,deadline));
        int channel=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC); assert(channel>=0); close(listener);
        assert(!md_event_wait_fd(channel,POLLIN,deadline));
        char id[33]; assert(!md_launch_peer_receive(channel,id));
        assert(!md_launch_peer_verify(&registration,channel,id));
        struct md_ipc_credentials *s=authority(argv[2]);
        struct md_ipc_peer *p=open_peer(s,application,channel,1,1);
        close(application); md_ipc_credentials_close(s);
        wait_peer(p); assert(agreed(p,1)==1); md_ipc_peer_close(p); md_launch_unregister(&registration); return 0;
    }
    assert(argc==2 && !mkdir(argv[1],0700));
    /* EVENT_WAIT: fixture-wide failure bound for child exit and control IO. */
    alarm(45);
    unsigned before=descriptors();
    test_launch_peers(argv[1]);
    test_message_routes(argv[1]);
    for (int allocation=0;allocation<2;++allocation) {
        struct md_ipc_credentials *failed=NULL; fail_calloc=allocation;
        assert(md_ipc_credentials_open(argv[1],MD_IPC_TRANSPORT_ORIGINS_V1,&failed)==-ENOMEM && !failed && fail_calloc==-1);
        assert(descriptors()==before);
    }
    struct md_ipc_credentials *s=authority(argv[1]);
    const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
    for (unsigned i=0;i<3;++i) for (int zero=0;zero<2;++zero) success(s,types[i],zero);
    admission(s); malformed(s); truncated(s); backpressure(s); confirmations(s); required(s);
    kernel_lifetime(s); independent(argv[1],s);
    md_ipc_credentials_close(s); epoch(argv[1]);
    assert(descriptors()==before);
    puts("PASS private IPC peer negotiation");
    return 0;
}
