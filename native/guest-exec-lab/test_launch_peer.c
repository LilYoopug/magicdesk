#define _GNU_SOURCE
#include "launch_peer.h"
#include "launch_peer_wire.h"
#include "fs_wire.h"
#include "event_wait.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (entry->d_name[0]!='.') ++n;
    assert(!closedir(dir)); return n;
}
static void ready(int fd) {
    /* EVENT_WAIT: fixture rendezvous/data readiness; expiry fails the test. */
    assert(!md_event_wait_fd(fd,POLLIN,md_event_now()+5000000000LL));
}
static void reaped(pid_t child) {
    /* EVENT_WAIT: exact owned child completion; fixture alarm bounds failure. */
    int status; assert(waitpid(child,&status,0)==child);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
}
static struct md_launch_registration registration(const char *path) {
    struct md_launch_registration r;
    assert(!md_launch_register(&r,path,"/fixture","/",0)); return r;
}
static int accept_peer(int listener) {
    ready(listener);
    int fd=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC); assert(fd>=0); return fd;
}
static struct md_launch_peer_packet hello(const char *id) {
    struct md_launch_peer_packet p={.magic=MD_LAUNCH_PEER_MAGIC,.version=MD_LAUNCH_PEER_VERSION};
    memcpy(p.id,id,sizeof(p.id)); return p;
}
static void basic(const char *path) {
    unsigned before=descriptors();
    struct md_launch_registration a=registration(path), b=registration(path);
    int listener=md_launch_peer_listen(&b); assert(listener>=0);
    unsigned current=descriptors();
    assert(md_launch_peer_listen(&b)==-EADDRINUSE && descriptors()==current);
    assert(md_launch_peer_connect(&a,"../wrong")==-EINVAL && descriptors()==current);
    int client=md_launch_peer_connect(&a,b.id); assert(client>=0);
    int server=accept_peer(listener); char id[33];
    assert(!md_launch_peer_receive(server,id) && !strcmp(id,a.id));
    assert(!md_launch_peer_verify(&b,server,id));
    assert(!md_launch_peer_verify(&a,client,b.id));
    assert(recv(server,id,sizeof(id),MSG_DONTWAIT)<0 && errno==EAGAIN);
    close(listener);
    assert(md_launch_peer_connect(&a,b.id)==-ECONNREFUSED);
    assert(send(client,"next",4,MSG_NOSIGNAL)==4 && recv(server,id,sizeof(id),0)==4);
    assert(!memcmp(id,"next",4));
    close(client); close(server); md_launch_unregister(&a); md_launch_unregister(&b);
    assert(descriptors()==before);
    puts("PASS launch rendezvous: lazy listener, exact registrations, untouched next packet and no descriptor leaks");
}
static void foreign(const char *path) {
    unsigned before=descriptors(); char moved[PATH_MAX], source[PATH_MAX];
    assert(snprintf(source,sizeof(source),"%s/discovery",path)<(int)sizeof(source));
    assert(snprintf(moved,sizeof(moved),"%s/moved",path)<(int)sizeof(moved));
    assert(!mkdir(source,0700));
    struct md_launch_registration a=registration(source), b=registration(source), other=registration(path);
    int listener=md_launch_peer_listen(&b); assert(listener>=0);
    assert(md_launch_peer_connect(&other,b.id)==-ENOENT);
    assert(accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC)<0 && errno==EAGAIN);
    assert(!rename(source,moved) && !mkdir(source,0700));
    struct md_launch_registration replacement=registration(source);
    assert(md_launch_peer_connect(&replacement,b.id)==-ENOENT);
    int client=md_launch_peer_connect(&a,b.id); assert(client>=0);
    int server=accept_peer(listener); char id[33];
    assert(!md_launch_peer_receive(server,id));
    assert(md_launch_peer_verify(&other,server,id)==-ENOENT);
    assert(!md_launch_peer_verify(&b,server,id));
    close(client); close(server); close(listener);
    md_launch_unregister(&a); md_launch_unregister(&b); md_launch_unregister(&other); md_launch_unregister(&replacement);
    char records[PATH_MAX];
    assert(snprintf(records,sizeof(records),"%s/launches",source)<(int)sizeof(records)); assert(!rmdir(records));
    assert(snprintf(records,sizeof(records),"%s/launches",moved)<(int)sizeof(records)); assert(!rmdir(records));
    assert(!rmdir(source) && !rmdir(moved)); assert(descriptors()==before);
    puts("PASS discovery uses retained store directory across rename, rejects foreign/replaced stores before connect");
}
static void malformed(const char *path) {
    unsigned before=descriptors(); struct md_launch_registration owner=registration(path);
    for (unsigned i=0;i<8;++i) {
        int ctl[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,ctl));
        char id[33]; memset(id,'x',sizeof(id));
        assert(md_launch_peer_receive(ctl[1],id)==-EAGAIN && id[0]=='x');
        struct {struct md_launch_peer_packet p; char extra;} bytes={.p=hello(owner.id)};
        size_t size=sizeof(bytes.p); int error=-EPROTO, pipefd[2]={-1,-1}; struct md_fs_rights rights={0};
        switch (i) {
        case 0: ++bytes.p.magic; break;
        case 1: ++bytes.p.version; error=-EPROTONOSUPPORT; break;
        case 2: bytes.p.id[31]=0; break;
        case 3: bytes.p.id[0]='g'; break;
        case 4: --size; break;
        case 5: ++size; break;
        case 6:
            assert(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK)); rights=(struct md_fs_rights){.count=1,.fd={pipefd[1]}}; break;
        case 7: close(ctl[0]); ctl[0]=-1; error=-ECONNRESET; break;
        }
        if (ctl[0]>=0) assert(md_fs_send(ctl[0],&bytes,size,&rights)==(long)size);
        if (pipefd[1]>=0) close(pipefd[1]);
        assert(md_launch_peer_receive(ctl[1],id)==error && id[0]=='x');
        if (pipefd[0]>=0) { char byte; assert(!read(pipefd[0],&byte,1)); close(pipefd[0]); }
        if (ctl[0]>=0) close(ctl[0]);
        close(ctl[1]);
    }
    md_launch_unregister(&owner); assert(descriptors()==before);
    puts("PASS discovery malformed/version/ID/EOF rejection, unchanged outputs and unexpected-rights cleanup");
}
static void overload(const char *path) {
    unsigned before=descriptors(); struct md_launch_registration a=registration(path), b=registration(path);
    int listener=md_launch_peer_listen(&b); assert(listener>=0);
    int clients[64], n=0, failure;
    for (;;) {
        int fd=md_launch_peer_connect(&a,b.id);
        if (fd<0) { failure=fd; break; }
        assert(n<64); clients[n++]=fd;
    }
    assert(n && failure==-EAGAIN);
    for (int i=0;i<n;++i) {
        int server=accept_peer(listener); char id[33];
        assert(!md_launch_peer_receive(server,id) && !md_launch_peer_verify(&b,server,id));
        close(server); close(clients[i]);
    }
    struct rlimit old, empty; assert(!getrlimit(RLIMIT_NOFILE,&old)); empty=old; empty.rlim_cur=0;
    assert(!setrlimit(RLIMIT_NOFILE,&empty));
    assert(md_launch_peer_connect(&a,b.id)==-EMFILE && md_launch_peer_listen(&a)==-EMFILE);
    assert(!setrlimit(RLIMIT_NOFILE,&old));
    close(listener); md_launch_unregister(&a); md_launch_unregister(&b); assert(descriptors()==before);
    puts("PASS discovery bounded backlog, EMFILE, no blocking or automatic replay and exact cleanup");
}
static void impostor(const char *path) {
    unsigned before=descriptors(); struct md_launch_registration a=registration(path), b=registration(path);
    int listener=md_launch_peer_listen(&b); assert(listener>=0);
    struct sockaddr_un addr; socklen_t size=sizeof(addr);
    assert(!getsockname(listener,(struct sockaddr *)&addr,&size)); close(listener);
    int signal[2]; assert(!pipe2(signal,O_CLOEXEC)); pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent); close(signal[0]);
        /* Inherited registration is not authority to impersonate its owner. */
        assert(md_launch_peer_listen(&b)==-EACCES);
        int fake=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0); assert(fake>=0);
        assert(!bind(fake,(struct sockaddr *)&addr,size) && !listen(fake,1));
        assert(write(signal[1],"r",1)==1); close(signal[1]);
        int server=accept_peer(fake); ready(server); char byte;
        assert(recv(server,&byte,1,0)==0); close(server); close(fake); _exit(0);
    }
    close(signal[1]); ready(signal[0]); char byte; assert(read(signal[0],&byte,1)==1); close(signal[0]);
    assert(md_launch_peer_connect(&a,b.id)==-EACCES); reaped(child);
    md_launch_unregister(&a); md_launch_unregister(&b); assert(descriptors()==before);
    puts("PASS endpoint replacement by same-UID process rejected before sending hello; inherited registration rejected");
}
static void stale(const char *path) {
    unsigned before=descriptors(); struct md_launch_registration a=registration(path);
    int signal[2]; assert(!pipe2(signal,O_CLOEXEC)); pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(signal[0]); struct md_launch_registration b=registration(path);
        assert(md_launch_peer_listen(&b)>=0);
        assert(write(signal[1],b.id,sizeof(b.id))==sizeof(b.id)); _exit(0);
    }
    close(signal[1]); ready(signal[0]); char id[33]; assert(read(signal[0],id,sizeof(id))==sizeof(id)); close(signal[0]);
    reaped(child);
    assert(md_launch_peer_connect(&a,id)==-ESRCH);
    assert(md_launch_peer_connect(&a,id)==-ENOENT);
    md_launch_unregister(&a); assert(descriptors()==before);
    puts("PASS dead launch discovery retires stale record without reconnect or PID guessing");
}
static void client_identity(const char *path, int dead) {
    unsigned before=descriptors(); struct md_launch_registration b=registration(path);
    int listener=md_launch_peer_listen(&b); assert(listener>=0);
    struct sockaddr_un addr; socklen_t size=sizeof(addr);
    assert(!getsockname(listener,(struct sockaddr *)&addr,&size));
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent); close(listener);
        int client;
        if (dead) {
            struct md_launch_registration a=registration(path);
            client=md_launch_peer_connect(&a,b.id); assert(client>=0);
            _exit(0);
        }
        client=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0); assert(client>=0);
        assert(!connect(client,(struct sockaddr *)&addr,size));
        struct md_launch_peer_packet packet=hello(b.id);
        assert(md_fs_send(client,&packet,sizeof(packet),&(struct md_fs_rights){0})==sizeof(packet));
        ready(client); char byte; assert(recv(client,&byte,1,0)==0);
        close(client); _exit(0);
    }
    if (dead) reaped(child);
    int server=accept_peer(listener); ready(server); char id[33];
    assert(!md_launch_peer_receive(server,id));
    assert(md_launch_peer_verify(&b,server,id)==(dead ? -ESRCH : -EACCES));
    close(server); close(listener);
    if (!dead) reaped(child);
    md_launch_unregister(&b); assert(descriptors()==before);
    puts(dead ? "PASS queued hello from departed owner rejected before peer admission"
              : "PASS same-UID caller's forged launch ID rejected against actual socket peer");
}
void test_launch_peers(const char *path) {
    basic(path); foreign(path); malformed(path); overload(path); impostor(path); stale(path);
    client_identity(path,0); client_identity(path,1);
}
