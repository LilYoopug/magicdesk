#define _GNU_SOURCE
#include "ipc_credentials.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static struct md_fs_result request(struct md_ipc_credentials *owner, unsigned operation,
        int fd, int second, const char *name, long result) {
    struct md_identity identity=md_identity_new(0,0);
    struct md_fs_request q={.operation=MD_FS_IPC,.flags=operation,.directory={fd,second},
        .peer=getpid(),.path={name,NULL},.offset=result};
    struct md_fs_result out;
    md_ipc_credentials_execute(owner,&identity,&q,&out,NULL);
    md_identity_release(&identity); return out;
}
static struct md_ipc_connection connection(struct md_ipc_credentials *owner, int fd) {
    struct md_ipc_connection out;
    assert(!md_ipc_credentials_connection(owner,fd,&out)); return out;
}
static void same(struct md_ipc_connection a, struct md_ipc_connection b, unsigned opposite) {
    assert(a.side==(b.side^opposite) && !memcmp(a.link,b.link,sizeof(a.link)));
}
static void unavailable(struct md_ipc_credentials *owner, int fd, int error) {
    struct md_ipc_connection out, before;
    memset(&out,0xab,sizeof(out)); before=out;
    assert(md_ipc_credentials_connection(owner,fd,&out)==error && !memcmp(&out,&before,sizeof(out)));
}
static int token(struct md_ipc_credentials *owner, int fd) {
    struct md_fs_result out=request(owner,MD_IPC_MESSAGE_CREATE,fd,-1,NULL,getpid());
    assert(!out.error && out.fd>=0); return out.fd;
}
static void token_check(struct md_ipc_credentials *owner, int fd, int value, pid_t pid, int error) {
    struct md_fs_result out=request(owner,MD_IPC_MESSAGE_READ,fd,value,NULL,0);
    assert(out.error==error && out.fd==-1);
    if (!error) assert(out.position==pid && !out.info.uid && !out.info.gid);
}
static void send_token(int socket, int value) {
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    control.align=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS,.cmsg_len=CMSG_LEN(sizeof(int))};
    memcpy(CMSG_DATA(&control.align),&value,sizeof(value));
    char byte='t'; struct iovec io={&byte,1};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    assert(sendmsg(socket,&msg,MSG_NOSIGNAL|MSG_DONTWAIT)==1);
}
static int receive_token(int socket) {
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    char byte; struct iovec io={&byte,1};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    assert(recvmsg(socket,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC)==1 && byte=='t'
        && !(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)));
    struct cmsghdr *h=CMSG_FIRSTHDR(&msg);
    assert(h && h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS && h->cmsg_len==CMSG_LEN(sizeof(int)));
    int fd; memcpy(&fd,CMSG_DATA(h),sizeof(fd)); return fd;
}
void test_ipc_store_cleanup(const char *store) {
    char path[PATH_MAX]; assert(snprintf(path,sizeof(path),"%s/ipc",store)<(int)sizeof(path));
    int dir=open(path,O_RDONLY|O_CLOEXEC|O_DIRECTORY); assert(dir>=0);
    const char *files[]={"credentials.db","credentials.db-wal","credentials.db-shm","gate","live"};
    for (unsigned i=0;i<sizeof(files)/sizeof(*files);++i) assert(!unlinkat(dir,files[i],0) || errno==ENOENT);
    assert(!close(dir) && !rmdir(path));
}
static void paired(struct md_ipc_credentials *first, struct md_ipc_credentials *second,
        struct md_ipc_credentials *foreign, int type) {
    int sockets[2], native[2];
    assert(!socketpair(AF_UNIX,type|SOCK_CLOEXEC,0,sockets)
        && !socketpair(AF_UNIX,type|SOCK_CLOEXEC,0,native));
    unavailable(first,sockets[0],-ENODATA);
    assert(!request(first,MD_IPC_PAIR,sockets[0],sockets[1],NULL,0).error);
    struct md_ipc_connection a=connection(first,sockets[0]), b=connection(second,sockets[1]);
    same(a,b,1); unavailable(foreign,sockets[1],-ENODATA);
    int alias=fcntl(sockets[0],F_DUPFD_CLOEXEC,0); assert(alias>=0);
    same(a,connection(second,alias),0);
    send_token(native[0],sockets[1]);
    int imported=receive_token(native[1]); same(b,connection(first,imported),0);
    for (unsigned i=0;i<2;++i) {
        int value=token(first,sockets[i]);
        token_check(second,sockets[i^1],value,getpid(),0);
        token_check(second,sockets[i^1],value,getpid(),0); // Peek must not consume association.
        token_check(second,sockets[i],value,0,-ENODATA);
        token_check(second,native[1],value,0,-ENODATA);
        token_check(foreign,sockets[i^1],value,0,-ENODATA);
        assert(!close(value));
    }
    assert(!close(sockets[0])); same(a,connection(second,alias),0);
    assert(!close(alias) && !close(sockets[1]) && !close(imported)
        && !close(native[0]) && !close(native[1]));
    printf("PASS IPC connection type=%d: opposite sides, dup/SCM aliases, directional credentials, peek and foreign/native rejection\n",type);
}
static int listener(int type, unsigned number, struct sockaddr_un *address, char *encoded, socklen_t *size) {
    int fd=socket(AF_UNIX,type|SOCK_CLOEXEC,0); assert(fd>=0);
    *address=(struct sockaddr_un){.sun_family=AF_UNIX};
    int n=snprintf(address->sun_path+1,sizeof(address->sun_path)-1,"md-connection-%d-%u",getpid(),number);
    assert(n>0 && n<(int)sizeof(address->sun_path)-1);
    *size=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+n);
    for (int i=0;i<=n;++i) {
        unsigned c=(unsigned char)address->sun_path[i];
        encoded[2*i]="0123456789abcdef"[c>>4]; encoded[2*i+1]="0123456789abcdef"[c&15];
    }
    encoded[2*(n+1)]=0;
    assert(!bind(fd,(void *)address,*size)); return fd;
}
static void listening(struct md_ipc_credentials *owner, int fd) {
    assert(!request(owner,MD_IPC_LISTEN_BEGIN,fd,-1,NULL,0).error);
    assert(!listen(fd,4));
    assert(!request(owner,MD_IPC_LISTEN_END,fd,-1,NULL,0).error);
}
static void independent(const char *store, struct md_ipc_credentials *first,
        struct md_ipc_credentials *second, int type, unsigned number) {
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(type,number,&address,name,&size), control[2];
    listening(first,fd);
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,control));
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        assert(!close(fd) && !close(control[0]));
        md_ipc_credentials_close(first); md_ipc_credentials_close(second);
        struct md_ipc_credentials *owner=NULL; assert(!md_ipc_credentials_open(store,&owner));
        int client=socket(AF_UNIX,type|SOCK_CLOEXEC,0); assert(client>=0);
        struct md_fs_result begun=request(owner,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
        assert(!begun.error && begun.position==1); unavailable(owner,client,-ESTALE);
        assert(!connect(client,(void *)&address,size));
        assert(!request(owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
        struct md_ipc_connection key=connection(owner,client);
        int value=token(owner,client); send_token(client,value); assert(!close(value));
        assert(send(control[1],&key,sizeof(key),MSG_NOSIGNAL)==sizeof(key));
        assert(!close(client) && !close(control[1]));
        md_ipc_credentials_close(owner); _exit(0);
    }
    assert(!close(control[1]));
    struct md_ipc_connection offered;
    /* EVENT_WAIT: child publishes its association and exits before accept;
     * the enclosing fixture alarm bounds failure. No metadata lock spans IO. */
    assert(recv(control[0],&offered,sizeof(offered),0)==sizeof(offered));
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    int peer=accept4(fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
    unavailable(second,peer,-ENODATA);
    assert(!request(second,MD_IPC_ACCEPT,peer,-1,NULL,0).error);
    same(offered,connection(first,peer),1);
    int value=receive_token(peer); token_check(first,peer,value,child,0);
    assert(!close(value) && !close(peer) && !close(fd) && !close(control[0]));
    printf("PASS IPC independent worker type=%d: send before accept, sender exit, shared association and queued credentials\n",type);
}
static void admission(struct md_ipc_credentials *owner, unsigned number, int tracked, int replaced) {
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(SOCK_STREAM,number,&address,name,&size);
    if (tracked) listening(owner,fd); else assert(!listen(fd,4));
    int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(client>=0);
    struct md_fs_result begun=request(owner,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
    assert(!begun.error && begun.position==tracked);
    if (replaced) listening(owner,fd);
    assert(!connect(client,(void *)&address,size));
    if (tracked) assert(!request(owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
    unavailable(owner,client,tracked ? -ESTALE : -ENODATA);
    int peer=accept4(fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
    assert(write(client,"n",1)==1);
    char byte; assert(read(peer,&byte,1)==1 && byte=='n');
    assert(!close(peer) && !close(client) && !close(fd));
}
static void native_listener_reuse(struct md_ipc_credentials *owner) {
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(SOCK_STREAM,9,&address,name,&size); listening(owner,fd);
    int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0), control[2];
    assert(client>=0 && !socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,control));
    struct md_fs_result begun=request(owner,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
    assert(!begun.error && begun.position==1 && !close(fd));
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        assert(!close(client) && !close(control[0]));
        md_ipc_credentials_close(owner);
        int native=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(native>=0);
        assert(!bind(native,(void *)&address,size) && !listen(native,1));
        assert(send(control[1],"r",1,MSG_NOSIGNAL)==1);
        int peer=accept4(native,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
        char byte; assert(read(peer,&byte,1)==1 && byte=='n');
        assert(!close(peer) && !close(native) && !close(control[1])); _exit(0);
    }
    assert(!close(control[1]));
    /* EVENT_WAIT: replacement listener readiness and child exit; the enclosing
     * alarm bounds failure. No metadata lock spans these native operations. */
    char byte; assert(recv(control[0],&byte,1,0)==1 && byte=='r');
    assert(!connect(client,(void *)&address,size));
    assert(request(owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error==-ESTALE);
    unavailable(owner,client,-ESTALE);
    assert(write(client,"n",1)==1);
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!close(client) && !close(control[0]));
    puts("PASS IPC native listener replacement: real peer checked before connection publication; payload remains native");
}
static void queued_name_reuse(struct md_ipc_credentials *owner, int different) {
    struct sockaddr_un address, local; socklen_t size, local_size; char name[217], unused[217];
    int fd=listener(SOCK_STREAM,7+20*different,&address,name,&size); listening(owner,fd);
    struct sockaddr_un next; socklen_t next_size; char next_name[217]; int next_fd=-1;
    if (different) { next_fd=listener(SOCK_STREAM,10,&next,next_name,&next_size); listening(owner,next_fd); }
    int client=listener(SOCK_STREAM,8+20*different,&local,unused,&local_size);
    struct md_ipc_connection offered[2];
    for (unsigned i=0;i<2;++i) {
        if (i) {
            client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(client>=0);
            assert(!bind(client,(void *)&local,local_size));
        }
        int use_next=different && i;
        struct md_fs_result begun=request(owner,MD_IPC_CONNECT_BEGIN,client,-1,use_next ? next_name : name,0);
        assert(!begun.error && begun.position==1 && !connect(client,
            (void *)(use_next ? &next : &address),use_next ? next_size : size));
        assert(!request(owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
        offered[i]=connection(owner,client);
        char byte=(char)('0'+i); assert(write(client,&byte,1)==1 && !close(client));
    }
    for (unsigned i=0;i<2;++i) {
        int peer=accept4(different && i ? next_fd : fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
        char byte; assert(read(peer,&byte,1)==1 && byte=='0'+i);
        struct md_fs_result accepted=request(owner,MD_IPC_ACCEPT,peer,-1,NULL,0);
        assert(accepted.error==(different ? 0 : -ESTALE));
        if (different) same(offered[i],connection(owner,peer),1);
        else unavailable(owner,peer,-ENODATA);
        assert(!close(peer));
    }
    assert(!close(fd));
    if (different) assert(!close(next_fd));
    printf("PASS IPC queued name reuse different=%d: distinct endpoints resolved, ambiguous connection rejected\n",different);
}
static void accepted_early(struct md_ipc_credentials *owner, struct md_ipc_credentials *other) {
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(SOCK_STREAM,5,&address,name,&size); listening(owner,fd);
    int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(client>=0);
    struct md_fs_result begun=request(other,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
    assert(!begun.error && begun.position==1 && !connect(client,(void *)&address,size));
    int peer=accept4(fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
    assert(!request(owner,MD_IPC_ACCEPT,peer,-1,NULL,0).error);
    unavailable(other,client,-ESTALE);
    int value=token(owner,peer); send_token(peer,value); assert(!close(value));
    assert(!request(other,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
    same(connection(owner,peer),connection(other,client),1);
    value=receive_token(client); token_check(other,client,value,getpid(),0);
    assert(!close(value) && !close(client) && !close(peer) && !close(fd));
    fd=listener(SOCK_STREAM,6,&address,name,&size); listening(owner,fd);
    client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(client>=0);
    begun=request(other,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
    assert(!begun.error && begun.position==1 && !close(fd));
    assert(connect(client,(void *)&address,size)==-1 && errno==ECONNREFUSED);
    assert(!request(other,MD_IPC_CONNECT_END,client,-1,NULL,-ECONNREFUSED).error);
    unavailable(other,client,-ESTALE); assert(!close(client));
    puts("PASS IPC connection ordering: accept before connect publication, server-first credentials and failed connect");
}
void test_ipc_connections(const char *directory) {
    char foreign_path[PATH_MAX];
    assert(snprintf(foreign_path,sizeof(foreign_path),"%s/foreign",directory)<(int)sizeof(foreign_path)
        && !mkdir(foreign_path,0700));
    struct md_ipc_credentials *first=NULL, *second=NULL, *foreign=NULL;
    assert(!md_ipc_credentials_open(directory,&first) && !md_ipc_credentials_open(directory,&second)
        && !md_ipc_credentials_open(foreign_path,&foreign));
    const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
    for (unsigned i=0;i<3;++i) paired(first,second,foreign,types[i]);
    independent(directory,first,second,SOCK_STREAM,1);
    independent(directory,first,second,SOCK_SEQPACKET,2);
    admission(first,3,0,0); admission(first,4,1,1);
    accepted_early(first,second);
    native_listener_reuse(first);
    queued_name_reuse(first,0); queued_name_reuse(first,1);
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets));
    assert(!request(first,MD_IPC_PAIR,sockets[0],sockets[1],NULL,0).error);
    struct md_ipc_connection before=connection(first,sockets[0]);
    int value=token(first,sockets[0]);
    md_ipc_credentials_close(first);
    same(before,connection(second,sockets[0]),0);
    md_ipc_credentials_close(second);
    assert(!md_ipc_credentials_open(directory,&first));
    unavailable(first,sockets[0],-ENODATA);
    assert(!request(first,MD_IPC_PAIR,sockets[0],sockets[1],NULL,0).error);
    struct md_ipc_connection after=connection(first,sockets[0]);
    assert(memcmp(before.link,after.link,sizeof(before.link)));
    token_check(first,sockets[1],value,0,-ENODATA);
    assert(!close(value) && !close(sockets[0]) && !close(sockets[1]));
    md_ipc_credentials_close(first); md_ipc_credentials_close(foreign);
    test_ipc_store_cleanup(directory); test_ipc_store_cleanup(foreign_path); assert(!rmdir(foreign_path));
    puts("PASS IPC connection authority: native bypass, revision rejection and last-owner epoch retirement");
}
