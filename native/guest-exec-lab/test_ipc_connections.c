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
    md_ipc_credentials_execute(owner,&identity,NULL,&q,&out,NULL);
    md_identity_release(&identity); return out;
}
static struct md_ipc_connection connection(struct md_ipc_credentials *owner, int fd) {
    struct md_ipc_connection out;
    assert(!md_ipc_credentials_connection(owner,fd,&out)); return out;
}
static void selected(struct md_ipc_credentials *owner, int fd, enum md_ipc_ancillary_transport expected) {
    struct md_ipc_binding binding={0}, retained={0};
    assert(!md_ipc_credentials_bind(owner,fd,&binding) && binding.transport==expected);
    assert(!md_ipc_binding_copy(&retained,&binding));
    md_ipc_binding_release(&binding);
    assert(retained.transport==expected); md_ipc_binding_release(&retained);
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
    assert(out.error==error);
    if (!error) { assert(out.fd>=0 && out.position==pid && !out.info.uid && !out.info.gid); close(out.fd); }
    else assert(out.fd==-1);
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
static void user_namespaces(struct md_ipc_credentials *owner) {
    struct md_identity parent=md_identity_new(1000,2000), child=md_identity_copy(&parent);
    uint32_t groups[]={2000,2001,3000};
    assert(!md_identity_groups(&parent,groups,3) && !md_identity_enter_user_namespace(&child));
    struct md_user_authority authority={.caps=UINT64_MAX};
    struct md_id_extent users={0,1000,2}, gids={0,2000,2};
    assert(!md_user_namespace_map(child.user_namespace,0,&authority,&authority,&users,1));
    assert(!md_user_namespace_map(child.user_namespace,1,&authority,&authority,&gids,1));
    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    struct md_fs_request q={.operation=MD_FS_IPC,.flags=MD_IPC_PAIR,
        .directory={pair[0],pair[1]},.peer=getpid()};
    struct md_fs_result out;
    md_ipc_credentials_execute(owner,&parent,NULL,&q,&out,NULL); assert(!out.error);
    struct { struct md_ipc_identity identity; uint32_t groups[3]; } peer;
    struct md_fs_output output={.data=&peer,.capacity=sizeof(peer)};
    q.operation=MD_FS_IPC_PEER; q.mode=1;
    md_ipc_credentials_execute(owner,&child,NULL,&q,&out,&output);
    assert(!out.error && out.size==sizeof(peer) && !peer.identity.uid && !peer.identity.gid
        && peer.identity.group_count==3 && peer.groups[0]==0 && peer.groups[1]==1 && peer.groups[2]==65534);
    md_ipc_credentials_execute(owner,&parent,NULL,&q,&out,&output);
    assert(!out.error && peer.identity.uid==1000 && peer.identity.gid==2000
        && !memcmp(peer.groups,groups,sizeof(groups)));
    q.operation=MD_FS_IPC; q.flags=MD_IPC_MESSAGE_CREATE; q.offset=getpid(); q.mode=0;
    md_ipc_credentials_execute(owner,&child,NULL,&q,&out,NULL); assert(!out.error && out.fd>=0);
    int token=out.fd;
    q.flags=MD_IPC_MESSAGE_READ; q.directory[0]=pair[1]; q.directory[1]=token;
    md_ipc_credentials_execute(owner,&parent,NULL,&q,&out,NULL);
    assert(!out.error && out.info.uid==1000 && out.info.gid==2000);
    close(out.fd);
    md_ipc_credentials_execute(owner,&child,NULL,&q,&out,NULL);
    assert(!out.error && !out.info.uid && !out.info.gid);
    close(out.fd);
    q.flags=MD_IPC_MESSAGE_CREATE; q.directory[0]=pair[0]; q.attributes.uid=2;
    md_ipc_credentials_execute(owner,&child,NULL,&q,&out,NULL); assert(out.error==-EINVAL && out.fd==-1);
    q.attributes.uid=1; child.caps.effective=0;
    md_ipc_credentials_execute(owner,&child,NULL,&q,&out,NULL); assert(out.error==-EPERM && out.fd==-1);
    q.attributes.uid=0;
    md_ipc_credentials_execute(owner,&child,NULL,&q,&out,NULL); assert(!out.error && out.fd>=0); close(out.fd);
    struct md_identity unmapped=md_identity_copy(&parent);
    assert(!md_identity_enter_user_namespace(&unmapped));
    q.flags=MD_IPC_MESSAGE_SENDER;
    md_ipc_credentials_execute(owner,&unmapped,NULL,&q,&out,NULL); assert(!out.error && out.fd>=0);
    int implicit=out.fd;
    q.flags=MD_IPC_MESSAGE_READ; q.directory[0]=pair[1]; q.directory[1]=implicit;
    md_ipc_credentials_execute(owner,&parent,NULL,&q,&out,NULL);
    assert(!out.error && out.info.uid==1000 && out.info.gid==2000);
    close(out.fd);
    md_ipc_credentials_execute(owner,&unmapped,NULL,&q,&out,NULL);
    assert(!out.error && out.info.uid==65534 && out.info.gid==65534);
    close(out.fd);
    close(implicit); md_identity_release(&unmapped);
    close(token); close(pair[0]); close(pair[1]);
    md_identity_release(&parent); md_identity_release(&child);
    puts("PASS IPC namespace credentials: canonical snapshots, receiver-relative peers/groups/messages and unmapped/unauthorized sender rejection");
}
static void pid_namespaces(struct md_ipc_credentials *owner) {
    struct md_identity identity=md_identity_new(0,0);
    struct md_pid_namespace *parent=md_pid_namespace_new(NULL,NULL);
    struct md_pid_namespace *child=md_pid_namespace_new(parent,NULL);
    struct md_pid_namespace *other=md_pid_namespace_new(NULL,NULL);
    assert(parent && child && other);
    struct md_pid_identity *viewers[4]={0}, *sender=NULL;
    assert(!md_pid_identity_prepare(parent,&viewers[0])
        && !md_pid_identity_prepare(child,&viewers[1])
        && !md_pid_identity_prepare(other,&viewers[2])
        && !md_pid_identity_prepare(child,&sender));
    for (unsigned i=0;i<3;++i) assert(!md_pid_identity_publish(viewers[i],getpid()+i+1,getpid()+i+1));
    assert(!md_pid_identity_publish(sender,getpid(),getpid()));
    pid_t expected[]={md_pid_identity_number(sender,parent),md_pid_identity_number(sender,child),0,getpid()};
    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    struct md_fs_request q={.operation=MD_FS_IPC,.flags=MD_IPC_PAIR,
        .directory={pair[0],pair[1]},.peer=getpid()};
    struct md_fs_result out;
    md_ipc_credentials_execute(owner,&identity,sender,&q,&out,NULL); assert(!out.error);
    q.flags=MD_IPC_MESSAGE_CREATE; q.offset=getpid();
    md_ipc_credentials_execute(owner,&identity,sender,&q,&out,NULL);
    assert(out.error==-EPERM && out.fd==-1);
    q.offset=expected[1];
    md_ipc_credentials_execute(owner,&identity,sender,&q,&out,NULL); assert(!out.error && out.fd>=0);
    int token=out.fd;
    md_pid_identity_exit(sender); md_pid_identity_reap(sender); md_pid_identity_release(sender);
    /* A new native process with the same PID cannot retarget saved credentials. */
    assert(!md_pid_identity_prepare(child,&sender) && !md_pid_identity_publish(sender,getpid(),getpid()));
    assert(md_pid_identity_number(sender,child)!=expected[1]);
    for (unsigned i=0;i<4;++i) {
        struct md_ipc_identity peer;
        struct md_fs_output output={.data=&peer,.capacity=sizeof(peer)};
        q.operation=MD_FS_IPC_PEER; q.mode=0;
        md_ipc_credentials_execute(owner,&identity,viewers[i],&q,&out,&output);
        assert(!out.error && out.size==sizeof(peer) && peer.pid==expected[i]);
        q.operation=MD_FS_IPC; q.flags=MD_IPC_MESSAGE_READ;
        q.directory[0]=pair[1]; q.directory[1]=token;
        md_ipc_credentials_execute(owner,&identity,viewers[i],&q,&out,NULL);
        assert(!out.error && out.position==expected[i]);
        close(out.fd);
    }
    close(token); close(pair[0]); close(pair[1]);
    md_pid_identity_release(sender);
    for (unsigned i=0;i<3;++i) md_pid_identity_release(viewers[i]);
    md_pid_namespace_release(other); md_pid_namespace_release(child); md_pid_namespace_release(parent);
    md_identity_release(&identity);
    puts("PASS IPC PID credentials: connection/send snapshots, receiver-relative numbers, reaping and native PID reuse");
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
        struct md_ipc_credentials *second, int type, unsigned number,
        enum md_ipc_ancillary_transport offer, enum md_ipc_ancillary_transport expected) {
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(type,number,&address,name,&size), control[2];
    listening(first,fd);
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,control));
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        assert(!close(fd) && !close(control[0]));
        md_ipc_credentials_close(first); md_ipc_credentials_close(second);
        struct md_ipc_credentials *owner=NULL;
        assert(!md_ipc_credentials_open(store,offer,&owner));
        int client=socket(AF_UNIX,type|SOCK_CLOEXEC,0); assert(client>=0);
        struct md_fs_result begun=request(owner,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
        assert(!begun.error && begun.position==1); unavailable(owner,client,-ESTALE);
        assert(!connect(client,(void *)&address,size));
        assert(!request(owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
        struct md_ipc_connection key=connection(owner,client);
        selected(owner,client,expected);
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
    selected(second,peer,expected);
    int value=receive_token(peer); token_check(first,peer,value,child,0);
    assert(!close(value) && !close(peer) && !close(fd) && !close(control[0]));
    printf("PASS IPC independent worker type=%d transport=%u: send before accept, sender exit, shared association and queued credentials\n",type,expected);
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
static void transport_connection(struct md_ipc_credentials *server, struct md_ipc_credentials *client_owner,
        struct md_ipc_credentials *accept_owner, int type, unsigned number, int early,
        enum md_ipc_ancillary_transport expected) {
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(type,number,&address,name,&size); listening(server,fd);
    int client=socket(AF_UNIX,type|SOCK_CLOEXEC,0); assert(client>=0);
    struct md_fs_result begun=request(client_owner,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
    assert(!begun.error && begun.position==1);
    struct md_ipc_binding absent={0};
    assert(md_ipc_credentials_bind(client_owner,client,&absent)==-ESTALE && !absent.scope);
    assert(!connect(client,(void *)&address,size));
    if (!early) {
        assert(!request(client_owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
        selected(client_owner,client,expected);
    }
    int peer=accept4(fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
    assert(!request(accept_owner,MD_IPC_ACCEPT,peer,-1,NULL,0).error);
    selected(accept_owner,peer,expected);
    if (early) assert(!request(client_owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
    selected(client_owner,client,expected);
    same(connection(server,client),connection(client_owner,peer),1);
    int pipefd[2]; assert(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK));
    send_token(client,pipefd[1]); assert(!close(pipefd[1]));
    int value=receive_token(peer); assert(write(value,"r",1)==1 && !close(value));
    char byte; assert(read(pipefd[0],&byte,1)==1 && byte=='r' && !read(pipefd[0],&byte,1));
    assert(!close(pipefd[0]) && !close(client) && !close(peer) && !close(fd));
    printf("PASS IPC transport connection type=%d early=%d selected=%u: creation-time agreement, unchanged payload and rights\n",
        type,early,expected);
}
static void transport_pair(struct md_ipc_credentials *owner, struct md_ipc_credentials *other,
        int type, enum md_ipc_ancillary_transport expected) {
    int app[2], channel[2];
    assert(!socketpair(AF_UNIX,type|SOCK_CLOEXEC,0,app)
        && !socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel));
    assert(!request(owner,MD_IPC_PAIR,app[0],app[1],NULL,0).error);
    struct md_ipc_connection before=connection(owner,app[0]);
    for (unsigned i=0;i<2;++i) selected(other,app[i],expected);
    assert(request(other,MD_IPC_PAIR,app[0],app[1],NULL,0).error==-EALREADY);
    same(before,connection(other,app[0]),0); selected(other,app[0],expected);
    /* The first row is new, but the second conflicts. Neither row may change. */
    assert(request(other,MD_IPC_PAIR,channel[0],app[1],NULL,0).error==-EALREADY);
    unavailable(owner,channel[0],-ENODATA);
    same(before,connection(other,app[1]),1); selected(other,app[1],expected);
    int alias=fcntl(app[1],F_DUPFD_CLOEXEC,0); assert(alias>=0);
    send_token(channel[0],alias); assert(!close(alias) && !close(app[1]));
    int imported=receive_token(channel[1]); selected(other,imported,expected);
    same(before,connection(other,imported),1);
    assert(!close(imported) && !close(app[0]) && !close(channel[0]) && !close(channel[1]));
    printf("PASS IPC transport pair type=%d selected=%u: immutable aliases, SCM transfer and atomic rollback\n",type,expected);
}
static void transport_revision(struct md_ipc_credentials *origins, struct md_ipc_credentials *native, int stage) {
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(SOCK_STREAM,130+(unsigned)stage,&address,name,&size); listening(origins,fd);
    int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(client>=0);
    assert(!request(origins,MD_IPC_CONNECT_BEGIN,client,-1,name,0).error);
    if (!stage) listening(native,fd);
    assert(!connect(client,(void *)&address,size));
    if (stage==2) {
        assert(!request(origins,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
        listening(native,fd);
    }
    int peer=accept4(fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
    assert(request(native,MD_IPC_ACCEPT,peer,-1,NULL,0).error==(stage ? 0 : -ESTALE));
    if (stage==1) listening(native,fd);
    assert(!request(origins,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
    if (stage) {
        selected(native,client,MD_IPC_TRANSPORT_ORIGINS_V1);
        selected(native,peer,MD_IPC_TRANSPORT_ORIGINS_V1);
    } else {
        unavailable(native,client,-ESTALE); unavailable(native,peer,-ENODATA);
    }
    assert(!close(client) && !close(peer) && !close(fd));
    printf("PASS IPC transport listener revision stage=%d: pending offers rejected, completed agreement retained\n",stage);
}
static void transports(const char *store, struct md_ipc_credentials *native) {
    struct md_ipc_credentials *origins=NULL;
    assert(md_ipc_credentials_open(store,(enum md_ipc_ancillary_transport)2,&origins)==-EINVAL && !origins);
    assert(!md_ipc_credentials_open(store,MD_IPC_TRANSPORT_ORIGINS_V1,&origins));
    struct md_ipc_credentials *owners[]={native,origins};
    const int types[]={SOCK_STREAM,SOCK_SEQPACKET,SOCK_DGRAM};
    unsigned number=100;
    for (unsigned type=0;type<2;++type) for (unsigned early=0;early<2;++early)
        for (unsigned server=0;server<2;++server) for (unsigned client=0;client<2;++client)
            transport_connection(owners[server],owners[client],owners[server^1],types[type],number++,(int)early,
                server && client ? MD_IPC_TRANSPORT_ORIGINS_V1 : MD_IPC_TRANSPORT_NATIVE);
    for (unsigned type=0;type<3;++type) for (unsigned owner=0;owner<2;++owner)
        transport_pair(owners[owner],owners[owner^1],types[type],
            owner ? MD_IPC_TRANSPORT_ORIGINS_V1 : MD_IPC_TRANSPORT_NATIVE);
    for (int stage=0;stage<3;++stage) transport_revision(origins,native,stage);
    for (unsigned type=0;type<2;++type) {
        independent(store,origins,native,types[type],140+type,MD_IPC_TRANSPORT_ORIGINS_V1,MD_IPC_TRANSPORT_ORIGINS_V1);
        independent(store,origins,native,types[type],150+type,MD_IPC_TRANSPORT_NATIVE,MD_IPC_TRANSPORT_NATIVE);
    }
    md_ipc_credentials_close(origins);
}
static void exposure(const char *store) {
    struct md_ipc_credentials *owner=NULL,*other=NULL;
    assert(!md_ipc_credentials_open(store,MD_IPC_TRANSPORT_ORIGINS_V1,&owner));
    assert(!md_ipc_credentials_open(store,MD_IPC_TRANSPORT_ORIGINS_V1,&other));
    const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
    for (unsigned t=0;t<3;++t) {
        int framed[2], raw[2], pipefd[2];
        assert(!socketpair(AF_UNIX,types[t]|SOCK_CLOEXEC,0,framed));
        assert(!socketpair(AF_UNIX,types[t]|SOCK_CLOEXEC,0,raw));
        assert(!pipe2(pipefd,O_CLOEXEC));
        assert(!request(owner,MD_IPC_PAIR,framed[0],framed[1],NULL,0).error);
        int batch[]={raw[0],pipefd[0],framed[1]};
        assert(md_ipc_credentials_native(other,batch,3)==-EXDEV);
        /* Rejected batches publish no partial exposure. */
        assert(!request(other,MD_IPC_PAIR,raw[0],raw[1],NULL,0).error);
        selected(owner,raw[0],MD_IPC_TRANSPORT_ORIGINS_V1);
        int alias=dup(framed[0]); assert(alias>=0);
        assert(md_ipc_credentials_native(owner,&alias,1)==-EXDEV);
        assert(write(framed[0],"q",1)==1);
        char byte; assert(read(framed[1],&byte,1)==1 && byte=='q');
        assert(!close(alias));
        for (unsigned i=0;i<2;++i) assert(!close(framed[i]) && !close(raw[i]) && !close(pipefd[i]));

        assert(!socketpair(AF_UNIX,types[t]|SOCK_CLOEXEC,0,raw));
        alias=dup(raw[0]); assert(alias>=0);
        assert(!md_ipc_credentials_native(other,&alias,1));
        assert(!request(owner,MD_IPC_PAIR,raw[0],raw[1],NULL,0).error);
        unavailable(owner,raw[0],-ENODATA); unavailable(other,raw[1],-ENODATA);
        assert(!close(alias) && !close(raw[0]) && !close(raw[1]));
    }
    for (unsigned exported_listener=0;exported_listener<2;++exported_listener) {
        struct sockaddr_un address; socklen_t size; char name[217];
        int fd=listener(SOCK_STREAM,170+exported_listener,&address,name,&size);
        int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(client>=0);
        int exported=exported_listener ? fd : client;
        assert(!md_ipc_credentials_native(other,&exported,1));
        listening(owner,fd);
        struct md_fs_result begun=request(owner,MD_IPC_CONNECT_BEGIN,client,-1,name,0);
        assert(!begun.error && !begun.position);
        assert(!connect(client,(void *)&address,size));
        int peer=accept4(fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
        assert(!request(owner,MD_IPC_ACCEPT,peer,-1,NULL,0).error);
        unavailable(owner,client,-ENODATA); unavailable(other,peer,-ENODATA);
        assert(!close(peer) && !close(client) && !close(fd));
    }
    struct sockaddr_un address; socklen_t size; char name[217];
    int fd=listener(SOCK_STREAM,175,&address,name,&size); listening(owner,fd);
    assert(md_ipc_credentials_native(other,&fd,1)==-EXDEV);
    int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(client>=0);
    assert(!request(owner,MD_IPC_CONNECT_BEGIN,client,-1,name,0).error);
    assert(md_ipc_credentials_native(other,&client,1)==-EXDEV);
    assert(!connect(client,(void *)&address,size));
    assert(!request(owner,MD_IPC_CONNECT_END,client,-1,NULL,0).error);
    int peer=accept4(fd,NULL,NULL,SOCK_CLOEXEC); assert(peer>=0);
    assert(!request(owner,MD_IPC_ACCEPT,peer,-1,NULL,0).error);
    int raw=socket(AF_UNIX,SOCK_STREAM,0); assert(raw>=0);
    assert(!fcntl(client,F_SETFD,0));
    struct md_ipc_inherited inherited={0};
    assert(!md_ipc_inherited_capture(&inherited) && inherited.count>=2);
    assert(!md_ipc_credentials_inherit(other,&inherited));
    md_ipc_inherited_release(&inherited);
    selected(other,client,MD_IPC_TRANSPORT_ORIGINS_V1);
    assert(!request(owner,MD_IPC_CONNECT_BEGIN,raw,-1,name,0).position);
    assert(!close(raw) && !close(peer) && !close(client) && !close(fd));
    md_ipc_credentials_close(other); md_ipc_credentials_close(owner);
    puts("PASS IPC native boundary: atomic export rejection, aliases, native-only future connect/listen/pair, inheritance and adapted launch preservation");
}
void test_ipc_connections(const char *directory) {
    char foreign_path[PATH_MAX];
    assert(snprintf(foreign_path,sizeof(foreign_path),"%s/foreign",directory)<(int)sizeof(foreign_path)
        && !mkdir(foreign_path,0700));
    struct md_ipc_credentials *first=NULL, *second=NULL, *foreign=NULL;
    assert(!md_ipc_credentials_open(directory,MD_IPC_TRANSPORT_NATIVE,&first)
        && !md_ipc_credentials_open(directory,MD_IPC_TRANSPORT_NATIVE,&second)
        && !md_ipc_credentials_open(foreign_path,MD_IPC_TRANSPORT_NATIVE,&foreign));
    const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
    for (unsigned i=0;i<3;++i) paired(first,second,foreign,types[i]);
    user_namespaces(first);
    pid_namespaces(first);
    independent(directory,first,second,SOCK_STREAM,1,MD_IPC_TRANSPORT_NATIVE,MD_IPC_TRANSPORT_NATIVE);
    independent(directory,first,second,SOCK_SEQPACKET,2,MD_IPC_TRANSPORT_NATIVE,MD_IPC_TRANSPORT_NATIVE);
    admission(first,3,0,0); admission(first,4,1,1);
    accepted_early(first,second);
    native_listener_reuse(first);
    queued_name_reuse(first,0); queued_name_reuse(first,1);
    transports(directory,first);
    exposure(directory);
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets));
    assert(!request(first,MD_IPC_PAIR,sockets[0],sockets[1],NULL,0).error);
    struct md_ipc_connection before=connection(first,sockets[0]);
    int value=token(first,sockets[0]);
    md_ipc_credentials_close(first);
    same(before,connection(second,sockets[0]),0);
    md_ipc_credentials_close(second);
    assert(!md_ipc_credentials_open(directory,MD_IPC_TRANSPORT_NATIVE,&first));
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
