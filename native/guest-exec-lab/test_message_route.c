#define _GNU_SOURCE
#include "fd_messages.h"
#include "fs_mount_internal.h"
#include "launch_peer.h"
#include "fs_wire.h"
#include "event_wait.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

void test_ipc_allocations(int);

static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (entry->d_name[0]!='.') ++n;
    assert(!closedir(dir)); return n;
}
static void ready(int fd) {
    /* EVENT_WAIT: message/control readiness; expiry fails without accepting it. */
    assert(!md_event_wait_fd(fd,POLLIN,md_event_now()+5000000000LL));
}
static struct md_ipc_credentials *authority(const char *path) {
    struct md_ipc_credentials *s=NULL;
    assert(!md_ipc_credentials_open(path,MD_IPC_TRANSPORT_ORIGINS_V1,&s)); return s;
}
static void pair(struct md_ipc_credentials *s, int fd[2]) {
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,fd));
    struct md_identity id=md_identity_new(0,0);
    struct md_fs_request q={.operation=MD_FS_IPC,.flags=MD_IPC_PAIR,.directory={fd[0],fd[1]},.peer=getpid()};
    struct md_fs_result r;
    md_ipc_credentials_execute(s,&id,NULL,&q,&r,NULL); md_identity_release(&id); assert(!r.error);
}
static struct md_ipc_binding binding(struct md_ipc_credentials *s, int fd) {
    struct md_ipc_binding b={0}; assert(!md_ipc_credentials_bind(s,fd,&b)); return b;
}
static struct md_fd_message *capture(unsigned count) {
    struct md_fd_origins *table=md_fd_origins_new(); assert(table);
    struct md_mount_namespace *view=md_mount_namespace_new(); assert(view);
    struct md_fs_anchor *origin=NULL;
    int fd=open("/",O_PATH|O_CLOEXEC); assert(fd>=0);
    struct md_fs_result result={.fd=fd};
    md_view_capture(&(struct md_filesystem){0},view,NULL,&result,&(struct md_fs_output){.origin=&origin});
    assert(!result.error && origin); close(fd);
    struct md_fd_origin_update update;
    assert(!md_fd_origins_prepare(table,origin,0,&update)); md_fd_origins_finish(&update,7);
    md_fs_anchor_release(origin); md_mount_namespace_release(view);
    int numbers[253]; for (unsigned i=0;i<count;++i) numbers[i]=i%2 ? 8 : 7;
    struct md_fd_order turn={0};
    assert(md_fd_order_begin(table,&turn,NULL)==1 && !md_fd_order_start(&turn));
    struct md_fd_message *p=NULL; assert(!md_fd_message_capture(table,numbers,count,&p));
    assert(!md_fd_order_complete(&turn)); md_fd_origins_release(table); return p;
}
static void send_route(int fd, const struct md_fd_message_route *route, int payload, unsigned count) {
    union {struct cmsghdr align; char bytes[CMSG_SPACE(253*sizeof(int))];} control={0};
    struct iovec io={(void *)route,sizeof(*route)};
    struct msghdr message={.msg_iov=&io,.msg_iovlen=1};
    if (count) {
        control.align=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS,.cmsg_len=CMSG_LEN(count*sizeof(int))};
        for (unsigned i=0;i<count;++i) memcpy(CMSG_DATA(&control.align)+i*sizeof(int),&payload,sizeof(payload));
        message.msg_control=&control; message.msg_controllen=CMSG_SPACE(count*sizeof(int));
    }
    assert(sendmsg(fd,&message,MSG_NOSIGNAL|MSG_DONTWAIT)==sizeof(*route));
}
static void carrier(int fd[2], int lifetime[2]) {
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,fd));
    assert(!pipe2(lifetime,O_CLOEXEC|O_NONBLOCK));
}
static void bind_publish(struct md_fd_messages *s, struct md_fd_message *p,
        const struct md_ipc_binding *source, const char *id, int fd, int reader, struct md_fd_message_route *route) {
    assert(!md_fd_message_bind(p,source,id));
    assert(md_fd_message_bind(p,source,id)==-ESTALE);
    struct md_ipc_connection destination=source->connection; destination.side^=1;
    assert(md_fd_messages_publish(s,p,&source->connection,fd,reader)==-EXDEV);
    assert(!md_fd_messages_publish(s,p,&destination,fd,reader));
    assert(!md_fd_message_route(p,route));
}
static void retained(const char *path) {
    unsigned before=descriptors();
    struct md_ipc_credentials *a=authority(path), *b=authority(path);
    int app[2], fd[2], lifetime[2], payload[2]; pair(a,app); carrier(fd,lifetime);
    assert(!pipe2(payload,O_CLOEXEC|O_NONBLOCK));
    struct md_ipc_binding source=binding(a,app[0]), destination=binding(b,app[1]);
    struct md_fd_messages *messages=NULL; assert(!md_fd_messages_new(&messages));
    struct md_fd_message *p=capture(253), *claim=NULL;
    struct md_fd_message_route route, observed;
    assert(md_fd_message_route(p,&route)==-ENODATA);
    test_ipc_allocations(0);
    bind_publish(messages,p,&source,"0123456789abcdef0123456789abcdef",fd[1],lifetime[0],&route);
    test_ipc_allocations(-1);
    md_ipc_binding_release(&source); md_ipc_credentials_close(a); md_ipc_credentials_close(b);
    send_route(fd[0],&route,payload[1],253); close(payload[1]);
    assert(md_fs_send(fd[0],"l",1,&(struct md_fs_rights){.count=1,.fd={lifetime[1]}})==1);
    close(lifetime[1]); close(fd[0]);
    unsigned current=descriptors();
    test_ipc_allocations(0);
    for (unsigned i=0;i<4;++i) {
        assert(!md_fd_message_route_read(fd[1],&destination,&observed));
        assert(!memcmp(&route,&observed,sizeof(route)) && descriptors()==current);
        assert(!md_fd_messages_claim(messages,&destination,fd[1],&observed,&claim) && claim==p);
        md_fd_message_release(claim); claim=NULL;
    }
    struct rlimit old, limited;
    assert(!getrlimit(RLIMIT_NOFILE,&old)); limited=old; limited.rlim_cur=0;
    assert(!setrlimit(RLIMIT_NOFILE,&limited));
    assert(!md_fd_message_route_read(fd[1],&destination,&observed));
    assert(!md_fd_messages_claim(messages,&destination,fd[1],&observed,&claim));
    md_fd_message_release(claim); claim=NULL;
    assert(!setrlimit(RLIMIT_NOFILE,&old));
    test_ipc_allocations(-1);
    observed.nonce[0]^=1;
    assert(md_fd_messages_claim(messages,&destination,fd[1],&observed,&claim)==-ESTALE && !claim);
    observed=route; observed.launch[0]='f';
    assert(md_fd_messages_claim(messages,&destination,fd[1],&observed,&claim)==-ESTALE && !claim);
    struct md_ipc_binding wrong={0}; assert(!md_ipc_binding_copy(&wrong,&destination)); wrong.connection.side^=1;
    assert(md_fd_message_route_read(fd[1],&wrong,&observed)==-EXDEV);
    assert(md_fd_messages_claim(messages,&wrong,fd[1],&route,&claim)==-EXDEV && !claim);
    md_ipc_binding_release(&wrong);
    char foreign[PATH_MAX]; assert(snprintf(foreign,sizeof(foreign),"%s/foreign-route",path)<(int)sizeof(foreign));
    assert(!mkdir(foreign,0700)); a=authority(foreign); int foreign_app[2]; pair(a,foreign_app);
    wrong=binding(a,foreign_app[1]); wrong.connection=destination.connection;
    assert(md_fd_messages_claim(messages,&wrong,fd[1],&route,&claim)==-EXDEV && !claim);
    md_ipc_binding_release(&wrong); close(foreign_app[0]); close(foreign_app[1]); md_ipc_credentials_close(a);
    assert(!md_fd_messages_claim(messages,&destination,fd[1],&route,&claim));
    md_fd_message_release(p); md_ipc_binding_release(&destination);
    close(fd[1]); ready(md_fd_messages_fd(messages)); assert(md_fd_messages_dispatch(messages)==1);
    md_fd_messages_free(messages);
    char byte; assert(!read(payload[0],&byte,1)); close(payload[0]);
    int maintenance=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(maintenance>=0);
    assert(flock(maintenance,LOCK_EX|LOCK_NB)<0 && errno==EWOULDBLOCK);
    a=authority(path); struct md_ipc_connection previous;
    assert(!md_ipc_credentials_connection(a,app[1],&previous)); md_ipc_credentials_close(a);
    assert(md_fd_message_count(claim)==253 && md_fd_message_origins(claim)[0] && !md_fd_message_origins(claim)[1]);
    md_fd_message_release(claim);
    assert(!flock(maintenance,LOCK_EX|LOCK_NB)); close(maintenance);
    a=authority(path); assert(md_ipc_credentials_connection(a,app[1],&previous)==-ENODATA); md_ipc_credentials_close(a);
    close(app[0]); close(app[1]); assert(descriptors()==before);
    puts("PASS routed message: 253 rights, descriptor-free peek, directional/store/nonce checks, last-pin epoch and payload EOF");
}
static void replacement(const char *path) {
    unsigned before=descriptors(); struct md_ipc_credentials *s=authority(path);
    int app[2], fd[2], life[2]; pair(s,app); carrier(fd,life);
    struct md_ipc_binding source=binding(s,app[0]), destination=binding(s,app[1]);
    struct md_fd_messages *messages=NULL; assert(!md_fd_messages_new(&messages));
    struct md_fd_message *p=capture(1), *q=capture(1), *claim=NULL;
    struct md_fd_message_route first, second;
    bind_publish(messages,p,&source,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",fd[1],life[0],&first);
    assert(!md_fd_messages_withdraw(messages,p)); close(life[1]);
    assert(!pipe2(life,O_CLOEXEC|O_NONBLOCK));
    bind_publish(messages,q,&source,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",fd[1],life[0],&second);
    assert(first.cookie==second.cookie && memcmp(first.nonce,second.nonce,sizeof(first.nonce)));
    assert(md_fd_messages_claim(messages,&destination,fd[1],&first,&claim)==-ESTALE && !claim);
    assert(!md_fd_messages_claim(messages,&destination,fd[1],&second,&claim) && claim==q);
    md_fd_message_release(claim); close(life[1]); assert(md_fd_messages_dispatch(messages)==1);
    md_fd_message_release(p); md_fd_message_release(q); md_fd_messages_free(messages);
    close(fd[0]); close(fd[1]); close(app[0]); close(app[1]);
    md_ipc_binding_release(&source); md_ipc_binding_release(&destination); md_ipc_credentials_close(s);
    assert(descriptors()==before);
    puts("PASS same carrier republished: stale route cannot select replacement origin vector");
}
static void malformed(const char *path) {
    unsigned before=descriptors(); struct md_ipc_credentials *s=authority(path);
    int app[2]; pair(s,app); struct md_ipc_binding destination=binding(s,app[1]);
    for (unsigned i=0;i<12;++i) {
        int fd[2], payload[2];
        assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,fd));
        assert(!pipe2(payload,O_CLOEXEC|O_NONBLOCK));
        struct {struct md_fd_message_route route; char extra;} packet={.route={
            .magic=MD_FD_ROUTE_MAGIC,.version=MD_FD_ROUTE_VERSION,.count=1,.side=destination.connection.side}};
        struct md_fd_message_route *route=&packet.route;
        memcpy(route->link,destination.connection.link,sizeof(route->link)); memset(route->launch,'a',sizeof(route->launch));
        socklen_t size=sizeof(route->cookie); assert(!getsockopt(fd[1],SOL_SOCKET,SO_COOKIE,&route->cookie,&size));
        size_t bytes=sizeof(*route); int error=-EPROTO;
        switch (i) {
        case 0: ++route->magic; break;
        case 1: ++route->version; error=-EPROTONOSUPPORT; break;
        case 2: route->count=0; break;
        case 3: route->count=254; break;
        case 4: route->side=2; break;
        case 5: route->side^=1; error=-EXDEV; break;
        case 6: ++route->link[0]; error=-EXDEV; break;
        case 7: ++route->cookie; error=-EXDEV; break;
        case 8: route->launch[0]=0; break;
        case 9: route->launch[31]='g'; break;
        case 10: --bytes; break;
        case 11: ++bytes; break;
        }
        assert(md_fs_send(fd[0],&packet,bytes,&(struct md_fs_rights){.count=1,.fd={payload[1]}})==(long)bytes);
        close(payload[1]);
        struct md_fd_message_route out, unchanged; memset(&unchanged,0x5a,sizeof(unchanged)); out=unchanged;
        unsigned current=descriptors();
        for (unsigned peek=0;peek<3;++peek) {
            assert(md_fd_message_route_read(fd[1],&destination,&out)==error && !memcmp(&out,&unchanged,sizeof(out)));
            assert(descriptors()==current); char byte; assert(read(payload[0],&byte,1)<0 && errno==EAGAIN);
        }
        close(fd[0]); close(fd[1]); char byte; assert(!read(payload[0],&byte,1)); close(payload[0]);
    }
    int fd[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,fd));
    struct md_fd_message_route out;
    assert(md_fd_message_route_read(fd[0],&destination,&out)==-EPROTOTYPE); close(fd[0]); close(fd[1]);
    close(app[0]); close(app[1]); md_ipc_binding_release(&destination); md_ipc_credentials_close(s);
    assert(descriptors()==before);
    puts("PASS routed header rejection: type/version/count/side/link/cookie/launch/length, unchanged outputs and non-consuming descriptor-free errors");
}
static pid_t child_start(const char *mode, const char *path, int fd) {
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        char number[16]; snprintf(number,sizeof(number),"%d",fd);
        assert(!fcntl(fd,F_SETFD,0));
        execl("/proc/self/exe","message-route",mode,path,number,(char *)NULL); _exit(91);
    }
    return child;
}
static void reaped(pid_t child) {
    /* EVENT_WAIT: exact fixture child exit; outer alarm fails a stuck process. */
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
}
int test_message_route_child(int argc, char **argv) {
    if (argc!=4 || (strcmp(argv[1],"--route-creator") && strcmp(argv[1],"--route-receiver"))) return -1;
    /* EVENT_WAIT: independent fixture process failure bound. */
    alarm(20);
    int fd=atoi(argv[3]); assert(!fcntl(fd,F_SETFD,FD_CLOEXEC));
    struct md_ipc_credentials *s=authority(argv[2]);
    if (!strcmp(argv[1],"--route-creator")) {
        int app[2]; pair(s,app);
        assert(md_fs_send(fd,"p",1,&(struct md_fs_rights){.count=2,.fd={app[0],app[1]}})==1);
        close(app[0]); close(app[1]); close(fd); md_ipc_credentials_close(s); return 0;
    }
    struct md_launch_registration local;
    assert(!md_launch_register(&local,argv[2],"/route-receiver","/",0));
    struct md_ipc_binding destination=binding(s,fd);
    ready(fd); char bytes[32]; struct md_fs_rights rights={0};
    assert(md_fs_receive(fd,bytes,sizeof(bytes),&rights)==11 && !memcmp(bytes,"application",11) && rights.count==1);
    int carrier=rights.fd[0]; struct md_fd_message_route route;
    assert(!md_fd_message_route_read(carrier,&destination,&route));
    char id[33]; memcpy(id,route.launch,32); id[32]=0;
    int control=md_launch_peer_connect(&local,id); assert(control>=0);
    assert(md_fs_send(control,&route,sizeof(route),&(struct md_fs_rights){.count=2,.fd={fd,carrier}})==sizeof(route));
    ready(control); struct md_fd_message_route reply;
    assert(md_fs_receive(control,&reply,sizeof(reply),&rights)==sizeof(reply) && !rights.count
        && !memcmp(&reply,&route,sizeof(reply)));
    /* The fixture reply only confirms source-side validation, not transported
     * mount origins. Payload still comes from the kernel carrier itself. */
    assert(md_fs_receive(carrier,&reply,sizeof(reply),&rights)==sizeof(reply) && rights.count==2);
    assert(!memcmp(&reply,&route,sizeof(reply)) && write(rights.fd[0],"z",1)==1);
    md_fs_close_rights(&rights); close(carrier); close(fd); close(control);
    md_ipc_binding_release(&destination); md_ipc_credentials_close(s); md_launch_unregister(&local); return 0;
}
static void independent(const char *path) {
    unsigned before=descriptors(); struct md_ipc_credentials *s=authority(path);
    struct md_launch_registration local;
    assert(!md_launch_register(&local,path,"/message-custodian","/",0));
    int listener=md_launch_peer_listen(&local); assert(listener>=0);
    int channel[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,channel));
    pid_t creator=child_start("--route-creator",path,channel[1]); close(channel[1]);
    ready(channel[0]); char byte; struct md_fs_rights rights={0};
    assert(md_fs_receive(channel[0],&byte,1,&rights)==1 && byte=='p' && rights.count==2);
    int app[2]={rights.fd[0],rights.fd[1]}; close(channel[0]); reaped(creator);
    struct ucred peer; socklen_t size=sizeof(peer);
    assert(!getsockopt(app[0],SOL_SOCKET,SO_PEERCRED,&peer,&size) && peer.pid==creator && peer.pid!=getpid());
    int carrierfd[2], life[2], payload[2]; carrier(carrierfd,life);
    assert(!pipe2(payload,O_CLOEXEC|O_NONBLOCK));
    struct md_ipc_binding source=binding(s,app[0]);
    struct md_fd_messages *messages=NULL; assert(!md_fd_messages_new(&messages));
    struct md_fd_message *p=capture(2); struct md_fd_message_route route;
    bind_publish(messages,p,&source,local.id,carrierfd[1],life[0],&route);
    md_ipc_binding_release(&source); md_ipc_credentials_close(s); s=NULL;
    send_route(carrierfd[0],&route,payload[1],2); close(payload[1]);
    assert(md_fs_send(carrierfd[0],"l",1,&(struct md_fs_rights){.count=1,.fd={life[1]}})==1);
    close(life[1]); close(carrierfd[0]);
    assert(md_fs_send(app[0],"application",11,&(struct md_fs_rights){.count=1,.fd={carrierfd[1]}})==11);
    close(carrierfd[1]); close(app[0]);
    pid_t receiver=child_start("--route-receiver",path,app[1]); close(app[1]);
    ready(listener); int control=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC); assert(control>=0);
    ready(control); char id[33]; assert(!md_launch_peer_receive(control,id));
    assert(!md_launch_peer_verify(&local,control,id));
    ready(control); struct md_fd_message_route requested;
    assert(md_fs_receive(control,&requested,sizeof(requested),&rights)==sizeof(requested) && rights.count==2);
    s=authority(path); struct md_ipc_binding destination=binding(s,rights.fd[0]); md_ipc_credentials_close(s);
    struct md_fd_message *claim=NULL;
    assert(!md_fd_messages_claim(messages,&destination,rights.fd[1],&requested,&claim) && claim==p);
    assert(md_fd_message_count(claim)==2 && md_fd_message_origins(claim)[0] && !md_fd_message_origins(claim)[1]);
    md_fs_close_rights(&rights); md_ipc_binding_release(&destination); md_fd_message_release(claim);
    assert(md_fs_send(control,&requested,sizeof(requested),&(struct md_fs_rights){0})==sizeof(requested));
    close(control); reaped(receiver);
    assert(read(payload[0],&byte,1)==1 && byte=='z' && !read(payload[0],&byte,1)); close(payload[0]);
    ready(md_fd_messages_fd(messages)); assert(md_fd_messages_dispatch(messages)==1);
    md_fd_message_release(p); md_fd_messages_free(messages); close(listener); md_launch_unregister(&local);
    assert(descriptors()==before);
    puts("PASS independent exec routing: dead socket creator, transferred application socket, header-selected live custodian, exact vector and payload EOF");
}
static void native_transport(const char *path) {
    unsigned before=descriptors(); struct md_ipc_credentials *native=NULL;
    assert(!md_ipc_credentials_open(path,MD_IPC_TRANSPORT_NATIVE,&native));
    int app[2], carrier[2], payload[2]; pair(native,app);
    struct md_ipc_credentials *upgraded=authority(path);
    struct md_ipc_binding source=binding(upgraded,app[0]), destination=binding(upgraded,app[1]);
    assert(source.transport==MD_IPC_TRANSPORT_NATIVE && destination.transport==MD_IPC_TRANSPORT_NATIVE);
    md_ipc_credentials_close(native); md_ipc_credentials_close(upgraded);
    struct md_fd_message *message=capture(1), *claim=NULL;
    assert(md_fd_message_bind(message,&source,"0123456789abcdef0123456789abcdef")==-ENOTSUP);
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,carrier)
        && !pipe2(payload,O_NONBLOCK|O_CLOEXEC));
    struct md_fd_message_route route={.magic=MD_FD_ROUTE_MAGIC,.version=MD_FD_ROUTE_VERSION,
        .side=destination.connection.side,.count=1}, out, unchanged;
    socklen_t size=sizeof(route.cookie); assert(!getsockopt(carrier[1],SOL_SOCKET,SO_COOKIE,&route.cookie,&size));
    memcpy(route.link,destination.connection.link,sizeof(route.link)); memset(route.launch,'a',sizeof(route.launch));
    send_route(carrier[0],&route,payload[1],1); close(payload[1]);
    memset(&unchanged,0xab,sizeof(unchanged)); out=unchanged;
    assert(md_fd_message_route_read(carrier[1],&destination,&out)==-ENOTSUP
        && !memcmp(&out,&unchanged,sizeof(out)));
    assert(md_fd_message_route_read(-1,&destination,&out)==-ENOTSUP);
    struct md_fd_messages *messages=NULL; assert(!md_fd_messages_new(&messages));
    assert(md_fd_messages_claim(messages,&destination,carrier[1],&route,&claim)==-ENOTSUP && !claim);
    int actual=-1; unsigned count=0;
    assert(md_fs_receive_fds(carrier[1],&out,sizeof(out),&actual,1,&count)==sizeof(out)
        && count==1 && !memcmp(&out,&route,sizeof(out)) && actual>=0);
    close(actual); char byte; assert(!read(payload[0],&byte,1));
    close(payload[0]); close(carrier[0]); close(carrier[1]); close(app[0]); close(app[1]);
    md_fd_messages_free(messages); md_fd_message_release(message);
    md_ipc_binding_release(&source); md_ipc_binding_release(&destination);
    assert(descriptors()==before);
    puts("PASS native transport: no upgrade, carrier sniffing, publication or claim; application packet and FD intact");
}
void test_message_routes(const char *path) {
    retained(path); replacement(path); malformed(path); independent(path); native_transport(path);
}
