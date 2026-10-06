#define _GNU_SOURCE
#include "test_ancillary_contract.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

enum { RIGHTS_MAX=253 };
union control { struct cmsghdr align; char bytes[CMSG_SPACE(RIGHTS_MAX*sizeof(int))]; };
static void send_rights(int socket, int fd, unsigned count) {
    union control control={0};
    char byte='x'; struct iovec vector={&byte,1};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,.msg_control=control.bytes,
        .msg_controllen=CMSG_SPACE(count*sizeof(int))};
    struct cmsghdr *c=CMSG_FIRSTHDR(&message);
    *c=(struct cmsghdr){.cmsg_len=CMSG_LEN(count*sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
    int *fds=(void *)CMSG_DATA(c);
    for (unsigned i=0;i<count;++i) fds[i]=fd;
    assert(sendmsg(socket,&message,MSG_NOSIGNAL)==1);
}
static unsigned descriptors(struct msghdr *message, int *out) {
    unsigned count=0;
    for (struct cmsghdr *c=CMSG_FIRSTHDR(message);c;c=CMSG_NXTHDR(message,c)) {
        assert(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS && c->cmsg_len>=CMSG_LEN(0));
        unsigned n=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
        assert(count+n<=RIGHTS_MAX);
        memcpy(out+count,CMSG_DATA(c),n*sizeof(int)); count+=n;
    }
    return count;
}
static void close_descriptors(struct msghdr *message, int cloexec) {
    int fds[RIGHTS_MAX]; unsigned count=descriptors(message,fds);
    for (unsigned i=0;i<count;++i) {
        assert(fcntl(fds[i],F_GETFD)==(cloexec ? FD_CLOEXEC : 0));
        assert(!close(fds[i]));
    }
}
static void rights_peek(void) {
    const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
    for (unsigned type=0;type<3;++type) {
        int sockets[2]; assert(!socketpair(AF_UNIX,types[type]|SOCK_CLOEXEC,0,sockets));
        int fd=open("peek",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,0600); assert(fd>=0);
        assert(write(fd,"abc",3)==3 && !lseek(fd,0,SEEK_SET));
        send_rights(sockets[0],fd,2);
        for (unsigned turn=0;turn<3;++turn) {
            union control control={0}; char byte=0;
            struct iovec vector={&byte,1};
            struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
                .msg_control=control.bytes,.msg_controllen=sizeof(control)};
            assert(recvmsg(sockets[1],&message,MSG_CMSG_CLOEXEC|(turn<2 ? MSG_PEEK : 0))==1 && byte=='x');
            int fds[RIGHTS_MAX]; assert(descriptors(&message,fds)==2);
            assert(read(fds[0],&byte,1)==1 && byte==(char)('a'+turn));
            assert(lseek(fds[1],0,SEEK_CUR)==(off_t)turn+1 && lseek(fd,0,SEEK_CUR)==(off_t)turn+1);
            close_descriptors(&message,1);
        }
        assert(!close(fd) && !close(sockets[0]) && !close(sockets[1]));
        printf("OBS rights-peek type=%d offsets=shared delivered=2 copies=3\n",types[type]);
    }
}
static void rights_truncate(void) {
    const size_t capacities[]={0,1,CMSG_LEN(0)-1,CMSG_LEN(0),CMSG_LEN(sizeof(int)),CMSG_SPACE(sizeof(int))};
    for (unsigned slot=0;slot<sizeof(capacities)/sizeof(*capacities);++slot) {
        int sockets[2], pipefd[2];
        assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        send_rights(sockets[0],pipefd[1],3); assert(!close(pipefd[1]));
        char byte; assert(read(pipefd[0],&byte,1)==-1 && errno==EAGAIN);
        union control control={0}; struct iovec vector={&byte,1};
        struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
            .msg_control=control.bytes,.msg_controllen=capacities[slot]};
        assert(recvmsg(sockets[1],&message,0)==1);
        int fds[RIGHTS_MAX]; unsigned count=descriptors(&message,fds);
        printf("OBS rights-truncate capacity=%zu count=%u length=%zu truncated=%d\n",
            capacities[slot],count,message.msg_controllen,!!(message.msg_flags&MSG_CTRUNC));
        close_descriptors(&message,0);
        assert(read(pipefd[0],&byte,1)==0);
        assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
    }
}
static void rights_limit(void) {
    int sockets[2], pipefd[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
    send_rights(sockets[0],pipefd[1],RIGHTS_MAX); assert(!close(pipefd[1]));
    union control control={0}; char byte; struct iovec vector={&byte,1};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=sizeof(control)};
    assert(recvmsg(sockets[1],&message,MSG_CMSG_CLOEXEC)==1);
    int fds[RIGHTS_MAX]; assert(descriptors(&message,fds)==RIGHTS_MAX && !(message.msg_flags&MSG_CTRUNC));
    close_descriptors(&message,1); assert(read(pipefd[0],&byte,1)==0);
    assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
    puts("OBS rights-limit delivered=253 cloexec=1 eof=1");
}
static void rights_batch(void) {
    int sockets[2], pipefd[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
    for (unsigned i=0;i<3;++i) send_rights(sockets[0],pipefd[1],2);
    assert(!close(pipefd[1]));
    union control control[4]={0}; char bytes[4]={0};
    struct iovec vectors[4]; struct mmsghdr messages[4]={0};
    for (unsigned i=0;i<4;++i) {
        vectors[i]=(struct iovec){bytes+i,1};
        messages[i].msg_hdr=(struct msghdr){.msg_iov=vectors+i,.msg_iovlen=1,
            .msg_control=control[i].bytes,.msg_controllen=i ? CMSG_LEN(i*sizeof(int)) : 0};
    }
    int n=recvmmsg(sockets[1],messages,4,MSG_CMSG_CLOEXEC|MSG_WAITFORONE,NULL); assert(n==3);
    for (int i=0;i<n;++i) {
        assert(messages[i].msg_len==1 && bytes[i]=='x');
        int fds[RIGHTS_MAX]; unsigned count=descriptors(&messages[i].msg_hdr,fds);
        printf("OBS rights-batch slot=%d count=%u length=%zu truncated=%d\n",i,count,
            messages[i].msg_hdr.msg_controllen,!!(messages[i].msg_hdr.msg_flags&MSG_CTRUNC));
        close_descriptors(&messages[i].msg_hdr,1);
    }
    char byte; assert(read(pipefd[0],&byte,1)==0);
    assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
}
static void rights_fault(void) {
    int sockets[2], pipefd[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
    send_rights(sockets[0],pipefd[1],2); assert(!close(pipefd[1]));
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    struct msghdr *message=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(message!=MAP_FAILED);
    union control control={0}; char byte=0; struct iovec vector={&byte,1};
    *message=(struct msghdr){.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=sizeof(control)};
    assert(!mprotect(message,page,PROT_READ));
    errno=0; ssize_t result=recvmsg(sockets[1],message,MSG_CMSG_CLOEXEC);
    int error=errno, fds[RIGHTS_MAX];
    struct msghdr published=*message;
    published.msg_controllen=control.align.cmsg_len ? CMSG_ALIGN(control.align.cmsg_len) : 0;
    unsigned count=descriptors(&published,fds), live=0;
    for (unsigned i=0;i<count;++i) if (fcntl(fds[i],F_GETFD)>=0) { ++live; assert(!close(fds[i])); }
    printf("OBS rights-fault result=%zd errno=%d payload=%d published=%u live=%u\n",
        result,error,byte=='x',count,live);
    assert(read(pipefd[0],&byte,1)==0 && !munmap(message,page));
    assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
}
static void rights_control_fault(void) {
    const size_t writable[]={0,CMSG_LEN(0),CMSG_LEN(sizeof(int)),CMSG_LEN(2*sizeof(int)),CMSG_LEN(0)};
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    for (unsigned slot=0;slot<sizeof(writable)/sizeof(*writable);++slot) {
        int sockets[2], pipefd[2];
        assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        send_rights(sockets[0],pipefd[1],3); assert(!close(pipefd[1]));
        char *mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(mapping!=MAP_FAILED);
        struct cmsghdr *control=(void *)(mapping+page-writable[slot]);
        memset(control,0,CMSG_SPACE(3*sizeof(int)));
        int *fds=(void *)CMSG_DATA(control);
        for (unsigned i=0;i<3;++i) fds[i]=-1;
        int readonly_header=slot==4;
        assert(!mprotect(mapping+(readonly_header?0:page),page,PROT_READ));
        char byte=0; struct iovec vector={&byte,1};
        struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,.msg_control=control,
            .msg_controllen=CMSG_SPACE(3*sizeof(int))};
        errno=0; ssize_t result=recvmsg(sockets[1],&message,MSG_CMSG_CLOEXEC); int error=errno;
        unsigned live=0;
        for (unsigned i=0;i<3;++i) if (fds[i]>=0 && fcntl(fds[i],F_GETFD)>=0) {
            ++live; assert(!close(fds[i]));
        }
        printf("OBS rights-control-fault writable=%zu readonly_header=%d result=%zd errno=%d payload=%d length=%zu live=%u truncated=%d\n",
            writable[slot],readonly_header,result,error,byte=='x',message.msg_controllen,live,!!(message.msg_flags&MSG_CTRUNC));
        assert(read(pipefd[0],&byte,1)==0 && !munmap(mapping,2*page));
        assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
    }
}
static void rights_header_outputs(void) {
    int sockets[2], pipefd[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
    send_rights(sockets[0],pipefd[1],2); assert(!close(pipefd[1]));
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(mapping!=MAP_FAILED);
    struct msghdr *message=(void *)(mapping+page-offsetof(struct msghdr,msg_controllen));
    union control control={0}; char byte=0; struct iovec vector={&byte,1};
    *message=(struct msghdr){.msg_iov=&vector,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    assert(!mprotect(mapping,page,PROT_READ));
    errno=0; ssize_t result=recvmsg(sockets[1],message,MSG_CMSG_CLOEXEC); int error=errno;
    struct msghdr published=*message;
    published.msg_controllen=control.align.cmsg_len ? CMSG_ALIGN(control.align.cmsg_len) : 0;
    int fds[RIGHTS_MAX]; unsigned count=descriptors(&published,fds),live=0;
    for (unsigned i=0;i<count;++i) if (fcntl(fds[i],F_GETFD)>=0) { ++live; assert(!close(fds[i])); }
    printf("OBS rights-header-outputs result=%zd errno=%d payload=%d published=%u live=%u\n",result,error,byte=='x',count,live);
    assert(read(pipefd[0],&byte,1)==0 && !munmap(mapping,2*page));
    assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
}
static void rights_name(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    for (unsigned batch=0;batch<2;++batch) for (unsigned fault=0;fault<2;++fault) {
        int sockets[2],pipefd[2];
        assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        struct sockaddr_un source={.sun_family=AF_UNIX};
        snprintf(source.sun_path+1,sizeof(source.sun_path)-1,"md-contract-%d-%u-%u",getpid(),batch,fault);
        size_t name_size=strlen(source.sun_path+1)+1;
        assert(!bind(sockets[0],(void *)&source,offsetof(struct sockaddr_un,sun_path)+name_size));
        send_rights(sockets[0],pipefd[1],2); assert(!close(pipefd[1]));
        struct sockaddr_un *address=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(address!=MAP_FAILED);
        if (fault) assert(!mprotect(address,page,PROT_READ));
        union control control={0}; char byte=0; struct iovec vector={&byte,1};
        struct mmsghdr message={.msg_hdr={.msg_name=address,.msg_namelen=sizeof(*address),
            .msg_iov=&vector,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)}};
        errno=0; long result=batch ? recvmmsg(sockets[1],&message,1,MSG_CMSG_CLOEXEC,NULL)
            : recvmsg(sockets[1],&message.msg_hdr,MSG_CMSG_CLOEXEC);
        int error=errno, fds[RIGHTS_MAX];
        struct msghdr published=message.msg_hdr;
        published.msg_controllen=control.align.cmsg_len ? CMSG_ALIGN(control.align.cmsg_len) : 0;
        unsigned count=descriptors(&published,fds),live=0;
        for (unsigned i=0;i<count;++i) if (fcntl(fds[i],F_GETFD)>=0) { ++live; assert(!close(fds[i])); }
        printf("OBS rights-name batch=%u fault=%u result=%ld errno=%d payload=%d name=%d published=%u live=%u\n",
            batch,fault,result,error,byte=='x',!memcmp(address->sun_path,source.sun_path,name_size),count,live);
        assert(read(pipefd[0],&byte,1)==0 && !munmap(address,page));
        assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
    }
}
static void rights_timeout_fault(void) {
    int sockets[2],pipefd[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets) && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
    for (unsigned i=0;i<3;++i) send_rights(sockets[0],pipefd[1],2);
    assert(!close(pipefd[1]));
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    struct timespec *timeout=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(timeout!=MAP_FAILED);
    *timeout=(struct timespec){.tv_sec=10}; assert(!mprotect(timeout,page,PROT_READ));
    union control control[3]={0}; char bytes[3]={0}; struct iovec vectors[3]; struct mmsghdr messages[3]={0};
    for (unsigned i=0;i<3;++i) {
        vectors[i]=(struct iovec){bytes+i,1};
        messages[i].msg_hdr=(struct msghdr){.msg_iov=vectors+i,.msg_iovlen=1,
            .msg_control=control[i].bytes,.msg_controllen=sizeof(control[i])};
    }
    errno=0; int result=recvmmsg(sockets[1],messages,3,MSG_CMSG_CLOEXEC,timeout), error=errno;
    unsigned published=0,live=0;
    for (unsigned i=0;i<3;++i) {
        struct msghdr item=messages[i].msg_hdr;
        item.msg_controllen=control[i].align.cmsg_len ? CMSG_ALIGN(control[i].align.cmsg_len) : 0;
        int fds[RIGHTS_MAX]; unsigned n=descriptors(&item,fds); published+=n;
        for (unsigned j=0;j<n;++j) if (fcntl(fds[j],F_GETFD)>=0) { ++live; assert(!close(fds[j])); }
    }
    printf("OBS rights-timeout-fault result=%d errno=%d payloads=%d published=%u live=%u\n",
        result,error,(bytes[0]=='x')+(bytes[1]=='x')+(bytes[2]=='x'),published,live);
    assert(read(pipefd[0],bytes,1)==0 && !munmap(timeout,page));
    assert(!close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
}
static void rights_batch_fault(void) {
    int sockets[2], pipefd[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,sockets)
        && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
    for (unsigned i=0;i<3;++i) send_rights(sockets[0],pipefd[1],2);
    assert(!close(pipefd[1]));
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(mapping!=MAP_FAILED);
    struct mmsghdr *messages=(void *)(mapping+page-sizeof(*messages));
    union control control[3]={0}; char bytes[3]={0}; struct iovec vectors[3];
    for (unsigned i=0;i<3;++i) {
        vectors[i]=(struct iovec){bytes+i,1};
        messages[i]=(struct mmsghdr){.msg_hdr={.msg_iov=vectors+i,.msg_iovlen=1,
            .msg_control=control[i].bytes,.msg_controllen=sizeof(control[i])}};
    }
    assert(!mprotect(mapping+page,page,PROT_READ));
    errno=0; int result=recvmmsg(sockets[1],messages,3,MSG_CMSG_CLOEXEC,NULL), error=errno;
    unsigned live=0, published=0;
    for (unsigned i=0;i<3;++i) {
        struct msghdr item=messages[i].msg_hdr;
        item.msg_controllen=control[i].align.cmsg_len ? CMSG_ALIGN(control[i].align.cmsg_len) : 0;
        int fds[RIGHTS_MAX]; unsigned n=descriptors(&item,fds); published+=n;
        for (unsigned j=0;j<n;++j) if (fcntl(fds[j],F_GETFD)>=0) { ++live; assert(!close(fds[j])); }
    }
    char byte; unsigned queued=0, pending=0;
    for (;;) {
        ssize_t n=recv(sockets[1],&byte,1,MSG_DONTWAIT);
        if (n==1) { ++queued; continue; }
        if (n<0 && errno==EFAULT && !pending) { pending=errno; continue; }
        assert(n==-1 && errno==EAGAIN); break;
    }
    assert(read(pipefd[0],&byte,1)==0);
    printf("OBS rights-batch-fault result=%d errno=%d payloads=%d published=%u live=%u queued=%u pending=%u\n",
        result,error,(bytes[0]=='x')+(bytes[1]=='x')+(bytes[2]=='x'),published,live,queued,pending);
    assert(!munmap(mapping,2*page) && !close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
}
static int socket_error(int socket) {
    int error=-1; socklen_t size=sizeof(error);
    assert(!getsockopt(socket,SOL_SOCKET,SO_ERROR,&error,&size) && size==sizeof(error));
    return error;
}
static void rights_socket_error(void) {
    /* A kernel payload fault preserves socket error state independently of adapter publication. */
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    void *unwritable=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(unwritable!=MAP_FAILED);
    for (unsigned consumer=0;consumer<4;++consumer) {
        int sockets[2],pipefd[2];
        assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,sockets)
            && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        int alias=dup(sockets[1]); assert(alias>=0);
        for (unsigned i=0;i<3;++i) send_rights(sockets[0],pipefd[1],2);
        assert(!close(pipefd[1]));
        union control control[3]={0}; char bytes[3]={0};
        struct iovec vectors[3]; struct mmsghdr messages[3]={0};
        for (unsigned i=0;i<3;++i) {
            vectors[i]=(struct iovec){i==1 ? unwritable : (void *)(bytes+i),1};
            messages[i].msg_hdr=(struct msghdr){.msg_iov=vectors+i,.msg_iovlen=1,
                .msg_control=control[i].bytes,.msg_controllen=sizeof(control[i])};
        }
        assert(recvmmsg(sockets[1],messages,3,MSG_CMSG_CLOEXEC,NULL)==1);
        close_descriptors(&messages[0].msg_hdr,1);
        struct pollfd pollfd={.fd=alias,.events=0};
        assert(poll(&pollfd,1,0)>=0);
        int epoll=epoll_create1(EPOLL_CLOEXEC); assert(epoll>=0);
        struct epoll_event event={.events=0,.data.u64=1}, ready={0};
        assert(!epoll_ctl(epoll,EPOLL_CTL_ADD,alias,&event));
        int n=epoll_wait(epoll,&ready,1,0); assert(n>=0);
        int reported=0;
        if (consumer==0) reported=socket_error(alias);
        else if (consumer==1) { errno=0; assert(read(alias,bytes,1)==-1); reported=errno; }
        else if (consumer==2) { errno=0; assert(recv(alias,bytes,1,MSG_DONTWAIT)==-1); reported=errno; }
        else {
            pid_t child=fork(); assert(child>=0);
            if (!child) _exit(socket_error(alias));
            int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status));
            reported=WEXITSTATUS(status);
        }
        int remaining=socket_error(sockets[1]);
        unsigned queued=0;
        while (recv(alias,bytes,1,MSG_DONTWAIT)==1) ++queued;
        assert(errno==EAGAIN && read(pipefd[0],bytes,1)==0);
        printf("OBS rights-socket-error consumer=%u pollerr=%d epollerr=%d error=%d remaining=%d queued=%u\n",
            consumer,!!(pollfd.revents&POLLERR),n==1 && !!(ready.events&EPOLLERR),reported,remaining,queued);
        assert(!close(epoll) && !close(alias) && !close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
    }
    assert(!munmap(unwritable,page));
}
static void watch_receive_fault(unsigned mode) {
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets));
    char name[32]; snprintf(name,sizeof(name),"received-watch-%u",mode);
    pid_t sender=fork(); assert(sender>=0);
    if (!sender) {
        assert(!close(sockets[1]));
        int watch=inotify_init1(IN_NONBLOCK|IN_CLOEXEC); assert(watch>=0);
        assert(inotify_add_watch(watch,".",IN_CREATE)>=0);
        int file=open(name,O_CREAT|O_EXCL|O_WRONLY,0600); assert(file>=0 && !close(file));
        if (mode==2) {
            struct sockaddr_un address={.sun_family=AF_UNIX};
            snprintf(address.sun_path+1,sizeof(address.sun_path)-1,"md-watch-%ld",(long)getpid());
            assert(!bind(sockets[0],(void *)&address,offsetof(struct sockaddr_un,sun_path)
                +1+strlen(address.sun_path+1)));
        }
        send_rights(sockets[0],watch,1);
        assert(!close(watch) && !close(sockets[0])); _exit(0);
    }
    assert(!close(sockets[0]));
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *memory=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED);
    union control control={0}; void *output=mode==1 ? memory+page-CMSG_LEN(0) : control.bytes;
    int missing=-1; memcpy((char *)output+CMSG_LEN(0),&missing,sizeof(missing));
    char byte=0; struct iovec vector={&byte,1};
    struct mmsghdr message={.msg_hdr={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=output,.msg_controllen=CMSG_SPACE(sizeof(int))}};
    struct mmsghdr *target=&message;
    struct timespec *timeout=NULL;
    if (mode==0 || mode==4) { target=(void *)memory; *target=message; }
    if (mode==2) { message.msg_hdr.msg_name=memory; message.msg_hdr.msg_namelen=sizeof(struct sockaddr_un); }
    if (mode==3) { timeout=(void *)memory; *timeout=(struct timespec){.tv_sec=1}; }
    assert(!mprotect(memory,page,PROT_READ));
    errno=0;
    long result=mode==3 || mode==4
        ? recvmmsg(sockets[1],target,1,MSG_CMSG_CLOEXEC,timeout)
        : recvmsg(sockets[1],&target->msg_hdr,MSG_CMSG_CLOEXEC);
    int error=result<0 ? errno : 0;
    assert(result==(mode==1 || mode==5 ? 1 : -1) && (result>=0 || error==EFAULT) && byte=='x');
    int received; memcpy(&received,(char *)output+CMSG_LEN(0),sizeof(received));
    assert(received>=0 && fcntl(received,F_GETFD)==FD_CLOEXEC);
    struct pollfd wait={.fd=received,.events=POLLIN};
    /* EVENT_WAIT: queued inotify event; expiry fails the fixture. */
    assert(poll(&wait,1,5000)==1 && (wait.revents&POLLIN));
    union { struct inotify_event align; char bytes[128]; } event={0};
    ssize_t n=read(received,event.bytes,sizeof(event.bytes));
    assert(n>=(ssize_t)sizeof(struct inotify_event) && n==(ssize_t)(sizeof(event.align)+event.align.len));
    assert(event.align.mask==IN_CREATE && event.align.len && !strcmp(event.align.name,name));
    assert(read(received,event.bytes,sizeof(event.bytes))==-1 && errno==EAGAIN);
    int status; assert(waitpid(sender,&status,0)==sender && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!close(received) && !close(sockets[1]) && !munmap(memory,2*page) && !unlink(name));
    printf("OBS rights-watch-fault mode=%u result=%ld errno=%d event=IN_CREATE cloexec=1\n",mode,result,error);
}
static void rights_watch_fault(void) {
    /* Each receiver starts without an inotify filter. The sender creates the
     * watch only after fork, so inherited filters cannot hide missing activation. */
    for (unsigned mode=0;mode<6;++mode) {
        pid_t receiver=fork(); assert(receiver>=0);
        if (!receiver) { watch_receive_fault(mode); _exit(0); }
        int status; assert(waitpid(receiver,&status,0)==receiver && WIFEXITED(status) && !WEXITSTATUS(status));
    }
}
int md_test_ancillary_contract(const char *name) {
    if (!strcmp(name,"rights-peek")) rights_peek();
    else if (!strcmp(name,"rights-truncate")) rights_truncate();
    else if (!strcmp(name,"rights-limit")) rights_limit();
    else if (!strcmp(name,"rights-batch")) rights_batch();
    else if (!strcmp(name,"rights-fault")) rights_fault();
    else if (!strcmp(name,"rights-control-fault")) rights_control_fault();
    else if (!strcmp(name,"rights-header-outputs")) rights_header_outputs();
    else if (!strcmp(name,"rights-name")) rights_name();
    else if (!strcmp(name,"rights-timeout-fault")) rights_timeout_fault();
    else if (!strcmp(name,"rights-batch-fault")) rights_batch_fault();
    else if (!strcmp(name,"rights-socket-error")) rights_socket_error();
    else if (!strcmp(name,"rights-watch-fault")) rights_watch_fault();
    else return 0;
    return 1;
}
