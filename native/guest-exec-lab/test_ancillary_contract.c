#define _GNU_SOURCE
#include "test_ancillary_contract.h"
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/resource.h>
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
static void receive_large_batch(void) {
    const unsigned counts[]={1,4,127,128,129,1024};
    for (unsigned test=0;test<sizeof(counts)/sizeof(*counts);++test) for (unsigned nonblocking=0;nonblocking<2;++nonblocking)
            for (unsigned large_control=0;large_control<2;++large_control) {
        unsigned count=counts[test];
        int sockets[2],pipefd[2];
        assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|(nonblocking?SOCK_NONBLOCK:0),0,sockets));
        assert(!pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        struct mmsghdr *messages=calloc(count,sizeof(*messages));
        struct iovec *vectors=calloc(count,sizeof(*vectors));
        char *bytes=calloc(count,1); union control *control=calloc(count,sizeof(*control));
        assert(messages && vectors && bytes && control);
        for (unsigned i=0;i<count;++i) {
            vectors[i]=(struct iovec){bytes+i,1};
            messages[i].msg_hdr=(struct msghdr){.msg_iov=vectors+i,.msg_iovlen=1,
                .msg_control=control[i].bytes,.msg_controllen=large_control ? sizeof(*control) : CMSG_SPACE(sizeof(int))};
            messages[i].msg_len=123;
        }
        for (unsigned attempt=0;attempt<(count<=128 ? 32u : 1u);++attempt)
            assert(recvmmsg(sockets[1],messages,count,MSG_DONTWAIT,NULL)==-1 && errno==EAGAIN);
        for (unsigned i=0;i<count;++i) assert(messages[i].msg_len==123 && !bytes[i]);
        send_rights(sockets[0],pipefd[1],1); close(pipefd[1]);
        struct timespec timeout={.tv_sec=1};
        assert(recvmmsg(sockets[1],messages,count,MSG_WAITFORONE|MSG_CMSG_CLOEXEC,&timeout)==1);
        assert(messages[0].msg_len==1 && bytes[0]=='x');
        close_descriptors(&messages[0].msg_hdr,1);
        for (unsigned i=1;i<count;++i) assert(messages[i].msg_len==123 && !bytes[i]);
        char byte; assert(read(pipefd[0],&byte,1)==0);
        close(pipefd[0]); close(sockets[0]); close(sockets[1]);
        free(messages); free(vectors); free(bytes); free(control);
        printf("OBS receive-large-batch count=%u nonblocking=%u large-control=%u empty=EAGAIN received=1 rights=1 untouched=1\n",
            count,nonblocking,large_control);
    }
}
static void receive_batch_snapshot(void) {
    enum { COUNT=64 };
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    for (unsigned fault=0;fault<4;++fault) {
        int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets));
        char *guard=mmap(NULL,3*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(guard!=MAP_FAILED && !mprotect(guard+2*page,page,PROT_NONE));
        struct mmsghdr local[COUNT]={0},*messages=local;
        struct iovec vectors[COUNT][9]={0}; char bytes[COUNT]={0};
        unsigned count=COUNT, good=fault ? 32 : COUNT;
        if (fault==2) messages=(void *)(guard+2*page-good*sizeof(*messages));
        if (fault==3) {
            messages=(void *)(guard+2*page-sizeof(struct msghdr)); count=1; good=0;
            messages->msg_hdr=(struct msghdr){0};
        }
        for (unsigned i=0;i<(fault==2 ? good : count);++i) {
            unsigned n=i%3==0 ? 1 : i%3==1 ? 8 : 9;
            vectors[i][n-1]=(struct iovec){bytes+i,1};
            messages[i].msg_hdr=(struct msghdr){.msg_iov=vectors[i],.msg_iovlen=n};
            if (fault!=3) messages[i].msg_len=123;
        }
        if (fault==1) messages[good].msg_hdr.msg_iov=(void *)(guard+2*page);
        for (unsigned i=0;i<good;++i) assert(send(sockets[0],"x",1,0)==1);
        errno=0;
        int result=recvmmsg(sockets[1],messages,count,MSG_DONTWAIT,NULL);
        int error=result<0 ? errno : 0;
        assert(result==(good ? (int)good : -1) && (good || error==EAGAIN));
        for (unsigned i=0;i<good;++i) assert(bytes[i]=='x' && messages[i].msg_len==1);
        for (unsigned i=good;i<COUNT;++i) assert(!bytes[i]);
        if (fault==1) assert(messages[good].msg_len==123);
        assert(!munmap(guard,3*page) && !close(sockets[0]) && !close(sockets[1]));
        printf("OBS receive-batch-snapshot fault=%u result=%d errno=%d prefix=exact\n",fault,result,error);
    }
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
static void rights_socket_error(unsigned fault) {
    /* Observe socket-owned error state through independent aliases/consumers.
     * Faults: payload, header outputs, source address, per-entry msg_len. */
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    void *unwritable=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(unwritable!=MAP_FAILED);
    for (unsigned consumer=0;consumer<4;++consumer) {
        int sockets[2],pipefd[2];
        assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,sockets)
            && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        int alias=dup(sockets[1]); assert(alias>=0);
        if (fault==2) {
            struct sockaddr_un address={.sun_family=AF_UNIX};
            snprintf(address.sun_path+1,sizeof(address.sun_path)-1,"md-batch-error-%ld-%u",(long)getpid(),consumer);
            assert(!bind(sockets[0],(void *)&address,offsetof(struct sockaddr_un,sun_path)
                +1+strlen(address.sun_path+1)));
        }
        for (unsigned i=0;i<3;++i) send_rights(sockets[0],pipefd[1],2);
        assert(!close(pipefd[1]));
        union control control[3]={0}; char bytes[3]={0};
        struct iovec vectors[3]; struct mmsghdr local[3]={0};
        char *mapping=NULL; struct mmsghdr *messages=local;
        if (fault==1 || fault==3) {
            mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            assert(mapping!=MAP_FAILED);
            messages=(void *)(mapping+page-sizeof(*messages)-(fault==3 ? offsetof(struct mmsghdr,msg_len) : 0));
        }
        for (unsigned i=0;i<3;++i) {
            vectors[i]=(struct iovec){!fault && i==1 ? unwritable : (void *)(bytes+i),1};
            messages[i].msg_hdr=(struct msghdr){.msg_iov=vectors+i,.msg_iovlen=1,
                .msg_control=control[i].bytes,.msg_controllen=sizeof(control[i])};
        }
        if (fault==2) { messages[1].msg_hdr.msg_name=unwritable; messages[1].msg_hdr.msg_namelen=sizeof(struct sockaddr_un); }
        if (mapping) assert(!mprotect(mapping+page,page,PROT_READ));
        assert(recvmmsg(sockets[1],messages,3,MSG_CMSG_CLOEXEC,NULL)==1);
        int payloads=(bytes[0]=='x')+(bytes[1]=='x')+(bytes[2]=='x');
        for (unsigned i=0;i<3;++i) if (control[i].align.cmsg_len) {
            struct msghdr published=messages[i].msg_hdr;
            published.msg_controllen=CMSG_ALIGN(control[i].align.cmsg_len);
            close_descriptors(&published,1);
        }
        struct pollfd pollfd={.fd=alias,.events=0};
        assert(poll(&pollfd,1,0)>=0);
        int epoll=epoll_create1(EPOLL_CLOEXEC); assert(epoll>=0);
        struct epoll_event event={.events=0,.data.u64=1}, ready={0};
        assert(!epoll_ctl(epoll,EPOLL_CTL_ADD,alias,&event));
        int n=epoll_wait(epoll,&ready,1,0); assert(n>=0);
        int reported=0;
        if (consumer==0) reported=socket_error(alias);
        else if (consumer==1) { errno=0; ssize_t r=read(alias,bytes,1); assert(r==-1 || r==1); reported=r<0 ? errno : 0; }
        else if (consumer==2) { errno=0; ssize_t r=recv(alias,bytes,1,MSG_DONTWAIT); assert(r==-1 || r==1); reported=r<0 ? errno : 0; }
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
        printf("OBS rights-socket-error fault=%u consumer=%u payloads=%d pollerr=%d epollerr=%d error=%d remaining=%d queued=%u\n",
            fault,consumer,payloads,
            !!(pollfd.revents&POLLERR),n==1 && !!(ready.events&EPOLLERR),reported,remaining,queued);
        assert(!close(epoll) && !close(alias) && !close(pipefd[0]) && !close(sockets[0]) && !close(sockets[1]));
        if (mapping) assert(!munmap(mapping,2*page));
    }
    assert(!munmap(unwritable,page));
}
static void rights_error_consumers(unsigned publication) {
    const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    void *unwritable=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(unwritable!=MAP_FAILED);
    for (unsigned type=0;type<3;++type) for (unsigned consumer=0;consumer<8;++consumer) {
        int sockets[2],pipefd[2];
        assert(!socketpair(AF_UNIX,types[type]|SOCK_CLOEXEC|SOCK_NONBLOCK,0,sockets)
            && !pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        int epoll=epoll_create1(EPOLL_CLOEXEC); assert(epoll>=0);
        struct epoll_event event={.events=0,.data.u64=1}, ready={0};
        assert(!epoll_ctl(epoll,EPOLL_CTL_ADD,sockets[1],&event));
        for (unsigned i=0;i<3;++i) send_rights(sockets[0],pipefd[1],1);
        assert(!close(pipefd[1]));
        char *mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(mapping!=MAP_FAILED);
        struct mmsghdr *messages=(void *)(mapping+page-sizeof(*messages));
        union control control[3]={0}; char bytes[3]={0}; struct iovec vectors[3];
        for (unsigned i=0;i<3;++i) {
            vectors[i]=(struct iovec){!publication && i==1 ? unwritable : (void *)(bytes+i),1};
            messages[i]=(struct mmsghdr){.msg_hdr={.msg_iov=vectors+i,.msg_iovlen=1,
                .msg_control=control[i].bytes,.msg_controllen=sizeof(control[i])}};
        }
        if (publication) assert(!mprotect(mapping+page,page,PROT_READ));
        assert(recvmmsg(sockets[1],messages,3,MSG_CMSG_CLOEXEC,NULL)==1);
        int payloads=(bytes[0]=='x')+(bytes[1]=='x')+(bytes[2]=='x');
        for (unsigned i=0;i<3;++i) if (control[i].align.cmsg_len) {
            struct msghdr published=messages[i].msg_hdr;
            published.msg_controllen=CMSG_ALIGN(control[i].align.cmsg_len);
            close_descriptors(&published,1);
        }
        int registered=epoll_wait(epoll,&ready,1,0); assert(registered>=0);
        int registered_error=registered==1 && !!(ready.events&EPOLLERR);
        struct pollfd pollfd={.fd=sockets[1],.events=0};
        assert(poll(&pollfd,1,0)>=0);
        assert(!epoll_ctl(epoll,EPOLL_CTL_MOD,sockets[1],&event));
        int rearmed=epoll_wait(epoll,&ready,1,0); assert(rearmed>=0);
        int rearmed_error=rearmed==1 && !!(ready.events&EPOLLERR);
        long result=0; int reported=0; socklen_t length=sizeof(int);
        errno=0;
        switch (consumer) {
            case 0: result=send(sockets[1],"a",1,MSG_NOSIGNAL|MSG_DONTWAIT); break;
            case 1: result=write(sockets[1],"a",1); break;
            case 2: result=read(sockets[1],bytes,0); break;
            case 3: result=recv(sockets[1],bytes,1,MSG_PEEK|MSG_DONTWAIT); break;
            case 4: result=getsockopt(sockets[1],SOL_SOCKET,SO_ERROR,unwritable,&length); break;
            case 5: result=getsockopt(sockets[1],SOL_SOCKET,SO_ERROR,&reported,unwritable); break;
            case 6: {
                struct iovec vector={bytes,1}; struct msghdr m={.msg_iov=&vector,.msg_iovlen=1};
                result=recvmsg(sockets[1],&m,MSG_DONTWAIT); break;
            }
            case 7: result=recvmmsg(sockets[1],messages,0,0,NULL); break;
        }
        if (result<0) reported=errno;
        int remaining=socket_error(sockets[1]);
        unsigned queued=0;
        while (recv(sockets[1],bytes,1,MSG_DONTWAIT)==1) ++queued;
        assert(errno==EAGAIN && read(pipefd[0],bytes,1)==0);
        struct pollfd after={.fd=sockets[1],.events=0}; assert(poll(&after,1,0)>=0);
        printf("OBS rights-error-consumers publication=%u type=%d consumer=%u payloads=%d registered=%d pollerr=%d rearmed=%d result=%ld error=%d remaining=%d queued=%u cleared=%d\n",
            publication,types[type],consumer,payloads,registered_error,!!(pollfd.revents&POLLERR),
            rearmed_error,result,reported,remaining,queued,!(after.revents&POLLERR));
        assert(!munmap(mapping,2*page) && !close(epoll) && !close(pipefd[0])
            && !close(sockets[0]) && !close(sockets[1]));
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
static void receive_full_table(void) {
    struct rlimit saved; assert(!getrlimit(RLIMIT_NOFILE,&saved));
    struct rlimit limited=saved; limited.rlim_cur=64;
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets));
    assert(write(sockets[0],"x",1)==1 && !setrlimit(RLIMIT_NOFILE,&limited));
    int filled[64],count=0,fd;
    while ((fd=fcntl(sockets[0],F_DUPFD_CLOEXEC,0))>=0) {
        assert(count<64); filled[count++]=fd;
    }
    if (errno!=EMFILE || !count) fprintf(stderr,"receive-full-table filled=%d error=%d socket=%d\n",count,errno,sockets[0]);
    assert(errno==EMFILE && count);
    char byte=0; struct iovec vector={&byte,1};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1};
    assert(recvmsg(sockets[1],&message,MSG_DONTWAIT)==1 && byte=='x');
    assert(recvmsg(sockets[1],&message,MSG_DONTWAIT)==-1 && errno==EAGAIN);
    for (int i=0;i<count;++i) assert(!close(filled[i]));
    assert(!close(sockets[0]) && !close(sockets[1]) && !setrlimit(RLIMIT_NOFILE,&saved));
    puts("OBS receive-full-table payload=x empty=EAGAIN");
}
static void receive_vectors(void) {
    const unsigned counts[]={1,8,9};
    const unsigned sizes[]={31,65536,65537};
    for (unsigned c=0;c<sizeof(counts)/sizeof(*counts);++c)
        for (unsigned s=0;s<sizeof(sizes)/sizeof(*sizes);++s) {
            int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets));
            unsigned count=counts[c],size=sizes[s];
            char *input=malloc(size),*output=malloc(size); assert(input && output);
            memset(input,'x',size); memset(output,0,size);
            assert(write(sockets[0],input,size)==(ssize_t)size);
            struct iovec vectors[9]; unsigned offset=0;
            for (unsigned i=0;i<count;++i) {
                unsigned length=(size-offset)/(count-i);
                vectors[i]=(struct iovec){output+offset,length}; offset+=length;
            }
            char control[64];
            struct msghdr message={.msg_iov=vectors,.msg_iovlen=count,
                .msg_control=control,.msg_controllen=sizeof(control)};
            assert(recvmsg(sockets[1],&message,MSG_DONTWAIT)==(ssize_t)size);
            assert(!memcmp(input,output,size) && !message.msg_controllen && !message.msg_flags);
            char empty_control[4096];
            const unsigned capacities[]={64,2048,4096};
            for (unsigned i=0;i<sizeof(capacities)/sizeof(*capacities);++i) {
                message.msg_control=empty_control; message.msg_controllen=capacities[i];
                message.msg_flags=0x123;
                struct msghdr before; memcpy(&before,&message,sizeof(before));
                errno=0; assert(recvmsg(sockets[1],&message,MSG_DONTWAIT)==-1 && errno==EAGAIN);
                assert(!memcmp(&before,&message,sizeof(message)));
            }
            message.msg_iov=(void *)-1;
            errno=0; assert(recvmsg(sockets[1],&message,MSG_DONTWAIT)==-1 && errno==EFAULT);
            assert(!close(sockets[0]) && !close(sockets[1])); free(input); free(output);
            printf("OBS receive-vectors count=%u size=%u empty=EAGAIN invalid=EFAULT\n",count,size);
        }
}
static void receive_entry(void) {
    const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    for (unsigned type=0;type<3;++type) for (unsigned mode=0;mode<3;++mode)
            for (unsigned fault=0;fault<2;++fault) {
        int sockets[2],pipefd[2],one=1;
        int flags=MSG_CMSG_CLOEXEC|(mode==1 ? MSG_DONTWAIT : 0);
        assert(!socketpair(AF_UNIX,types[type]|SOCK_CLOEXEC|(mode==2 ? SOCK_NONBLOCK : 0),0,sockets));
        assert(!setsockopt(sockets[1],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)));
        assert(!pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
        struct msghdr *message=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(message!=MAP_FAILED);
        union { struct cmsghdr align; char bytes[128]; } control={0};
        char byte=0; struct iovec vectors[8]={{0}}; vectors[7]=(struct iovec){&byte,1};
        *message=(struct msghdr){.msg_iov=vectors,.msg_iovlen=8,.msg_control=control.bytes,
            .msg_controllen=sizeof(control)};
        send_rights(sockets[0],pipefd[1],2); assert(!close(pipefd[1]));
        if (fault) assert(!mprotect(message,page,PROT_READ));
        errno=0; ssize_t result=recvmsg(sockets[1],message,flags); int error=result<0 ? errno : 0;
        assert(result==(fault ? -1 : 1) && error==(fault ? EFAULT : 0) && byte=='x');
        struct msghdr published=*message;
        if (fault) published.msg_controllen=CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(2*sizeof(int));
        unsigned rights=0,credentials=0;
        for (struct cmsghdr *c=CMSG_FIRSTHDR(&published);c;c=CMSG_NXTHDR(&published,c)) {
            assert(c->cmsg_level==SOL_SOCKET);
            if (c->cmsg_type==SCM_CREDENTIALS) {
                struct ucred sender; assert(c->cmsg_len==CMSG_LEN(sizeof(sender)));
                memcpy(&sender,CMSG_DATA(c),sizeof(sender));
                assert(sender.pid==getpid() && sender.uid==getuid() && sender.gid==getgid()); ++credentials;
            } else {
                assert(c->cmsg_type==SCM_RIGHTS && c->cmsg_len==CMSG_LEN(2*sizeof(int)));
                int fds[2]; memcpy(fds,CMSG_DATA(c),sizeof(fds));
                for (unsigned i=0;i<2;++i) {
                    assert(fcntl(fds[i],F_GETFD)==FD_CLOEXEC && !close(fds[i])); ++rights;
                }
            }
        }
        assert(rights==2 && credentials==1 && read(pipefd[0],&byte,1)==0);
        assert(!mprotect(message,page,PROT_READ|PROT_WRITE));
        message->msg_controllen=sizeof(control); message->msg_flags=0x123;
        struct msghdr before; memcpy(&before,message,sizeof(before));
        assert(recvmsg(sockets[1],message,flags|MSG_DONTWAIT)==-1 && errno==EAGAIN);
        assert(!memcmp(&before,message,sizeof(before)));
        close(sockets[0]);
        if (types[type]!=SOCK_DGRAM) assert(recvmsg(sockets[1],message,flags|MSG_DONTWAIT)==0);
        assert(!close(sockets[1]) && !close(pipefd[0]) && !munmap(message,page));
        printf("OBS receive-entry type=%d mode=%u fault=%u rights=2 credentials=1 empty=EAGAIN eof=1\n",
            types[type],mode,fault);
    }
}
static volatile sig_atomic_t receive_signals;
static void receive_signal(int signal) {
    assert(signal==SIGUSR1);
    ++receive_signals;
}
static void receive_entry_signals(void) {
    struct sigaction action={.sa_handler=receive_signal},previous;
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1,&action,&previous));
    sigset_t blocked,saved,current;
    sigemptyset(&blocked); sigaddset(&blocked,SIGUSR1);
    assert(!sigprocmask(SIG_BLOCK,&blocked,&saved));
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,sockets));
    char byte; struct iovec vector={&byte,1};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1};
    for (unsigned i=0;i<64;++i) {
        assert(!raise(SIGUSR1));
        assert(recvmsg(sockets[1],&message,0)==-1 && errno==EAGAIN);
        assert(!sigprocmask(SIG_SETMASK,NULL,&current) && sigismember(&current,SIGUSR1)==1);
        assert(receive_signals==(sig_atomic_t)i);
        assert(!sigprocmask(SIG_UNBLOCK,&blocked,NULL));
        assert(receive_signals==(sig_atomic_t)i+1);
        assert(write(sockets[0],"x",1)==1);
        assert(recvmsg(sockets[1],&message,0)==1 && byte=='x');
        assert(!sigprocmask(SIG_SETMASK,NULL,&current) && sigismember(&current,SIGUSR1)==0);
        assert(!sigprocmask(SIG_BLOCK,&blocked,NULL));
    }
    close(sockets[0]); close(sockets[1]);
    assert(!sigprocmask(SIG_SETMASK,&saved,NULL));
    assert(!sigaction(SIGUSR1,&previous,NULL));
    puts("OBS receive-entry-signals pending=64 delivered=64 mask=preserved");
}
int md_test_ancillary_contract(const char *name) {
    if (!strcmp(name,"receive-entry-signals")) { receive_entry_signals(); return 1; }
    if (!strcmp(name,"receive-entry")) { receive_entry(); return 1; }
    if (!strcmp(name,"receive-vectors")) { receive_vectors(); return 1; }
    if (!strcmp(name,"receive-full-table")) { receive_full_table(); return 1; }
    if (!strcmp(name,"rights-peek")) rights_peek();
    else if (!strcmp(name,"rights-truncate")) rights_truncate();
    else if (!strcmp(name,"rights-limit")) rights_limit();
    else if (!strcmp(name,"rights-batch")) rights_batch();
    else if (!strcmp(name,"receive-large-batch")) receive_large_batch();
    else if (!strcmp(name,"receive-batch-snapshot")) receive_batch_snapshot();
    else if (!strcmp(name,"rights-fault")) rights_fault();
    else if (!strcmp(name,"rights-control-fault")) rights_control_fault();
    else if (!strcmp(name,"rights-header-outputs")) rights_header_outputs();
    else if (!strcmp(name,"rights-name")) rights_name();
    else if (!strcmp(name,"rights-timeout-fault")) rights_timeout_fault();
    else if (!strcmp(name,"rights-batch-fault")) rights_batch_fault();
    else if (!strcmp(name,"rights-socket-error")) rights_socket_error(0);
    else if (!strcmp(name,"rights-publication-error")) for (unsigned fault=1;fault<=3;++fault) rights_socket_error(fault);
    else if (!strcmp(name,"rights-error-consumers")) rights_error_consumers(0);
    else if (!strcmp(name,"rights-publication-consumers")) rights_error_consumers(1);
    else if (!strcmp(name,"rights-watch-fault")) rights_watch_fault();
    else return 0;
    return 1;
}
