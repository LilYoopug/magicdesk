#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void require(int condition,const char *what) {
    if (!condition) { perror(what); exit(1); }
}
static double seconds(void) {
    struct timespec t;
    require(!clock_gettime(CLOCK_MONOTONIC,&t),"clock_gettime");
    return t.tv_sec+t.tv_nsec/1e9;
}
static double cpu(const struct rusage *r) {
    return r->ru_utime.tv_sec+r->ru_stime.tv_sec+(r->ru_utime.tv_usec+r->ru_stime.tv_usec)/1e6;
}
static struct sockaddr_in address(unsigned port) {
    return (struct sockaddr_in){.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
}
static int channel(int type) {
    int fd=socket(AF_INET,type|SOCK_CLOEXEC,0);
    require(fd>=0,"socket");
    struct timeval timeout={.tv_sec=10};
    require(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)),"receive timeout");
    require(!setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)),"send timeout");
    if (type==SOCK_STREAM) {
        int on=1;
        require(!setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&on,sizeof(on)),"TCP_NODELAY");
        require(!setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)),"SO_REUSEADDR");
    }
    return fd;
}
static void transfer(int fd,void *data,size_t bytes,int sending) {
    size_t at=0;
    while (at<bytes) {
        ssize_t n=sending ? send(fd,(char *)data+at,bytes-at,MSG_NOSIGNAL)
            : recv(fd,(char *)data+at,bytes-at,0);
        if (n<0 && errno==EINTR) continue;
        require(n>0,sending ? "send" : "recv"); at+=(size_t)n;
    }
}
static void measure(int type,unsigned bind_port,unsigned connect_port,unsigned rounds,size_t bytes) {
    struct rusage before,after,child_usage;
    require(!getrusage(RUSAGE_SELF,&before),"rusage before");
    int listener=channel(type);
    struct sockaddr_in local=address(bind_port);
    require(!bind(listener,(void *)&local,sizeof(local)),"bind");
    socklen_t size=sizeof(local);
    require(!getsockname(listener,(void *)&local,&size),"getsockname");
    if (type==SOCK_STREAM) require(!listen(listener,1),"listen");
    pid_t child=fork(); require(child>=0,"fork");
    if (!child) {
        char data[65536];
        int fd=type==SOCK_STREAM ? accept(listener,NULL,NULL) : listener;
        require(fd>=0,"accept");
        for (unsigned i=0;i<rounds+16;++i) {
            if (type==SOCK_STREAM) { transfer(fd,data,bytes,0); transfer(fd,data,bytes,1); }
            else {
                struct sockaddr_in peer; socklen_t length=sizeof(peer);
                require(recvfrom(fd,data,sizeof(data),0,(void *)&peer,&length)==(ssize_t)bytes,"recvfrom");
                require(sendto(fd,data,bytes,0,(void *)&peer,length)==(ssize_t)bytes,"sendto");
            }
        }
        close(fd); if (fd!=listener) close(listener); _exit(0);
    }
    close(listener);
    int fd=channel(type);
    struct sockaddr_in peer=address(connect_port ? connect_port : ntohs(local.sin_port));
    if (type==SOCK_STREAM) require(!connect(fd,(void *)&peer,sizeof(peer)),"connect");
    char sent[65536],received[65536]; memset(sent,0xa5,bytes);
    double start=0;
    for (unsigned i=0;i<rounds+16;++i) {
        if (i==16) start=seconds();
        if (type==SOCK_STREAM) { transfer(fd,sent,bytes,1); transfer(fd,received,bytes,0); }
        else {
            require(sendto(fd,sent,bytes,0,(void *)&peer,sizeof(peer))==(ssize_t)bytes,"client sendto");
            require(recv(fd,received,sizeof(received),0)==(ssize_t)bytes,"client recv");
        }
        require(!memcmp(sent,received,bytes),"echo payload");
    }
    double elapsed=seconds()-start;
    close(fd);
    int status;
    // EVENT_WAIT: exact echo child completion; the outer launch deadline bounds a hang.
    require(wait4(child,&status,0,&child_usage)==child && status==0,"echo child");
    require(!getrusage(RUSAGE_SELF,&after),"rusage after");
    printf("\"%s\":{\"seconds\":%.9f,\"roundTrips\":%u,\"payloadBytes\":%zu,\"applicationCpuSeconds\":%.9f}",
        type==SOCK_STREAM ? "tcp" : "udp",elapsed,rounds,bytes,cpu(&after)-cpu(&before)+cpu(&child_usage));
}
int main(int argc,char **argv) {
    if (argc>2 && !strcmp(argv[1],"--time")) {
        pid_t child=fork(); require(child>=0,"timed fork");
        if (!child) { execvp(argv[2],argv+2); perror("timed exec"); _exit(127); }
        struct rusage usage;
        int status;
        pid_t result;
        // EVENT_WAIT: exact invocation exit; the test transport bounds the command.
        do { result=wait4(child,&status,0,&usage); } while (result<0 && errno==EINTR);
        require(result==child,"timed child");
        printf("NETWORK_CPU %.9f\n",cpu(&usage));
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
    }
    require(argc==3,"arguments: bind-port connect-port");
    unsigned port=(unsigned)strtoul(argv[1],NULL,10), target=(unsigned)strtoul(argv[2],NULL,10);
    require(port<=65535 && target<=65535,"port range");
    printf("NETWORK_BENCH {");
    measure(SOCK_STREAM,port,target,1024,65536);
    printf(","); measure(SOCK_DGRAM,port,target,4096,128);
    printf("}\n"); return 0;
}
