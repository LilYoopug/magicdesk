/* Included by the credential fixture to share native/guest launch coverage. */
#include <sys/time.h>
#include <sys/timerfd.h>

static void io_filter(void) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,CLONE_THREAD,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog filter={sizeof(code)/sizeof(*code),code};
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) && !prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter));
}
static volatile sig_atomic_t io_signal;
static void io_handler(int sig) { io_signal=sig; }
static void io_alarm(void) {
    struct itimerval timer={.it_value={.tv_usec=50000}};
    CHECK(!setitimer(ITIMER_REAL,&timer,NULL));
}
static void io_later(void) {
    int timer=timerfd_create(CLOCK_MONOTONIC,TFD_CLOEXEC); CHECK(timer>=0);
    struct itimerspec when={.it_value={.tv_nsec=100000000}};
    CHECK(!timerfd_settime(timer,0,&when,NULL));
    /* EVENT_WAIT: timed producer supplies the second fragment; launch deadline
     * bounds failure. No production settling delay is exercised. */
    uint64_t ticks; CHECK(read(timer,&ticks,sizeof(ticks))==sizeof(ticks)); close(timer);
}
static void io_batch_inputs(unsigned mode) {
    int sockets[2]; CHECK(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK,0,sockets));
    for (unsigned i=0;i<3;++i) CHECK(send(sockets[0],"x",1,0)==1);
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(mapping!=MAP_FAILED);
    struct mmsghdr *messages=(void *)(mapping+page-sizeof(*messages));
    char bytes[3]={0}; struct iovec vectors[3];
    for (unsigned i=0;i<3;++i) {
        vectors[i]=(struct iovec){bytes+i,1};
        messages[i]=(struct mmsghdr){.msg_hdr={.msg_iov=vectors+i,.msg_iovlen=1}};
    }
    if (mode==25) CHECK(!mprotect(mapping+page,page,PROT_NONE));
    else {
        messages[1].msg_hdr.msg_name=bytes;
        messages[1].msg_hdr.msg_namelen=(socklen_t)-1;
    }
    io_filter(); CHECK(!prctl(PR_SET_DUMPABLE,0));
    CHECK(recvmmsg(sockets[1],messages,3,MSG_DONTWAIT,NULL)==1 && bytes[0]=='x' && !bytes[1] && !bytes[2]);
    int alias=dup(sockets[1]); CHECK(alias>=0);
    struct pollfd ready={.fd=alias}; CHECK(poll(&ready,1,0)==1 && (ready.revents&POLLERR));
    int error=0; socklen_t size=sizeof(error);
    CHECK(!getsockopt(alias,SOL_SOCKET,SO_ERROR,&error,&size) && error==(mode==25 ? EFAULT : EINVAL));
    for (unsigned i=0;i<2;++i) CHECK(recv(alias,bytes,1,0)==1);
    CHECK(recv(alias,bytes,1,0)==-1 && errno==EAGAIN);
    CHECK(!close(alias) && !close(sockets[0]) && !close(sockets[1]) && !munmap(mapping,2*page));
}
static void io_contract(unsigned mode) {
    alarm(15);
    if (mode==25 || mode==26) {
        io_batch_inputs(mode); printf("PASS filtered socket IO mode=%u\n",mode); return;
    }
    int pair[2];
    if (mode==14 || mode==27) {
        int server=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(server>=0);
        struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        socklen_t size=sizeof(address);
        CHECK(!bind(server,(void *)&address,size) && !getsockname(server,(void *)&address,&size) && !listen(server,1));
        pair[0]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(pair[0]>=0 && !connect(pair[0],(void *)&address,size));
        pair[1]=accept4(server,NULL,NULL,SOCK_CLOEXEC); CHECK(pair[1]>=0); close(server);
    } else CHECK(!socketpair(AF_UNIX,mode==0 || (mode>=16 && mode<=23) ? SOCK_DGRAM : SOCK_STREAM,0,pair));
    io_filter();
    CHECK(!prctl(PR_SET_DUMPABLE,0));
    if (mode==0) {
        size_t length=96*1024, control_size=8192;
        char *sent=malloc(length), *received=calloc(1,length), *control=calloc(1,control_size);
        CHECK(sent && received && control); memset(sent,0x5a,length);
        struct cmsghdr *header=(void *)control;
        *header=(struct cmsghdr){.cmsg_len=control_size,.cmsg_level=12345,.cmsg_type=1};
        struct iovec data={sent,length};
        struct msghdr message={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,.msg_controllen=control_size};
        CHECK(sendmsg(pair[0],&message,0)==(ssize_t)length);
        data=(struct iovec){received,length}; message.msg_control=control; message.msg_controllen=control_size;
        CHECK(recvmsg(pair[1],&message,0)==(ssize_t)length && !memcmp(sent,received,length));
        CHECK(!(message.msg_flags&MSG_CMSG_CLOEXEC));
        free(sent); free(received); free(control);
    } else if (mode>=16 && mode<=23) {
        unsigned sent=mode==18 ? 0 : mode==19 ? 1 : mode==16 ? 2 : 3;
        int pipefd[2]; CHECK(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK));
        for (unsigned i=0;i<sent;++i) {
            char byte=(char)('a'+i);
            union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(int))]; } control={0};
            control.align=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
            memcpy(CMSG_DATA(&control.align),&pipefd[1],sizeof(int));
            struct iovec vector={&byte,1};
            struct msghdr m={.msg_iov=&vector,.msg_iovlen=1,.msg_control=control.data,.msg_controllen=sizeof(control)};
            CHECK(sendmsg(pair[0],&m,0)==1);
        }
        close(pipefd[1]);
        struct mmsghdr messages[3]={0}; struct iovec vectors[3]; char bytes[3]={0};
        union { struct cmsghdr align; char data[128]; } controls[3]={0};
        for (unsigned i=0;i<3;++i) {
            vectors[i]=(struct iovec){bytes+i,1};
            messages[i].msg_hdr=(struct msghdr){.msg_iov=vectors+i,.msg_iovlen=1,
                .msg_control=controls[i].data,.msg_controllen=sizeof(controls[i])};
        }
        struct sigaction action={.sa_handler=io_handler}; sigemptyset(&action.sa_mask);
        CHECK(!sigaction(SIGALRM,&action,NULL));
        if (mode==18) {
            struct timeval timeout={.tv_usec=30000};
            CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
        }
        if (mode==19) io_alarm();
        if (mode==22 || mode==23) {
            messages[1].msg_hdr.msg_iov=NULL;
            messages[1].msg_hdr.msg_iovlen=mode==22 ? 1 : 1025;
        }
        size_t page=(size_t)sysconf(_SC_PAGESIZE);
        struct timespec zero={0}, *timeout=NULL;
        if (mode==20) {
            timeout=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); CHECK(timeout!=MAP_FAILED);
            *timeout=(struct timespec){.tv_sec=1}; CHECK(!mprotect(timeout,page,PROT_READ));
        } else if (mode==21) timeout=&zero;
        errno=0;
        int result=recvmmsg(pair[1],messages,3,MSG_CMSG_CLOEXEC|(mode==16 ? MSG_WAITFORONE : mode==17 ? MSG_DONTWAIT : 0),timeout);
        CHECK(result==(mode==18 || mode==20 ? -1 : mode==19 || mode>=21 ? 1 : (int)sent));
        if (mode==18) CHECK(errno==EAGAIN);
        if (mode==20) CHECK(errno==EFAULT);
        if (mode==19) CHECK(io_signal==SIGALRM);
        unsigned completed=mode>=21 ? 1 : sent;
        for (unsigned i=0;i<completed;++i) {
            CHECK(messages[i].msg_len==1 && bytes[i]=='a'+i);
            struct cmsghdr *h=CMSG_FIRSTHDR(&messages[i].msg_hdr);
            CHECK(h && h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS && h->cmsg_len==CMSG_LEN(sizeof(int)));
            int fd; memcpy(&fd,CMSG_DATA(h),sizeof(fd)); CHECK(fcntl(fd,F_GETFD)&FD_CLOEXEC); CHECK(!close(fd));
        }
        if (mode>=22) {
            int alias=dup(pair[1]); CHECK(alias>=0);
            struct pollfd event={.fd=alias}; CHECK(poll(&event,1,0)==1 && (event.revents&POLLERR));
            int error=0; socklen_t length=sizeof(error);
            CHECK(!getsockopt(alias,SOL_SOCKET,SO_ERROR,&error,&length));
            CHECK(error==(mode==22 ? EFAULT : EMSGSIZE)); close(alias);
        }
        for (unsigned i=completed;i<sent;++i) CHECK(recv(pair[1],bytes,1,MSG_DONTWAIT)==1);
        CHECK(read(pipefd[0],bytes,1)==0); close(pipefd[0]);
        if (mode==20) CHECK(!munmap(timeout,page));
    } else {
        char data[8]={0}; _Alignas(struct cmsghdr) char control[8192];
        struct iovec vector={data,4};
        struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        struct sigaction action={.sa_handler=io_handler}; CHECK(!sigemptyset(&action.sa_mask));
        CHECK(!sigaction(SIGALRM,&action,NULL));
        if (mode==1) {
            struct timeval timeout={.tv_usec=30000};
            CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
            CHECK(recvmsg(pair[1],&message,0)==-1 && errno==EAGAIN);
        } else if (mode==2 || mode==28) {
            if (mode==28) {
                action.sa_flags=SA_RESTART; CHECK(!sigaction(SIGALRM,&action,NULL));
                struct timeval timeout={.tv_sec=2};
                CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
            }
            io_alarm(); ssize_t result=recvmsg(pair[1],&message,0);
            if (result!=-1 || errno!=EINTR || io_signal!=SIGALRM)
                fprintf(stderr,"IO interrupt result=%zd error=%d signal=%d\n",result,errno,io_signal);
            CHECK(result==-1 && errno==EINTR && io_signal==SIGALRM);
        } else if (mode==3 || mode==4 || mode==5 || mode==13 || mode==14 || mode==27) {
            if (mode==27) {
                int low=4; CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_RCVLOWAT,&low,sizeof(low)));
            }
            CHECK(write(pair[0],"ab",2)==2);
            if (mode==4) {
                io_alarm(); CHECK(recvmsg(pair[1],&message,MSG_WAITALL)==2 && !memcmp(data,"ab",2) && io_signal==SIGALRM);
            } else if (mode==5) {
                struct timeval timeout={.tv_usec=30000};
                CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
                CHECK(recvmsg(pair[1],&message,MSG_WAITALL)==2 && !memcmp(data,"ab",2));
            } else {
                pid_t child=fork(); CHECK(child>=0);
                if (!child) { close(pair[1]); io_later(); CHECK(write(pair[0],"cd",2)==2); _exit(0); }
                ssize_t expected=mode==13 ? 2 : 4;
                CHECK(recvmsg(pair[1],&message,mode==27 ? 0 : MSG_WAITALL|(mode>=13 ? MSG_PEEK : 0))==expected
                    && !memcmp(data,"abcd",(size_t)expected)); done(child);
                if (mode==13 || mode==14) CHECK(read(pair[1],data,4)==4 && !memcmp(data,"abcd",4));
            }
        } else if (mode==9 || mode==10 || mode==11) {
            int size=4096; CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_SNDBUF,&size,sizeof(size)));
            char fill[4096]={0};
            while (send(pair[0],fill,sizeof(fill),MSG_DONTWAIT|MSG_NOSIGNAL)>0) {}
            CHECK(errno==EAGAIN);
            struct cmsghdr *header=(void *)control;
            int fd=open("/dev/null",O_RDONLY); CHECK(fd>=0);
            *header=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
            memcpy(CMSG_DATA(header),&fd,sizeof(fd)); message.msg_controllen=CMSG_SPACE(sizeof(fd));
            if (mode==9) {
                struct timeval timeout={.tv_usec=30000};
                CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)));
                CHECK(sendmsg(pair[0],&message,MSG_NOSIGNAL)==-1 && errno==EAGAIN);
            } else if (mode==10) {
                io_alarm(); CHECK(sendmsg(pair[0],&message,MSG_NOSIGNAL)==-1 && errno==EINTR && io_signal==SIGALRM);
            } else {
                CHECK(shutdown(pair[1],SHUT_RD)==0);
                action=(struct sigaction){.sa_sigaction=broken_pipe,.sa_flags=SA_SIGINFO};
                CHECK(!sigemptyset(&action.sa_mask) && !sigaction(SIGPIPE,&action,NULL));
                CHECK(sendmsg(pair[0],&message,0)==-1 && errno==EPIPE && broken_count==1);
            }
            close(fd);
        } else if (mode==12) {
            size_t length=1024*1024;
            char *sent=malloc(length); CHECK(sent); memset(sent,0x75,length);
            int size=4096; CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_SNDBUF,&size,sizeof(size)));
            struct cmsghdr *header=(void *)control;
            int fd=open("/dev/null",O_RDONLY); CHECK(fd>=0);
            *header=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
            memcpy(CMSG_DATA(header),&fd,sizeof(fd)); message.msg_controllen=CMSG_SPACE(sizeof(fd));
            pid_t child=fork(); CHECK(child>=0);
            if (!child) {
                close(pair[0]); close(fd);
                char *received=calloc(1,length); CHECK(received); size_t count=0; unsigned rights=0;
                while (count<length) {
                    struct iovec iov={received+count,length-count};
                    struct msghdr next={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
                    ssize_t n=recvmsg(pair[1],&next,MSG_WAITALL); CHECK(n>0); count+=(size_t)n;
                    for (struct cmsghdr *h=CMSG_FIRSTHDR(&next);h;h=CMSG_NXTHDR(&next,h)) {
                        CHECK(h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS && h->cmsg_len==CMSG_LEN(sizeof(int)));
                        int received_fd; memcpy(&received_fd,CMSG_DATA(h),sizeof(int)); CHECK(!close(received_fd)); ++rights;
                    }
                }
                CHECK(rights==1 && !memcmp(sent,received,length)); _exit(0);
            }
            close(pair[1]); pair[1]=-1;
            struct iovec many[12];
            for (unsigned i=0;i<12;++i) {
                size_t start=length*i/12, end=length*(i+1)/12;
                many[i]=(struct iovec){sent+start,end-start};
            }
            message.msg_iov=many; message.msg_iovlen=12;
            CHECK(sendmsg(pair[0],&message,MSG_NOSIGNAL)==(ssize_t)length); done(child);
            close(fd); free(sent);
        } else if (mode==15) {
            int enabled=1; CHECK(!setsockopt(pair[1],SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled)));
            pid_t child=fork(); CHECK(child>=0);
            if (!child) {
                close(pair[1]); CHECK(write(pair[0],"ab",2)==2);
                io_later(); CHECK(write(pair[0],"cd",2)==2); _exit(0);
            }
            ssize_t n=recvmsg(pair[1],&message,MSG_WAITALL);
            if (n!=4) fprintf(stderr,"IO credential WAITALL result=%zd error=%d\n",n,errno);
            CHECK(n==4 && !memcmp(data,"abcd",4));
            struct cmsghdr *h=CMSG_FIRSTHDR(&message);
            CHECK(h && h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDENTIALS
                && h->cmsg_len==CMSG_LEN(sizeof(struct ucred)));
            struct ucred cred; memcpy(&cred,CMSG_DATA(h),sizeof(cred));
            CHECK(cred.pid==child); done(child);
        } else if (mode==7 || mode==24) {
            action.sa_flags=SA_RESTART; CHECK(!sigaction(SIGALRM,&action,NULL));
            pid_t child=fork(); CHECK(child>=0);
            if (!child) { close(pair[1]); io_later(); CHECK(write(pair[0],"abcd",4)==4); _exit(0); }
            io_alarm();
            CHECK(recvmsg(pair[1],&message,mode==24 ? MSG_WAITALL : 0)==4 && !memcmp(data,"abcd",4) && io_signal==SIGALRM);
            done(child);
        } else if (mode==6 || mode==8) {
            close(pair[1]); pair[1]=-1;
            action=(struct sigaction){.sa_sigaction=broken_pipe,.sa_flags=SA_SIGINFO};
            CHECK(!sigemptyset(&action.sa_mask) && !sigaction(SIGPIPE,&action,NULL));
            sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGPIPE);
            if (mode==8) CHECK(!sigprocmask(SIG_BLOCK,&mask,NULL));
            int fd=open("/dev/null",O_RDONLY); CHECK(fd>=0);
            message.msg_controllen=CMSG_SPACE(sizeof(int));
            struct cmsghdr *header=CMSG_FIRSTHDR(&message);
            *header=(struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
            memcpy(CMSG_DATA(header),&fd,sizeof(fd));
            CHECK(sendmsg(pair[0],&message,0)==-1 && errno==EPIPE);
            if (mode==8) {
                siginfo_t info; struct timespec zero={0};
                CHECK(sigtimedwait(&mask,&info,&zero)==SIGPIPE && info.si_code==SI_USER
                    && info.si_pid==getpid() && !broken_count);
            } else CHECK(broken_count==1 && broken_code==SI_USER && broken_pid==getpid());
            CHECK(sendmsg(pair[0],&message,MSG_NOSIGNAL)==-1 && errno==EPIPE && broken_count==(mode==6));
            close(fd);
        } else CHECK(0);
    }
    close(pair[0]); if (pair[1]>=0) close(pair[1]);
    printf("PASS filtered socket IO mode=%u\n",mode);
}
