#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

struct reader { int fd, mode, sink; atomic_int entered, cleaned; };
static void cleaned(void *arg) {
    struct reader *r=arg;
    atomic_fetch_add(&r->cleaned,1);
}
static void *receive(void *arg) {
    struct reader *r=arg;
    char buffer[8192];
    pthread_cleanup_push(cleaned,r);
    atomic_store(&r->entered,1);
    if (r->mode==2) (void)splice(r->fd,NULL,r->sink,NULL,sizeof(buffer),0);
    else if (r->mode==1) {
        struct iovec v={buffer,sizeof(buffer)};
        (void)readv(r->fd,&v,1);
    } else (void)read(r->fd,buffer,sizeof(buffer));
    pthread_cleanup_pop(0);
    return NULL;
}
int main(void) {
    alarm(30);
    for (unsigned fuse=0;fuse<2;++fuse) for (unsigned mode=0;mode<3;++mode) {
        int pipefd[2]={-1,-1},sink[2];
        assert(!pipe2(sink,O_CLOEXEC));
        if (!fuse) assert(!pipe2(pipefd,O_CLOEXEC));
        int fd=fuse ? open("/dev/fuse",O_RDWR|O_CLOEXEC) : pipefd[0];
        assert(fd>=0);
        for (unsigned i=0;i<8;++i) {
            struct reader r={.fd=fd,.mode=mode,.sink=sink[1]};
            pthread_t thread;
            assert(!pthread_create(&thread,NULL,receive,&r));
            while (!atomic_load(&r.entered)) sched_yield();
            /* Vary admission races; cancellation must also work once parked. */
            for (unsigned n=0;n<i*128;++n) sched_yield();
            assert(!pthread_cancel(thread));
            struct timespec deadline;
            assert(!clock_gettime(CLOCK_REALTIME,&deadline)); deadline.tv_sec+=3;
            /* EVENT_WAIT: exact cancelled thread; timeout is failure. */
            void *result=NULL;
            int error=pthread_timedjoin_np(thread,&result,&deadline);
            if (error || result!=PTHREAD_CANCELED || atomic_load(&r.cleaned)!=1) {
                fprintf(stderr,"cancel fuse=%u mode=%u round=%u error=%d result=%p cleaned=%d\n",
                    fuse,mode,i,error,result,atomic_load(&r.cleaned));
                return 1;
            }
        }
        assert(!close(fd));
        assert(!close(sink[0]) && !close(sink[1]));
        if (!fuse) assert(!close(pipefd[1]));
        printf("PASS cancellation: %s %s, cleanup and join\n",fuse ? "FUSE" : "pipe",(const char *[]){"read","readv","splice"}[mode]);
        fflush(stdout);
    }
    return 0;
}
