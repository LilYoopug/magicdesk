#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <ucontext.h>
extern long entry_probe(long,long,long,long,long,long,long);
extern const unsigned entry_probe_svc;
__asm__(".text\n.balign 4\n.global entry_probe\nentry_probe:\nmov x8,x0\n"
        "mov x0,x1\nmov x1,x2\nmov x2,x3\nmov x3,x4\nmov x4,x5\nmov x5,x6\n"
        ".global entry_probe_svc\nentry_probe_svc:\nsvc #0\nret\n");

static sem_t semaphore;
static atomic_int tid, handled;
static int notification;
static int raw_mode, futex_word;
static uintptr_t handler_pc;
static void handler(int signal,siginfo_t *info,void *context) {
    (void)signal;
    (void)info;
    handler_pc=((ucontext_t *)context)->uc_mcontext.pc;
    int saved=errno;
    uint64_t one=1;
    assert(write(notification,&one,sizeof(one))==sizeof(one));
    atomic_fetch_add(&handled,1);
    errno=saved;
}
static void *waiter(void *unused) {
    (void)unused;
    atomic_store(&tid,(int)syscall(SYS_gettid));
    int result, error;
    if (raw_mode) {
        long value=entry_probe(SYS_futex,(long)&futex_word,FUTEX_WAIT_PRIVATE,0,0,0,0);
        result=value<0 ? -1 : value; error=value<0 ? -value : 0;
    } else { result=sem_wait(&semaphore); error=errno; }
    if (result!=-1 || error!=EINTR) {
        fprintf(stderr,"sem_wait=%d errno=%d\n",result,error);
        abort();
    }
    return NULL;
}
int main(int argc,char **argv) {
    (void)argv;
    raw_mode=argc>1;
    alarm(30);
    for (unsigned i=0;i<32;++i) assert(entry_probe(SYS_getuid,0,0,0,0,0,0)>=0);
    fprintf(stderr,"entryProbe=%#x\n",*(const volatile unsigned *)&entry_probe_svc);
    notification=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    assert(notification>=0 && !sem_init(&semaphore,0,0));
    struct sigaction action={.sa_sigaction=handler,.sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGHUP,&action,NULL));
    int input=open("/etc/os-release",O_RDONLY|O_CLOEXEC);
    assert(input>=0);
    for (unsigned i=0;i<32;++i) {
        atomic_store(&tid,0);
        pthread_t thread;
        assert(!pthread_create(&thread,NULL,waiter,NULL));
        while (!atomic_load(&tid)) sched_yield();
        for (unsigned n=0;n<32;++n) {
            char buffer[64];
            assert(lseek(input,0,SEEK_SET)==0 && read(input,buffer,sizeof(buffer))>0);
            int fd=open("/etc/os-release",O_RDONLY|O_CLOEXEC);
            assert(fd>=0 && !close(fd));
        }
        char path[128];
        snprintf(path,sizeof(path),"/proc/self/task/%d/syscall",atomic_load(&tid));
        /* EVENT_WAIT: observe the target blocked in futex before signalling;
         * the process alarm bounds failed observation without a settling delay. */
        for (;;) {
            FILE *file=fopen(path,"r");
            assert(file);
            long nr=-1;
            unsigned long args[6],sp,pc;
            int fields=fscanf(file,"%ld %lx %lx %lx %lx %lx %lx %lx %lx",&nr,
                args,args+1,args+2,args+3,args+4,args+5,&sp,&pc);
            fclose(file);
            if (fields==9 && nr==SYS_futex) {
                fprintf(stderr,"round=%u waitPC=%#lx instruction=%#x\n",i,pc,*(unsigned *)(pc-4));
                break;
            }
            sched_yield();
        }
        assert(!pthread_kill(thread,SIGHUP));
        struct timespec deadline;
        assert(!clock_gettime(CLOCK_REALTIME,&deadline)); deadline.tv_sec+=2;
        /* EVENT_WAIT: interruptible semaphore returns and thread exits. */
        int error=pthread_timedjoin_np(thread,NULL,&deadline);
        if (error) {
            fprintf(stderr,"round=%u join=%d handled=%d tid=%d\n",i,error,
                atomic_load(&handled),atomic_load(&tid));
            return 1;
        }
        assert(atomic_load(&handled)==(int)i+1);
        fprintf(stderr,"handlerPC=%#lx\n",(unsigned long)handler_pc);
    }
    assert(!sem_destroy(&semaphore) && !close(notification) && !close(input));
    puts("PASS semaphore interruption, handler IO and pthread_kill: 32 rounds");
    return 0;
}
