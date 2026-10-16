#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}
static void reap(pid_t pid) {
    int status; assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && !WEXITSTATUS(status));
}
static void *metadata_thread(void *unused) {
    (void)unused;
    for (unsigned i=0;i<1000;++i) { struct stat st; assert(!stat("marker",&st) && st.st_size==7); }
    return NULL;
}
static int channel[2];
static pthread_barrier_t barrier;
static _Thread_local sigjmp_buf escape;
static _Thread_local volatile sig_atomic_t escape_armed;
static int escape_ready, escape_done;
static void escape_handler(int signal) {
    (void)signal;
    if (escape_armed) siglongjmp(escape,1);
}
static void *escaping_thread(void *unused) {
    (void)unused;
    if (!sigsetjmp(escape,1)) {
        escape_armed=1;
        __atomic_store_n(&escape_ready,1,__ATOMIC_RELEASE);
        for (;;) { struct stat st; assert(!stat("marker",&st)); }
    }
    escape_armed=0;
    int state;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&state));
    assert(state==PTHREAD_CANCEL_ENABLE);
    assert(!pthread_setcancelstate(state,NULL));
    __atomic_store_n(&escape_done,1,__ATOMIC_RELEASE);
    return NULL;
}
static void signal_abandonment(void) {
    struct sigaction action={.sa_handler=escape_handler},old;
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1,&action,&old));
    for (unsigned i=0;i<16;++i) {
        __atomic_store_n(&escape_ready,0,__ATOMIC_RELEASE);
        __atomic_store_n(&escape_done,0,__ATOMIC_RELEASE);
        pthread_t thread; assert(!pthread_create(&thread,NULL,escaping_thread,NULL));
        while (!__atomic_load_n(&escape_ready,__ATOMIC_ACQUIRE)) sched_yield();
        while (!__atomic_load_n(&escape_done,__ATOMIC_ACQUIRE)) {
            int result=pthread_kill(thread,SIGUSR1); assert(!result || result==ESRCH);
            sched_yield();
        }
        assert(!pthread_join(thread,NULL));
    }
    assert(!sigaction(SIGUSR1,&old,NULL));
}
static void *blocking_thread(void *unused) {
    (void)unused;
    int b=pthread_barrier_wait(&barrier); assert(!b || b==PTHREAD_BARRIER_SERIAL_THREAD);
    char c; read(channel[0],&c,1);
    return NULL;
}
static void *opening_thread(void *unused) {
    (void)unused;
    int b=pthread_barrier_wait(&barrier); assert(!b || b==PTHREAD_BARRIER_SERIAL_THREAD);
    int fd=open("cancel-fifo",O_RDONLY|O_CLOEXEC);
    if (fd>=0) close(fd);
    return NULL;
}
static unsigned descriptor_count(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned count=0;
    while (readdir(dir)) ++count;
    assert(!closedir(dir)); return count;
}
static int fifo_finished, fifo_signalled, fifo_opened, fifo_writer_ready;
static void fifo_signal(int signal) {
    (void)signal;
    __atomic_store_n(&fifo_signalled,1,__ATOMIC_RELEASE);
}
static void *fifo_signalled_open(void *context) {
    int restart=(int)(uintptr_t)context;
    int b=pthread_barrier_wait(&barrier); assert(!b || b==PTHREAD_BARRIER_SERIAL_THREAD);
    int fd=open("signal-fifo",O_RDONLY|O_CLOEXEC);
    if (restart) {
        assert(fd>=0);
        __atomic_store_n(&fifo_opened,1,__ATOMIC_RELEASE);
        while (!__atomic_load_n(&fifo_writer_ready,__ATOMIC_ACQUIRE)) sched_yield();
        char byte; ssize_t n;
        do { n=read(fd,&byte,1); } while (n<0 && errno==EINTR);
        assert(n==1 && byte=='x' && !close(fd));
    } else assert(fd==-1 && errno==EINTR);
    __atomic_store_n(&fifo_finished,1,__ATOMIC_RELEASE);
    return NULL;
}
static void fifo_signals(void) {
    unsigned before=descriptor_count();
    assert(!mkfifo("signal-fifo",0600));
    for (unsigned round=0;round<8;++round) for (int restart=0;restart<2;++restart) {
        struct sigaction action={.sa_handler=fifo_signal,.sa_flags=restart ? SA_RESTART : 0},old;
        sigemptyset(&action.sa_mask); assert(!sigaction(SIGUSR1,&action,&old));
        __atomic_store_n(&fifo_finished,0,__ATOMIC_RELEASE);
        __atomic_store_n(&fifo_signalled,0,__ATOMIC_RELEASE);
        __atomic_store_n(&fifo_opened,0,__ATOMIC_RELEASE);
        __atomic_store_n(&fifo_writer_ready,0,__ATOMIC_RELEASE);
        assert(!pthread_barrier_init(&barrier,NULL,2));
        pthread_t thread; assert(!pthread_create(&thread,NULL,fifo_signalled_open,(void *)(uintptr_t)restart));
        int b=pthread_barrier_wait(&barrier); assert(!b || b==PTHREAD_BARRIER_SERIAL_THREAD);
        int writer=-1;
        while (!__atomic_load_n(&fifo_finished,__ATOMIC_ACQUIRE)) {
            if (restart && __atomic_load_n(&fifo_signalled,__ATOMIC_ACQUIRE)) {
                writer=open("signal-fifo",O_WRONLY|O_NONBLOCK|O_CLOEXEC);
                if (writer>=0) {
                    /* An interrupted native FIFO open may close its temporary
                     * reader before restarting. Retain the writer until the
                     * application confirms its final open, then test data. */
                    while (!__atomic_load_n(&fifo_opened,__ATOMIC_ACQUIRE)) sched_yield();
                    __atomic_store_n(&fifo_writer_ready,1,__ATOMIC_RELEASE);
                    assert(write(writer,"x",1)==1); break;
                }
                assert(errno==ENXIO);
            }
            assert(!pthread_kill(thread,SIGUSR1)); sched_yield();
        }
        assert(!pthread_join(thread,NULL));
        if (writer>=0) assert(!close(writer));
        assert(!pthread_barrier_destroy(&barrier)); assert(!sigaction(SIGUSR1,&old,NULL));
    }
    assert(!unlink("signal-fifo") && descriptor_count()==before);
    puts("PASS musl FIFO signals: EINTR, SA_RESTART, completed endpoint and exact FD retirement");
}
static void descriptor_contracts(void) {
    int warm=open("marker",O_RDONLY|O_CLOEXEC); assert(warm>=0); close(warm);
    unsigned before=descriptor_count();
    for (unsigned i=0;i<64;++i) {
        int fd=open("created",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600); assert(fd>=0);
        assert(fcntl(fd,F_GETFD)==FD_CLOEXEC);
        assert(write(fd,"fd",2)==2);
        assert(open("created",O_CREAT|O_EXCL|O_RDWR,0600)==-1 && errno==EEXIST);
        struct stat st; assert(!fstat(fd,&st) && st.st_size==2);
        assert(!close(fd));
        fd=open("created",O_CREAT|O_RDWR|O_APPEND,0600); assert(fd>=0);
        assert(write(fd,"!",1)==1 && !fstat(fd,&st) && st.st_size==3 && !close(fd));
        fd=open("created",O_WRONLY|O_TRUNC); assert(fd>=0);
        assert(!fstat(fd,&st) && !st.st_size && !close(fd));
        assert(!unlink("created"));
        fd=open("marker",O_PATH|O_CLOEXEC); assert(fd>=0 && (fcntl(fd,F_GETFL)&O_PATH));
        assert(!fstat(fd,&st) && st.st_size==7); assert(!close(fd));
    }
    assert(descriptor_count()==before);
    puts("PASS musl FD: exclusive creation, CLOEXEC, O_PATH and exact descriptor retirement");
}
static void relative_contracts(void) {
    assert(!mkdir("left",0700) && !mkdir("right",0700));
    int left=open("left",O_DIRECTORY|O_RDONLY),right=open("right",O_PATH|O_DIRECTORY);
    assert(left>=0 && right>=0);
    int fd=openat(left,"leaf",O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"l",1)==1 && !close(fd));
    fd=openat(right,"leaf",O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"rr",2)==2 && !close(fd));
    int base=dup(left); assert(base>=0);
    for (unsigned i=0;i<128;++i) {
        int source=i&1 ? right : left;
        assert(dup2(source,base)==base);
        struct stat st;
        assert(!fstatat(base,"leaf",&st,0) && st.st_size==(i&1 ? 2 : 1));
        assert(!fchdir(source));
        assert(!stat("leaf",&st) && st.st_size==(i&1 ? 2 : 1));
    }
    assert(!chdir(".."));
    assert(!rename("left","moved"));
    struct stat st; assert(!fstatat(left,"leaf",&st,0) && st.st_size==1);
    assert(!unlinkat(left,"leaf",0) && !unlinkat(right,"leaf",0));
    assert(!close(left) && !close(right) && !close(base));
    assert(!rmdir("moved") && !rmdir("right"));
    puts("PASS musl paths: live dirfd replacement, cwd changes and renamed anchors");
}
static void contracts(const char *executable) {
    descriptor_contracts(); relative_contracts();
    pthread_t threads[4];
    for (unsigned i=0;i<4;++i) assert(!pthread_create(&threads[i],NULL,metadata_thread,NULL));
    for (unsigned i=0;i<4;++i) assert(!pthread_join(threads[i],NULL));
    for (unsigned i=0;i<12;++i) {
        assert(!pipe(channel)); assert(!pthread_barrier_init(&barrier,NULL,2));
        assert(!pthread_create(&threads[0],NULL,blocking_thread,NULL));
        int b=pthread_barrier_wait(&barrier); assert(!b || b==PTHREAD_BARRIER_SERIAL_THREAD);
        assert(!pthread_cancel(threads[0])); void *result=NULL;
        assert(!pthread_join(threads[0],&result) && result==PTHREAD_CANCELED);
        assert(!pthread_barrier_destroy(&barrier)); close(channel[0]); close(channel[1]);
    }
    unsigned descriptors=descriptor_count();
    assert(!mkfifo("cancel-fifo",0600));
    for (unsigned i=0;i<16;++i) {
        assert(!pthread_barrier_init(&barrier,NULL,2));
        assert(!pthread_create(&threads[0],NULL,opening_thread,NULL));
        int b=pthread_barrier_wait(&barrier); assert(!b || b==PTHREAD_BARRIER_SERIAL_THREAD);
        /* Mix cancellation before admission with a queued FIFO completion. */
        for (unsigned n=0;n<i*64;++n) sched_yield();
        assert(!pthread_cancel(threads[0])); void *result=NULL;
        assert(!pthread_join(threads[0],&result) && result==PTHREAD_CANCELED);
        assert(!pthread_barrier_destroy(&barrier));
    }
    assert(!unlink("cancel-fifo"));
    assert(descriptor_count()==descriptors);
    puts("PASS musl cancellation: FIFO open retires pending descriptors without leaks");
    fifo_signals();
    signal_abandonment();
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        metadata_thread(NULL);
        execl(executable,executable,".","exec",NULL); _exit(90);
    }
    reap(child);
    child=fork(); assert(child>=0);
    if (!child) {
        struct sock_filter instructions[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_newfstatat,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
        };
        struct sock_fprog program={sizeof(instructions)/sizeof(*instructions),instructions};
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        assert(!prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program));
        struct stat st; assert(stat("marker",&st)==-1 && errno==EACCES);
        int fd=open("marker",O_RDONLY); assert(fd>=0 && !fstat(fd,&st) && st.st_size==7); close(fd);
        fifo_signals();
        _exit(0);
    }
    reap(child);
    puts("PASS musl: real libc metadata, threads, cancellation, signal longjmp, fork/exec and seccomp");
}
int main(int argc,char **argv) {
    alarm(90); assert(argc>=3); setbuf(stdout,NULL);
    if (!strcmp(argv[2],"prepare")) {
        assert(!chown("/",0,0) && !chmod("/",0755));
        assert(!mkdir(argv[1],0755));
        return 0;
    }
    char executable[4096]; assert(realpath(argv[0],executable));
    assert(!chdir(argv[1]));
    if (!strcmp(argv[2],"exec")) { metadata_thread(NULL); return 0; }
    int fd=open("marker",O_CREAT|O_TRUNC|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"payload",7)==7); close(fd);
    if (!strcmp(argv[2],"abi")) {
        struct stat st; assert(!stat("marker",&st) && st.st_size==7);
        assert(stat("absent",&st)==-1 && errno==ENOENT);
        pthread_t thread; assert(!pthread_create(&thread,NULL,metadata_thread,NULL));
        assert(!pthread_join(thread,NULL));
        pid_t child=fork(); assert(child>=0);
        if (!child) { metadata_thread(NULL); _exit(0); }
        reap(child); assert(!unlink("marker"));
        puts("PASS musl ABI: absent provider retains metadata, native IO, threads and fork");
        return 0;
    }
    if (!strcmp(argv[2],"check")) { contracts(executable); assert(!unlink("marker")); return 0; }
    assert(argc==4); unsigned count=(unsigned)strtoul(argv[3],NULL,10); assert(count);
    char absolute[4096]; assert(realpath("marker",absolute));
    struct rusage before,after;
    assert(!getrusage(RUSAGE_SELF,&before));
    uint64_t begin=now();
    if (!strcmp(argv[2],"metadata") || !strcmp(argv[2],"metadata-absolute") || !strcmp(argv[2],"metadata-dirfd")) {
        struct stat st;
        const char *name=!strcmp(argv[2],"metadata-absolute") ? absolute : "marker";
        int base=!strcmp(argv[2],"metadata-dirfd") ? open(".",O_PATH|O_DIRECTORY) : AT_FDCWD;
        assert(base==AT_FDCWD || base>=0);
        for (unsigned i=0;i<count;++i) assert(!fstatat(base,name,&st,0) && st.st_size==7);
        if (base>=0) assert(!close(base));
    } else if (!strcmp(argv[2],"opens") || !strcmp(argv[2],"opens-cloexec")
            || !strcmp(argv[2],"opens-write") || !strcmp(argv[2],"opens-create") || !strcmp(argv[2],"opens-truncate")) {
        int flags=!strcmp(argv[2],"opens-cloexec") ? O_CLOEXEC
            : !strcmp(argv[2],"opens-write") ? O_RDWR
            : !strcmp(argv[2],"opens-create") ? O_CREAT|O_RDWR
            : !strcmp(argv[2],"opens-truncate") ? O_TRUNC|O_RDWR : O_RDONLY;
        for (unsigned i=0;i<count;++i) {
            fd=open("marker",flags,0600); assert(fd>=0); assert(!close(fd));
        }
    } else if (!strcmp(argv[2],"files") || !strcmp(argv[2],"files-create")) {
        int flags=O_CREAT|O_RDWR|O_CLOEXEC|(!strcmp(argv[2],"files") ? O_EXCL : 0);
        for (unsigned i=0;i<count;++i) {
            fd=open("created",flags,0600); assert(fd>=0); assert(!close(fd));
            assert(!rename("created","renamed")); assert(!unlink("renamed"));
        }
    } else if (!strcmp(argv[2],"native")) {
        fd=open("marker",O_RDWR); assert(fd>=0); char value[7];
        for (unsigned i=0;i<count;++i) {
            assert(pread(fd,value,7,0)==7); assert(pwrite(fd,value,7,0)==7);
        }
        close(fd);
    } else abort();
    uint64_t elapsed=now()-begin;
    assert(!getrusage(RUSAGE_SELF,&after));
    assert(!unlink("marker"));
    long user=(after.ru_utime.tv_sec-before.ru_utime.tv_sec)*1000000L+after.ru_utime.tv_usec-before.ru_utime.tv_usec;
    long system=(after.ru_stime.tv_sec-before.ru_stime.tv_sec)*1000000L+after.ru_stime.tv_usec-before.ru_stime.tv_usec;
    printf("{\"workload\":\"%s\",\"iterations\":%u,\"nanoseconds\":%llu,\"userUs\":%ld,\"systemUs\":%ld,\"voluntarySwitches\":%ld,\"involuntarySwitches\":%ld}\n",
        argv[2],count,(unsigned long long)elapsed,user,system,
        after.ru_nvcsw-before.ru_nvcsw,after.ru_nivcsw-before.ru_nivcsw);
    return 0;
}
