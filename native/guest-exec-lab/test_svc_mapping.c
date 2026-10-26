#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static long (*call)(void);
static unsigned number;
extern long image_uid(void);
extern long live_uid(void);
extern long live_open(long,const char *,long,long);
extern long live_unmap(void *,size_t);
extern long live_protect(void *,size_t,int);
extern long live_map(void *,size_t,int,int,int,long);
extern long live_remap(void *,size_t,size_t,int,void *);
__asm__(".pushsection .text\n.p2align 16\n.global image_uid\n"
    "image_uid:\nmov x8,#174\nsvc #0\nret\n.p2align 16\n"
    ".global live_uid\nlive_uid:\nmov x8,#174\nsvc #0\nret\n"
    ".global live_open\nlive_open:\nmov x8,#56\nsvc #0\nret\n"
    ".global live_unmap\nlive_unmap:\nmov x8,#215\nsvc #0\nret\n"
    ".global live_protect\nlive_protect:\nmov x8,#226\nsvc #0\nret\n"
    ".global live_map\nlive_map:\nmov x8,#222\nsvc #0\nret\n"
    ".global live_remap\nlive_remap:\nmov x8,#216\nsvc #0\nret\n.popsection");
static size_t unmap_page;
static volatile sig_atomic_t unmap_signals;
static void unmap_signal(int signal) {
    (void)signal;
    int saved=errno;
    void *p=mmap(NULL,unmap_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED && !live_unmap(p,1));
    ++unmap_signals;
    errno=saved;
}
static int unmap_loop(void *unused) {
    (void)unused;
    for (unsigned i=0;i<4096;++i) {
        void *p=mmap(NULL,unmap_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(p!=MAP_FAILED);
        assert(live_unmap((char *)p+1,1)==-EINVAL);
        assert(!live_unmap(p,1));
    }
    return 0;
}
static void native_unmap(void) {
    alarm(30);
    unmap_page=(size_t)sysconf(_SC_PAGESIZE);
    unmap_loop(NULL);
    struct sigaction sa={.sa_handler=unmap_signal};
    sigemptyset(&sa.sa_mask);
    assert(!sigaction(SIGALRM,&sa,NULL));
    struct itimerval timer={.it_interval={.tv_usec=1000},.it_value={.tv_usec=1000}};
    assert(!setitimer(ITIMER_REAL,&timer,NULL));
    unmap_loop(NULL);
    timer=(struct itimerval){0};
    assert(!setitimer(ITIMER_REAL,&timer,NULL) && unmap_signals>0);
    sa.sa_handler=SIG_DFL;
    assert(!sigaction(SIGALRM,&sa,NULL));
    alarm(30);
    void *p=mmap(NULL,unmap_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED);
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_munmap,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    assert(live_unmap(p,1)==-EACCES);
    *(volatile char *)p=42;
    puts("PASS SVC native unmap: rounded ranges, invalid address, signal reentry and filter revocation");
}
static void protect_loop(unsigned count) {
    void *p=mmap(NULL,unmap_page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED);
    for (unsigned i=0;i<count;++i) {
        assert(!live_protect(p,1,PROT_READ|PROT_EXEC));
        assert(!live_protect(p,1,PROT_NONE));
        /* The second page is not included by page rounding. */
        *((volatile char *)p+unmap_page)=42;
        assert(!live_protect(p,1,PROT_READ|PROT_WRITE));
        *(volatile char *)p=43;
        assert(live_protect((char *)p+1,1,PROT_READ)==-EINVAL);
        assert(live_protect(p,1,PROT_READ|PROT_GROWSDOWN)==-EINVAL);
    }
    assert(!munmap(p,unmap_page*2));
}
static void protect_signal(int signal) {
    (void)signal;
    int saved=errno;
    protect_loop(1);
    ++unmap_signals;
    errno=saved;
}
static void native_protect(void) {
    alarm(30);
    unmap_page=(size_t)sysconf(_SC_PAGESIZE);
    protect_loop(4096);
    struct sigaction sa={.sa_handler=protect_signal};
    sigemptyset(&sa.sa_mask);
    assert(!sigaction(SIGALRM,&sa,NULL));
    struct itimerval timer={.it_interval={.tv_usec=1000},.it_value={.tv_usec=1000}};
    assert(!setitimer(ITIMER_REAL,&timer,NULL));
    protect_loop(4096);
    timer=(struct itimerval){0};
    assert(!setitimer(ITIMER_REAL,&timer,NULL) && unmap_signals>0);
    sa.sa_handler=SIG_DFL;
    assert(!sigaction(SIGALRM,&sa,NULL));
    alarm(30);
    void *p=mmap(NULL,unmap_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED);
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mprotect,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    assert(live_protect(p,1,PROT_NONE)==-EACCES);
    *(volatile char *)p=44;
    assert(!munmap(p,unmap_page));
    puts("PASS SVC native protect: rounded ranges, growth fallback, signal reentry and filter revocation");
}
static void map_loop(unsigned count) {
    char *p=mmap(NULL,unmap_page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED);
    p[unmap_page]=42;
    for (unsigned i=0;i<count;++i) {
        p[0]=43;
        assert(live_map(p,1,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(long)p);
        assert(!p[0] && p[unmap_page]==42);
        assert(live_map(p+1,1,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==-EINVAL);
        assert(live_map(p,1,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,1)==-EINVAL);
    }
    assert(!munmap(p,unmap_page*2));
}
static void map_signal(int signal) {
    (void)signal;
    int saved=errno;
    map_loop(1);
    ++unmap_signals;
    errno=saved;
}
static void native_map(void) {
    alarm(30);
    unmap_page=(size_t)sysconf(_SC_PAGESIZE);
    map_loop(4096);
    struct sigaction sa={.sa_handler=map_signal};
    sigemptyset(&sa.sa_mask);
    assert(!sigaction(SIGALRM,&sa,NULL));
    struct itimerval timer={.it_interval={.tv_usec=1000},.it_value={.tv_usec=1000}};
    assert(!setitimer(ITIMER_REAL,&timer,NULL));
    map_loop(4096);
    timer=(struct itimerval){0};
    assert(!setitimer(ITIMER_REAL,&timer,NULL) && unmap_signals>0);
    sa.sa_handler=SIG_DFL;
    assert(!sigaction(SIGALRM,&sa,NULL));
    alarm(30);
    char *p=mmap(NULL,unmap_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED); *p=44;
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mmap,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    assert(live_map(p,1,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==-EACCES);
    assert(*p==44 && !munmap(p,unmap_page));
    /* stdio may allocate after mmap has deliberately been denied. */
    static const char result[]="PASS SVC native map: anonymous replacement, rounded ranges, invalid arguments, signal reentry and filter revocation\n";
    assert(write(STDOUT_FILENO,result,sizeof(result)-1)==sizeof(result)-1);
}
static void remap_loop(unsigned count) {
    char *p=mmap(NULL,unmap_page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED);
    p[0]=42;
    for (unsigned i=0;i<count;++i) {
        assert(live_remap(p,unmap_page*2,unmap_page,0,NULL)==(long)p);
        long result=live_remap(p,unmap_page,unmap_page*2,MREMAP_MAYMOVE,NULL);
        assert((unsigned long)result<(unsigned long)-4095);
        p=(char *)result;
        assert(p[0]==42 && !p[unmap_page]);
        p[unmap_page]=43;
        assert(live_remap(p+1,unmap_page,unmap_page,0,NULL)==-EINVAL);
        assert(live_remap(p,unmap_page,0,MREMAP_MAYMOVE,NULL)==-EINVAL);
    }
    assert(!munmap(p,unmap_page*2));
}
static void remap_signal(int signal) {
    (void)signal;
    int saved=errno;
    remap_loop(1);
    ++unmap_signals;
    errno=saved;
}
static void native_remap(void) {
    alarm(30);
    unmap_page=(size_t)sysconf(_SC_PAGESIZE);
    remap_loop(4096);
    struct sigaction sa={.sa_handler=remap_signal};
    sigemptyset(&sa.sa_mask);
    assert(!sigaction(SIGALRM,&sa,NULL));
    struct itimerval timer={.it_interval={.tv_usec=1000},.it_value={.tv_usec=1000}};
    assert(!setitimer(ITIMER_REAL,&timer,NULL));
    remap_loop(4096);
    timer=(struct itimerval){0};
    assert(!setitimer(ITIMER_REAL,&timer,NULL) && unmap_signals>0);
    sa.sa_handler=SIG_DFL;
    assert(!sigaction(SIGALRM,&sa,NULL));
    alarm(30);
    /* Fixed remapping must still use the owner and retain file provenance. */
    char *blocked=mmap(NULL,unmap_page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(blocked!=MAP_FAILED && !mprotect(blocked+unmap_page,unmap_page,PROT_READ|PROT_WRITE));
    blocked[unmap_page]=41;
    long moved=live_remap(blocked+unmap_page,unmap_page,unmap_page*2,MREMAP_MAYMOVE,NULL);
    assert((unsigned long)moved<(unsigned long)-4095 && moved!=(long)(blocked+unmap_page));
    assert(*(char *)moved==41);
    assert(!munmap((void *)moved,unmap_page*2) && !munmap(blocked,unmap_page*3));
    int fd=open("/proc/self/exe",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    char *file=mmap(NULL,unmap_page,PROT_READ,MAP_PRIVATE,fd,0); assert(file!=MAP_FAILED);
    char *p=mmap(NULL,unmap_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED);
    assert(live_remap(file,unmap_page,unmap_page,MREMAP_MAYMOVE|MREMAP_FIXED,p)==(long)p);
    assert(!memcmp(p,"\177ELF",4));
    assert(!mprotect(p,unmap_page,PROT_NONE));
    assert(!mprotect(p,unmap_page,PROT_READ));
    assert(!memcmp(p,"\177ELF",4));
    assert(!munmap(p,unmap_page) && !close(fd));
    p=mmap(NULL,unmap_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(p!=MAP_FAILED); *p=44;
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mremap,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    assert(live_remap(p,unmap_page,unmap_page,MREMAP_MAYMOVE,NULL)==-EACCES);
    assert(*p==44 && !munmap(p,unmap_page));
    puts("PASS SVC native remap: resize, content, fixed file fallback, signal reentry and filter revocation");
}
static void image_protection(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    void *address=(void *)((uintptr_t)image_uid&~(page-1));
    long expected=getuid();
    for (unsigned i=0;i<64;++i) assert(image_uid()==expected);
    for (unsigned i=0;i<3;++i) {
        assert(!mprotect(address,page,PROT_NONE));
        assert(!mprotect(address,page,PROT_READ|PROT_EXEC));
        assert(image_uid()==expected);
        assert(!mprotect(address,page,PROT_READ));
        assert(!mprotect(address,page,PROT_READ|PROT_EXEC));
        assert(image_uid()==expected);
    }
}
static int exercise(void *unused) {
    (void)unused;
    long expected=syscall(number);
    for (unsigned i=0;i<1024;++i) assert(call()==expected);
    return 0;
}
static void joined(pid_t child) {
    int status;
    assert(child>0 && waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
}
static atomic_uint ready, finished;
static long expected_uid;
static int protected;
static const char *image_path;
static void *racing_peer(void *unused) {
    (void)unused;
    for (unsigned i=0;i<64;++i) assert(live_uid()==expected_uid);
    atomic_fetch_add(&ready,1);
    while (!atomic_load(&finished)) {
        long result=live_uid();
        assert(result==expected_uid || result==-EACCES);
        result=live_open(AT_FDCWD,image_path,O_RDONLY,0);
        assert(result>=0 || result==-EACCES);
        if (result>=0) assert(!close((int)result));
    }
    for (unsigned i=0;i<64;++i) assert(live_uid()==(protected ? expected_uid : -EACCES));
    long result=live_open(AT_FDCWD,image_path,O_RDONLY,0);
    if (protected) { assert(result>=0); assert(!close((int)result)); }
    else assert(result==-EACCES);
    return NULL;
}
static void entry_transition_race(void) {
    for (unsigned round=0;round<24;++round) {
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            alarm(20);
            expected_uid=getuid();
            pthread_t peers[4];
            for (unsigned i=0;i<4;++i) assert(!pthread_create(&peers[i],NULL,racing_peer,NULL));
            while (atomic_load(&ready)!=4) sched_yield();
            if (protected) {
                assert(!prctl(PR_SET_DUMPABLE,0,0,0,0));
                assert(!prctl(PR_GET_DUMPABLE,0,0,0,0));
            } else {
                struct sock_filter code[]={
                    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
                    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_gettid,0,1),
                    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
                    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getuid,0,1),
                    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
                    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_openat,0,1),
                    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
                    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
                };
                struct sock_fprog program={sizeof(code)/sizeof(*code),code};
                assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
                long result=syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&program);
                if (result) fprintf(stderr,"filter race round=%u TSYNC result=%ld errno=%d\n",round,result,errno);
                assert(!result);
            }
            atomic_store(&finished,1);
            for (unsigned i=0;i<4;++i) assert(!pthread_join(peers[i],NULL));
            if (protected) {
                assert(!prctl(PR_GET_DUMPABLE,0,0,0,0));
                pid_t next=fork(); assert(next>=0);
                if (!next) {
                    assert(!prctl(PR_GET_DUMPABLE,0,0,0,0));
                    racing_peer(NULL);
                    _exit(0);
                }
                joined(next);
                assert(!prctl(PR_GET_DUMPABLE,0,0,0,0));
                /* Restore only after protected operations and fork, so the
                 * harness can read final resident-entry counters at exit. */
                assert(!prctl(PR_SET_DUMPABLE,1,0,0,0));
            }
            _exit(0);
        }
        joined(child);
    }
    puts(protected ? "PASS SVC protected race: 24 transitions, live peers and protected fork"
        : "PASS SVC filter race: 24 TSYNC installs, live peers, forbidden helper and post-filter denial");
}
int main(int argc,char **argv) {
    image_path=argv[0];
    if (argc>1 && !strcmp(argv[1],"native-unmap")) { native_unmap(); return 0; }
    if (argc>1 && !strcmp(argv[1],"native-protect")) { native_protect(); return 0; }
    if (argc>1 && !strcmp(argv[1],"native-map")) { native_map(); return 0; }
    if (argc>1 && !strcmp(argv[1],"native-remap")) { native_remap(); return 0; }
    if (argc>1 && !strcmp(argv[1],"protected-race")) { protected=1; entry_transition_race(); return 0; }
    if (argc>1 && !strcmp(argv[1],"filter-race")) { entry_transition_race(); return 0; }
    image_protection();
    pid_t image_child=fork(); assert(image_child>=0);
    if (!image_child) { image_protection(); _exit(0); }
    joined(image_child);
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uintptr_t hint=((uintptr_t)main+0x2000000)&~(page-1);
    void *code=mmap((void *)hint,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(code!=MAP_FAILED);
    void *stack=mmap(NULL,1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    call=(long (*)(void))code;
    const unsigned numbers[]={SYS_getpid,SYS_getppid,SYS_getuid,SYS_getgid};
    for (unsigned version=0;version<sizeof(numbers)/sizeof(*numbers);++version) {
        number=numbers[version];
        void *copy=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(copy!=MAP_FAILED);
        uint32_t program[]={0xd2800008|(numbers[version]<<5),0xd4000001,0xd65f03c0};
        memcpy(copy,program,sizeof(program));
        __builtin___clear_cache(copy,(char *)copy+sizeof(program));
        assert(!mprotect(copy,page,PROT_READ|PROT_EXEC));
        assert(mremap(copy,page,page,MREMAP_FIXED|MREMAP_MAYMOVE,code)==code);
        exercise(NULL);
        /* SIGCHLD selects PTRACE_EVENT_FORK even with CLONE_VM. The mm
         * owner must follow clone flags, not the ptrace event's name. */
        joined(clone(exercise,(char *)stack+1024*1024,CLONE_VM|SIGCHLD,NULL));
        pid_t child=fork(); assert(child>=0);
        if (!child) _exit(exercise(NULL));
        joined(child); exercise(NULL);
    }
    assert(!munmap(stack,1024*1024) && !munmap(code,page));
    puts("PASS SVC mapping: ELF protection, address reuse, fork copies and CLONE_VM with SIGCHLD");
}
