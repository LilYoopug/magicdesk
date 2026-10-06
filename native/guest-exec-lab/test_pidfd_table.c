#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Native feasibility only: the pidfd is fixture infrastructure, not a proposed
 * extra descriptor in an application's table. No pathname-based FD reopening. */
struct transfer { int tid, phase, release, killed; int source[3]; };
static void wake(int *word, int value) {
    __atomic_store_n(word,value,__ATOMIC_RELEASE);
    assert(syscall(SYS_futex,word,FUTEX_WAKE,1,NULL,NULL,0)>=0);
}
static void wait_word(int *word, int value) {
    /* EVENT_WAIT: shared readiness/clear-child-tid, bounded by fixture alarm. */
    int current;
    while ((current=__atomic_load_n(word,__ATOMIC_ACQUIRE))!=value) {
        long r=syscall(SYS_futex,word,FUTEX_WAIT,current,NULL,NULL,0);
        assert(!r || (r<0 && (errno==EINTR || errno==EAGAIN)));
    }
}
static int helper(void *data) {
    struct transfer *t=data;
    /* The three consecutive sources are the only retained descriptions. */
    assert(!syscall(SYS_close_range,0,(unsigned)t->source[0]-1,0));
    assert(!syscall(SYS_close_range,(unsigned)t->source[2]+1,~0U,0));
    wake(&t->phase,1);
    wait_word(&t->release,1);
    if (t->killed) {
        struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getppid,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_THREAD),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
        };
        struct sock_fprog program={sizeof(code)/sizeof(*code),code};
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
        syscall(SYS_getppid);
        __builtin_trap();
    }
    syscall(SYS_exit,0);
    __builtin_unreachable();
}
static void exercise(const char *directory, int protected, int killed, unsigned slots) {
    struct rlimit limit; assert(!getrlimit(RLIMIT_NOFILE,&limit));
    int dumpable=prctl(PR_GET_DUMPABLE); assert(dumpable>=0);
    char path[4096]; assert(snprintf(path,sizeof(path),"%s/source",directory)>0);
    int file=open(path,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600); assert(file>=0);
    assert(write(file,"abcdef",6)==6 && lseek(file,1,SEEK_SET)==1);
    int pathfd=open(path,O_PATH|O_CLOEXEC); assert(pathfd>=0);
    int pipefd[2]; assert(!pipe2(pipefd,O_CLOEXEC|O_NONBLOCK));
    struct transfer t={.killed=killed};
    /* Reserve a contiguous private-helper input interval. */
    t.source[0]=fcntl(file,F_DUPFD_CLOEXEC,32); assert(t.source[0]>=32);
    t.source[1]=fcntl(pathfd,F_DUPFD_CLOEXEC,t.source[0]+1); assert(t.source[1]==t.source[0]+1);
    t.source[2]=fcntl(pipefd[1],F_DUPFD_CLOEXEC,t.source[1]+1); assert(t.source[2]==t.source[1]+1);
    assert(!close(pathfd) && !close(pipefd[1]) && !unlink(path));
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED && !prctl(PR_SET_DUMPABLE,protected ? 0 : 1));
    int flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID;
    int tid=clone(helper,(char *)stack+65536,flags,&t,&t.tid,NULL,&t.tid); assert(tid>0);
    wait_word(&t.phase,1);
    for (unsigned i=0;i<3;++i) assert(!close(t.source[i]));
    int pidfd=syscall(SYS_pidfd_open,tid,O_EXCL);
    if (pidfd<0) fprintf(stderr,"pidfd_open(PIDFD_THREAD): errno=%d\n",errno);
    assert(pidfd>=0 && (fcntl(pidfd,F_GETFD)&FD_CLOEXEC));
    struct rlimit reduced=limit; reduced.rlim_cur=64;
    assert(!setrlimit(RLIMIT_NOFILE,&reduced));
    int fillers[64]; unsigned filled=0; int fd;
    while ((fd=fcntl(file,F_DUPFD_CLOEXEC,0))>=0) { assert(filled<64); fillers[filled++]=fd; }
    assert(errno==EMFILE && filled>=slots);
    for (unsigned i=0;i<slots;++i) assert(!close(fillers[--filled]));
    int copied[3]={-1,-1,-1}; unsigned received=0;
    for (;received<3;++received) {
        fd=syscall(SYS_pidfd_getfd,pidfd,t.source[received],0);
        if (fd<0) { assert(received==slots && errno==EMFILE); break; }
        copied[received]=fd; assert(fcntl(fd,F_GETFD)==FD_CLOEXEC);
        if (!received) {
            char byte=0; assert(read(fd,&byte,1)==1 && byte=='b');
            assert(lseek(file,0,SEEK_CUR)==2);
        } else if (received==1) {
            struct stat a,b; assert((fcntl(fd,F_GETFL)&O_PATH) && !fstat(file,&a) && !fstat(fd,&b));
            assert(a.st_dev==b.st_dev && a.st_ino==b.st_ino);
        } else assert(write(fd,"p",1)==1);
    }
    assert(received==(slots<3 ? slots : 3));
    wake(&t.release,1); wait_word(&t.tid,0);
    struct pollfd exited={pidfd,POLLIN,0};
    /* EVENT_WAIT: clear-child-tid precedes final task exit. Await the pidfd's
     * terminal event; timeout fails instead of assuming the file table died. */
    assert(poll(&exited,1,5000)==1 && (exited.revents&POLLIN));
    if (received) { char byte; assert(read(copied[0],&byte,1)==1 && byte=='c'); }
    for (unsigned i=0;i<received;++i) assert(!close(copied[i]));
    char byte=0;
    if (received==3) assert(read(pipefd[0],&byte,1)==1 && byte=='p');
    assert(read(pipefd[0],&byte,1)==0);
    assert(!setrlimit(RLIMIT_NOFILE,&limit));
    while (filled) assert(!close(fillers[--filled]));
    assert(!close(pidfd) && !close(file) && !close(pipefd[0]));
    assert(!munmap(stack,65536) && !prctl(PR_SET_DUMPABLE,dumpable));
    printf("PASS same-group private table protected=%d killed=%d slots=%u received=%u\n",protected,killed,slots,received);
}
int main(int argc, char **argv) {
    assert(argc==2); setbuf(stdout,NULL); alarm(20);
    assert(!mkdir(argv[1],0700));
    for (int protected=0;protected<2;++protected) for (int killed=0;killed<2;++killed)
        for (unsigned slots=0;slots<=3;++slots) exercise(argv[1],protected,killed,slots);
    assert(!rmdir(argv[1]));
    puts("PASS same-group private-table pidfd feasibility");
}
