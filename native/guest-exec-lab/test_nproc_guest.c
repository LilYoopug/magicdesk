#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int channel[2];
static void *worker(void *unused) {
    (void)unused; char byte;
    /* EVENT_WAIT: parent releases the worker; alarm terminates a broken test. */
    assert(read(channel[0],&byte,1)==1); return NULL;
}
static void exhausted(void) { errno=0; assert(fork()==-1 && errno==EAGAIN); }
static void reaped(pid_t pid) { int status; assert(waitpid(pid,&status,0)==pid && status==0); }
static void proc_limit(unsigned long soft,unsigned long hard) {
    FILE *file=fopen("/proc/self/limits","re"); assert(file);
    char line[256]; unsigned long a,b; int seen=0;
    while (fgets(line,sizeof(line),file))
        if (sscanf(line,"Max processes %lu %lu",&a,&b)==2) {
            assert(a==soft && b==hard); seen=1;
        }
    assert(seen && !ferror(file)); fclose(file);
}
static void scenario(int protected) {
    assert(!setgid(23456) && !setuid(23456));
    if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
    struct rlimit limit={3,3}, old;
    assert(!syscall(SYS_prlimit64,0,RLIMIT_NPROC,&limit,&old));
    assert(!getrlimit(RLIMIT_NPROC,&old) && old.rlim_cur==3 && old.rlim_max==3);
    assert(!syscall(SYS_getrlimit,RLIMIT_NPROC,&old) && old.rlim_cur==3);
    proc_limit(3,3);
    assert(!pipe(channel));
    pthread_t a,b,c;
    assert(!pthread_create(&a,NULL,worker,NULL));
    assert(!pthread_create(&b,NULL,worker,NULL));
    assert(pthread_create(&c,NULL,worker,NULL)==EAGAIN);
    exhausted();
    assert(write(channel[1],"xx",2)==2);
    assert(!pthread_join(a,NULL) && !pthread_join(b,NULL));
    close(channel[0]); close(channel[1]);
    pid_t first=fork(); assert(first>=0); if (!first) _exit(0);
    pid_t second=fork(); assert(second>=0); if (!second) _exit(0);
    siginfo_t info;
    /* EVENT_WAIT: WNOWAIT proves both zombies still consume UID quota. */
    assert(!waitid(P_PID,first,&info,WEXITED|WNOWAIT));
    assert(!waitid(P_PID,second,&info,WEXITED|WNOWAIT));
    exhausted(); reaped(first);
    first=fork(); assert(first>=0); if (!first) _exit(0);
    reaped(first); reaped(second);
    limit=(struct rlimit){4,4}; errno=0;
    assert(setrlimit(RLIMIT_NPROC,&limit)==-1 && errno==EPERM);
    limit=(struct rlimit){4,3}; errno=0;
    assert(setrlimit(RLIMIT_NPROC,&limit)==-1 && errno==EINVAL);
    /* An output fault follows the limit update, matching prlimit64. */
    limit=(struct rlimit){2,3}; errno=0;
    assert(syscall(SYS_prlimit64,0,RLIMIT_NPROC,&limit,(void *)1)==-1 && errno==EFAULT);
    assert(!getrlimit(RLIMIT_NPROC,&old) && old.rlim_cur==2);
    proc_limit(2,3);
    errno=0;
    assert(syscall(SYS_setrlimit,RLIMIT_NPROC,(void *)1)==-1 && errno==EFAULT);
    assert(!getrlimit(RLIMIT_NPROC,&old) && old.rlim_cur==2);
    printf("PASS nproc guest: pthreads, fork, zombies, permissions and faults (protected=%d)\n",protected);
}
static void exec_quota(const char *program) {
    int ready[2], release[2]; assert(!pipe(ready) && !pipe(release));
    struct rlimit limit={2,2}; assert(!setrlimit(RLIMIT_NPROC,&limit));
    pid_t children[2];
    for (int i=0;i<2;++i) {
        children[i]=fork(); assert(children[i]>=0);
        if (!children[i]) {
            char byte;
            assert(!setgid(23457) && !setuid(23457));
            assert(write(ready[1],"r",1)==1);
            assert(read(release[0],&byte,1)==1); _exit(0);
        }
    }
    char byte;
    /* EVENT_WAIT: both children committed their UID before the parent's change. */
    assert(read(ready[0],&byte,1)==1 && read(ready[0],&byte,1)==1);
    assert(!setgid(23457) && !setuid(23457));
    char *const argv[]={(char *)program,"--exec-admitted",NULL};
    errno=0; execv(program,argv); assert(errno==EAGAIN);
    assert(write(release[1],"xx",2)==2);
    reaped(children[0]); reaped(children[1]);
    execv(program,argv); assert(!"exec quota remained charged after wait");
}
static void denied_limit(void) {
    struct rlimit old,after,next={1,1}; assert(!getrlimit(RLIMIT_NPROC,&old));
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prlimit64,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog filter={sizeof(code)/sizeof(code[0]),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&filter));
    errno=0; assert(syscall(SYS_prlimit64,0,RLIMIT_NPROC,&next,NULL)==-1 && errno==EPERM);
    assert(!getrlimit(RLIMIT_NPROC,&after) && after.rlim_cur==old.rlim_cur && after.rlim_max==old.rlim_max);
}
static void peer_limits(void) {
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        struct rlimit value;
        assert(!setgid(23458) && !setuid(23458));
        errno=0;
        assert(syscall(SYS_prlimit64,parent,RLIMIT_NPROC,NULL,&value)==-1 && errno==EPERM);
        _exit(0);
    }
    reaped(child);
    struct rlimit limit={8,8}, old, files;
    assert(!setrlimit(RLIMIT_NPROC,&limit));
    assert(!getrlimit(RLIMIT_NOFILE,&files));
    assert(!setgid(23458) && !setuid(23458));
    child=fork(); assert(child>=0);
    if (!child) {
        limit.rlim_cur=7;
        assert(!syscall(SYS_prlimit64,parent,RLIMIT_NPROC,&limit,&old) && old.rlim_cur==8);
        assert(!getrlimit(RLIMIT_NPROC,&old) && old.rlim_cur==8);
        errno=0;
        assert(syscall(SYS_prlimit64,2147483647,RLIMIT_NPROC,NULL,&old)==-1 && errno==ESRCH);
        _exit(0);
    }
    reaped(child);
    assert(!getrlimit(RLIMIT_NPROC,&old) && old.rlim_cur==7 && old.rlim_max==8);
    assert(!getrlimit(RLIMIT_NOFILE,&old) && old.rlim_cur==files.rlim_cur && old.rlim_max==files.rlim_max);
    proc_limit(7,8);
    puts("PASS nproc peer permissions, PID translation, fork copies and native nofile");
}
int main(int argc,char **argv) {
    if (argc==2 && !strcmp(argv[1],"--exec-admitted")) {
        assert(getuid()==23457); puts("PASS nproc exec after UID quota release"); return 0;
    }
    alarm(60);
    for (int protected=0;protected<2;++protected) {
        pid_t child=fork(); assert(child>=0);
        if (!child) { scenario(protected); fflush(stdout); _exit(0); }
        reaped(child);
    }
    pid_t child=fork(); assert(child>=0);
    if (!child) exec_quota(argv[0]);
    reaped(child);
    child=fork(); assert(child>=0);
    if (!child) { denied_limit(); _exit(0); }
    reaped(child);
    child=fork(); assert(child>=0);
    if (!child) { peer_limits(); fflush(stdout); _exit(0); }
    reaped(child);
    puts("PASS RLIMIT_NPROC");
}
