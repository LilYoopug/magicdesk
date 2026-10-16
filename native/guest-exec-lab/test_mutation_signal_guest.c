#define _GNU_SOURCE
#include "test_syscall_registers.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t delivered;
static void interrupted(int signal) {
    (void)signal;
    /* Bound the burst even when a nested debugger needs longer than one
     * timer period to deliver a signal. All file operations must still finish. */
    if (++delivered==4096) {
        int saved=errno;
        struct itimerval stopped={0};
        if (syscall(SYS_setitimer,ITIMER_REAL,&stopped,NULL)) _exit(122);
        errno=saved;
    }
}
int test_mutation_signal_guest(const char *root, int protected, int restart) {
    char directory[512];
    assert(snprintf(directory,sizeof(directory),"%s/md-mutation-signal-XXXXXX",root)<(int)sizeof(directory));
    assert(mkdtemp(directory));
    int native=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(native>=0);
    if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
    struct sigaction action={.sa_handler=interrupted,.sa_flags=restart ? SA_RESTART : 0};
    assert(!sigaction(SIGALRM,&action,NULL));
    sigset_t blocked,before,after;
    assert(!sigemptyset(&blocked) && !sigaddset(&blocked,SIGUSR1));
    assert(!sigprocmask(SIG_BLOCK,&blocked,&before));
    /* Periodic signals stress mutation interruption; they are not readiness
     * or settling waits. The runner deadline bounds the complete fixture. */
    struct itimerval timer={.it_interval={0,1000},.it_value={0,1000}};
    assert(!setitimer(ITIMER_REAL,&timer,NULL));
    for (unsigned i=0;i<2000;++i) {
        char path[544]; assert(snprintf(path,sizeof(path),"%s/%u",directory,i)<(int)sizeof(path));
        int fd;
        do { fd=test_open_registers(AT_FDCWD,path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600); } while (fd<0 && errno==EINTR);
        if (fd<0) { fprintf(stderr,"create %u: errno=%d signals=%d\n",i,errno,delivered); return 1; }
        assert(fcntl(fd,F_GETFD)==FD_CLOEXEC);
        ssize_t written;
        do { written=write(fd,"x",1); } while (written<0 && errno==EINTR);
        assert(written==1 && !test_syscall_registers(SYS_close,(UINT64_C(1)<<32)|(unsigned)fd,0x123,0x456,0x789));
        assert(test_syscall_registers(SYS_close,fd,0x123,0x456,0x789)==-1 && errno==EBADF);
        char renamed[552]; assert(snprintf(renamed,sizeof(renamed),"%s.moved",path)<(int)sizeof(renamed));
        int moved;
        do { moved=(int)test_syscall_registers(SYS_renameat,AT_FDCWD,(unsigned long)path,
            AT_FDCWD,(unsigned long)renamed); } while (moved<0 && errno==EINTR);
        assert(!moved);
        struct stat st; int result;
        do { result=stat(renamed,&st); } while (result<0 && errno==EINTR);
        assert(!result && st.st_size==1);
        do { result=fstat(native,&st); } while (result<0 && errno==EINTR);
        assert(!result && S_ISCHR(st.st_mode));
        do { result=(int)test_syscall_registers(SYS_unlinkat,AT_FDCWD,(unsigned long)renamed,0,0x789); }
            while (result<0 && errno==EINTR);
        if (result) fprintf(stderr,"unlink %u: result=%d errno=%d signals=%d\n",i,result,errno,delivered);
        assert(!result);
    }
    timer=(struct itimerval){0}; assert(!setitimer(ITIMER_REAL,&timer,NULL));
    assert(!sigprocmask(SIG_SETMASK,NULL,&after));
    for (int signal=1;signal<NSIG;++signal)
        assert(sigismember(&after,signal)==(signal==SIGUSR1 ? 1 : sigismember(&before,signal)));
    assert(!sigprocmask(SIG_SETMASK,&before,NULL));
    assert(delivered>0 && !rmdir(directory) && !close(native));
    printf("PASS mutation under signals: protected=%d restart=%d delivered=%d\n",protected,restart,delivered);
    return 0;
}
