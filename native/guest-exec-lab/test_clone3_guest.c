#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc,char **argv) {
    alarm(20);
    int probe=argc==2 && !strcmp(argv[1],"--probe");
    struct clone_args args={.exit_signal=SIGCHLD};
    long child=syscall(SYS_clone3,&args,sizeof(args));
    if (!child) _exit(0);
    if (child<0) {
        int error=errno;
        printf("clone3: errno=%d (%s)\n",error,strerror(error));
        return probe ? 0 : 1;
    }
    int status;
    assert(waitpid((pid_t)child,&status,0)==child && status==0);
    puts("PASS clone3 fork/wait");
    return 0;
}
