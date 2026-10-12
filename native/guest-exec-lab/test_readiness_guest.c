#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int filter_probe(void) {
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_epoll_pwait,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,UINT_MAX,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program={sizeof(filter)/sizeof(*filter),filter};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    long result=syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&program);
    if (result) {
        printf("FAIL readiness selector admission result=%ld errno=%d\n",result,errno);
        return 1;
    }
    struct epoll_event event;
    assert(syscall(SYS_epoll_pwait,-1,&event,1,0,NULL,8)==-1 && errno==EACCES);
    int ep=epoll_create1(EPOLL_CLOEXEC); assert(ep>=0);
    assert(!syscall(SYS_epoll_pwait,ep,&event,1,0,NULL,8));
    close(ep);
    puts("PASS readiness selector admission under inherited service filters");
    return 0;
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);
    assert(argc>=2 && !strcmp(argv[1],"--filter"));
    int result=filter_probe();
    if (result || argc==2) return result;
    execv(argv[2],argv+2);
    perror("readiness exec");
    return 1;
}
