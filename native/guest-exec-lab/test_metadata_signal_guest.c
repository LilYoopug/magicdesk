#define _GNU_SOURCE
#include "namespace_broker.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/stat.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static volatile sig_atomic_t caught;
static atomic_int done;
static pthread_t reader;
static void signal_handler(int signal) { assert(signal==SIGUSR1); ++caught; }
static void *sender(void *unused) {
    (void)unused;
    while (!atomic_load(&done)) {
        assert(!pthread_kill(reader,SIGUSR1));
        sched_yield();
    }
    return NULL;
}
static void install_filter(void) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_faccessat2,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,X_OK,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOMSG),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
}
static void reads(int file,int directory,int filtered,int protected,int restart) {
    struct stat st;
    struct statx sx;
    struct statfs space;
    char value[256];
    const char *name="metadata-notification",*attribute="user.metadata";
#define P(p) ((unsigned long)(p))
    struct { int nr; unsigned long args[6]; long result; } calls[]={
        {SYS_newfstatat,{directory,P(name),P(&st),0},0},
        {SYS_fstat,{file,P(&st)},0},
        {SYS_statx,{directory,P(name),0,STATX_BASIC_STATS,P(&sx)},0},
        {SYS_readlinkat,{directory,P("metadata-notification-link"),P(value),sizeof(value)},21},
        {SYS_faccessat,{directory,P(name),R_OK},0},
        {SYS_faccessat2,{directory,P(name),R_OK,AT_EACCESS},0},
        {SYS_statfs,{P(name),P(&space)},0},
        {SYS_fstatfs,{file,P(&space)},0},
        {SYS_getxattr,{P(name),P(attribute),P(value),sizeof(value)},5},
        {SYS_lgetxattr,{P(name),P(attribute),P(value),sizeof(value)},5},
        {SYS_fgetxattr,{file,P(attribute),P(value),sizeof(value)},5},
        {SYS_listxattr,{P(name),P(value),sizeof(value)},-1},
        {SYS_llistxattr,{P(name),P(value),sizeof(value)},-1},
        {SYS_flistxattr,{file,P(value),sizeof(value)},-1}
    };
#undef P
    for (int nr=0;nr<512;++nr) if (md_broker_metadata_call(nr)) {
        unsigned found=0;
        for (unsigned i=0;i<sizeof(calls)/sizeof(*calls);++i) found+=calls[i].nr==nr;
        assert(found==1);
    }
    struct sigaction action={.sa_handler=signal_handler,.sa_flags=restart ? SA_RESTART : 0};
    sigemptyset(&action.sa_mask); assert(!sigaction(SIGUSR1,&action,NULL));
    if (filtered) install_filter();
    if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
    caught=0; atomic_store(&done,0); reader=pthread_self();
    pthread_t peer; assert(!pthread_create(&peer,NULL,sender,NULL));
    for (unsigned round=0;round<32;++round) for (unsigned i=0;i<sizeof(calls)/sizeof(*calls);++i) {
        memset(value,0xa5,sizeof(value));
        unsigned long *a=calls[i].args;
        long result=syscall(calls[i].nr,a[0],a[1],a[2],a[3],a[4],a[5]);
        if (result<0 || (calls[i].result>=0 && result!=calls[i].result))
            fprintf(stderr,"metadata nr=%d result=%ld errno=%d filtered=%d protected=%d restart=%d\n",
                calls[i].nr,result,errno,filtered,protected,restart);
        assert(result>=0 && (calls[i].result<0 || result==calls[i].result));
        if (i<2) assert(st.st_size==7);
        else if (i==2) assert(sx.stx_size==7);
        else if (i==3) assert(!memcmp(value,name,strlen(name)));
        else if (i==6 || i==7) assert(space.f_type);
        else if (i>=8 && i<=10) assert(!memcmp(value,"value",5));
        else if (i>=11) assert(memmem(value,result,attribute,strlen(attribute)+1));
        if (filtered) assert(syscall(SYS_faccessat2,directory,name,X_OK,0)==-1 && errno==ENOMSG);
    }
    atomic_store(&done,1);
    /* EVENT_WAIT: sender observes completion and joins; fixture alarm bounds failure. */
    assert(!pthread_join(peer,NULL) && caught);
    printf("PASS metadata under signals: 14 families, filtered=%d protected=%d restart=%d signals=%d\n",
        filtered,protected,restart,(int)caught);
}
int test_metadata_signal_guest(int mode) {
    assert(mode>=0 && mode<8);
    alarm(60); setbuf(stdout,NULL);
    int file=open("metadata-notification",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
    assert(file>=0 && write(file,"payload",7)==7);
    assert(!setxattr("metadata-notification","user.metadata","value",5,0));
    assert(!symlink("metadata-notification","metadata-notification-link"));
    int directory=open(".",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(directory>=0);
    {
        pid_t child=fork(); assert(child>=0);
        if (!child) { alarm(60); reads(file,directory,mode&1,!!(mode&2),!!(mode&4)); _exit(0); }
        int status; assert(waitpid(child,&status,0)==child);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) fprintf(stderr,"metadata child mode=%d status=%#x\n",mode,status);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    assert(!close(file) && !close(directory));
    assert(!unlink("metadata-notification") && !unlink("metadata-notification-link"));
    return 0;
}
