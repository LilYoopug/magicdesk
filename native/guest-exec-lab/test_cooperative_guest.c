#define _GNU_SOURCE
#include "cooperative_entry.h"
#include "../shroot/src/cooperative_channel.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/stat.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/utsname.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const struct md_entry_api *api;
static struct md_entry_client client;
static const char *path="/tmp/cooperative-file";
static unsigned direct_calls, fallback_calls;
static enum md_entry_outcome stat_try(struct md_entry_client *c,struct stat *st,long *result) {
    struct md_entry_call call={.number=SYS_newfstatat,.args={AT_FDCWD,(uintptr_t)path,(uintptr_t)st,0}};
    enum md_entry_outcome outcome=api->try_syscall(c,&call);
    *result=call.result; return outcome;
}
static long call6(int nr,unsigned long a,unsigned long b,unsigned long c,unsigned long d,unsigned long e,unsigned long f) {
    struct md_entry_call call={.number=nr,.args={a,b,c,d,e,f}};
    enum md_entry_outcome outcome=api->try_syscall(&client,&call);
    assert(outcome!=MD_ENTRY_UNKNOWN);
    if (outcome==MD_ENTRY_COMPLETED) { ++direct_calls; return call.result; }
    ++fallback_calls;
    long result=syscall(nr,a,b,c,d,e,f);
    return result<0 ? -errno : result;
}
static void reap(pid_t child) {
    int status;
    while (waitpid(child,&status,0)<0) assert(errno==EINTR);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) fprintf(stderr,"child status=%#x\n",status);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
}
static void filter(unsigned flags) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_newfstatat,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_gettid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={sizeof(code)/sizeof(*code),code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,flags,&program));
}
static pthread_barrier_t filter_barrier;
static void barrier(pthread_barrier_t *value) {
    int result=pthread_barrier_wait(value); assert(!result || result==PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *filtered_peer(void *unused) {
    (void)unused;
    struct md_entry_client local={0},fresh={0}; struct stat st; long result;
    assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && !result);
    barrier(&filter_barrier); barrier(&filter_barrier);
    assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && result==-EACCES);
    assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && result==-EACCES);
    assert((fresh.opaque[MD_ENTRY_CLIENT_CONTROL]>>1)==UINT32_MAX);
    assert(syscall(SYS_newfstatat,AT_FDCWD,path,&st,0)==-1 && errno==EACCES);
    return NULL;
}
static void filters(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client fresh={0}; struct stat st; long result;
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
        pthread_t peer;
        assert(!pthread_barrier_init(&filter_barrier,NULL,2));
        assert(!pthread_create(&peer,NULL,filtered_peer,NULL)); barrier(&filter_barrier);
        filter(SECCOMP_FILTER_FLAG_TSYNC);
        barrier(&filter_barrier);
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && result==-EACCES);
        assert(syscall(SYS_newfstatat,AT_FDCWD,path,&st,0)==-1 && errno==EACCES);
        assert(!pthread_join(peer,NULL));
        _exit(0);
    }
    reap(child); puts("PASS cooperative entry: TSYNC peer/fresh clients use kernel admission without forbidden helper syscalls");
}
static long required_call(struct md_entry_client *local,int nr,const uint64_t args[6]) {
    struct md_entry_call call={.number=nr};
    memcpy(call.args,args,sizeof(call.args));
    assert(api->try_syscall(local,&call)==MD_ENTRY_COMPLETED);
    return call.result;
}
static unsigned live_descriptors(void) {
    DIR *directory=opendir("/proc/self/fd"); assert(directory);
    unsigned count=0; struct dirent *entry;
    while ((entry=readdir(directory))) if (entry->d_name[0]!='.') ++count;
    assert(!closedir(directory)); return count;
}
static pthread_barrier_t native_barrier;
static struct md_entry_client *native_client;
static int native_action, native_checks;
static void native_signal(int number) { (void)number; }
static long native_checkpoint(long number,const uint64_t *args) {
    struct md_entry_channel *channel=(void *)native_client->opaque[MD_ENTRY_CLIENT_CHANNEL];
    if (number==SYS_futex && channel && atomic_load(&channel->state)==MD_ENTRY_NATIVE) {
        assert(atomic_load(&channel->native.state)==MD_NATIVE_READY); ++native_checks;
        if (native_action==1) assert(!raise(SIGUSR2));
        else if (native_action==2) { barrier(&native_barrier); barrier(&native_barrier); }
        else if (native_action==3) _exit(0);
    }
    long result=syscall(number,args[0],args[1],args[2],args[3],args[4],args[5]);
    return result<0 ? -errno : result;
}
static void *replace_pinned_file(void *unused) {
    (void)unused;
    struct md_entry_client local={0}; struct stat st; long result;
    assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && !result);
    barrier(&native_barrier);
    /* Absolute worker mutations do not borrow the opener's file-table turn.
     * This checkpoint deliberately holds that turn before the native effect. */
    assert(!required_call(&local,SYS_renameat2,(uint64_t[]){AT_FDCWD,(uintptr_t)"/tmp/entry-pinned",
        AT_FDCWD,(uintptr_t)"/tmp/entry-old",0,0}));
    assert(!required_call(&local,SYS_renameat2,(uint64_t[]){AT_FDCWD,(uintptr_t)"/tmp/entry-replacement",
        AT_FDCWD,(uintptr_t)"/tmp/entry-pinned",0,0}));
    assert(!required_call(&local,SYS_unlinkat,(uint64_t[]){AT_FDCWD,(uintptr_t)"/tmp/entry-old",0,0,0,0}));
    barrier(&native_barrier); return NULL;
}
static void native_descriptors(void) {
    unsigned before=live_descriptors();
    int descriptors[192];
    for (unsigned i=0;i<192;++i) {
        int fd=required_call(&client,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)path,O_RDONLY|O_CLOEXEC,0,0,0});
        assert(fd>=0); descriptors[i]=fd;
        assert(required_call(&client,SYS_fcntl,(uint64_t[]){fd,F_GETFD,0,0,0,0})==FD_CLOEXEC);
        assert(!required_call(&client,SYS_fcntl,(uint64_t[]){fd,F_SETFD,0,0,0,0}));
        assert(fcntl(fd,F_GETFD)==0);
        assert(!required_call(&client,SYS_fcntl,(uint64_t[]){fd,F_SETFD,FD_CLOEXEC,0,0,0}));
        assert(fcntl(fd,F_GETFD)==FD_CLOEXEC);
    }
    for (unsigned i=0;i<192;++i) {
        int fd=descriptors[i],copy=fcntl(fd,F_DUPFD_CLOEXEC,512); assert(copy>=512);
        struct stat st; assert(!fstat(copy,&st) && st.st_size==7);
        assert(!required_call(&client,SYS_close,(uint64_t[]){fd,0,0,0,0,0}));
        assert(required_call(&client,SYS_close,(uint64_t[]){fd,0,0,0,0,0})==-EBADF);
        assert(!syscall(SYS_close_range,copy,copy,0));
    }
    assert(live_descriptors()==before);
    int watch=inotify_init1(IN_CLOEXEC|IN_NONBLOCK); assert(watch>=0);
    assert(inotify_add_watch(watch,path,IN_OPEN|IN_CLOSE_NOWRITE)>0);
    int watched=required_call(&client,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)path,O_RDONLY,0,0,0});
    assert(watched>=0 && !required_call(&client,SYS_close,(uint64_t[]){watched,0,0,0,0,0}));
    char events[1024] __attribute__((aligned(8))); ssize_t bytes=read(watch,events,sizeof(events));
    assert(bytes>0); unsigned opens=0,closes=0;
    for (size_t at=0;at<(size_t)bytes;) {
        struct inotify_event *e=(void *)(events+at);
        opens+=!!(e->mask&IN_OPEN); closes+=!!(e->mask&IN_CLOSE_NOWRITE);
        at+=sizeof(*e)+e->len;
    }
    assert(opens==1 && closes==1);
    assert(read(watch,events,sizeof(events))==-1 && errno==EAGAIN && !close(watch));
    puts("PASS native FD watches: exactly one open and one close event");
    const char *writable="/tmp/entry-writable";
    int initial=open(writable,O_CREAT|O_EXCL|O_RDWR,0600); assert(initial>=0);
    assert(write(initial,"old",3)==3 && !close(initial));
    watch=inotify_init1(IN_CLOEXEC|IN_NONBLOCK); assert(watch>=0);
    assert(inotify_add_watch(watch,writable,IN_OPEN|IN_CLOSE_WRITE|IN_MODIFY)>0);
    int writer=required_call(&client,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)writable,O_RDWR|O_APPEND|O_CREAT,0600,0,0});
    assert(writer>=0 && (fcntl(writer,F_GETFL)&(O_ACCMODE|O_APPEND))==(O_RDWR|O_APPEND));
    assert(write(writer,"!",1)==1);
    assert(!required_call(&client,SYS_close,(uint64_t[]){writer,0,0,0,0,0}));
    bytes=read(watch,events,sizeof(events)); assert(bytes>0); opens=closes=0;
    unsigned modifications=0;
    for (size_t at=0;at<(size_t)bytes;) {
        struct inotify_event *e=(void *)(events+at);
        opens+=!!(e->mask&IN_OPEN); closes+=!!(e->mask&IN_CLOSE_WRITE);
        modifications+=!!(e->mask&IN_MODIFY); at+=sizeof(*e)+e->len;
    }
    assert(opens==1 && closes==1 && modifications==1);
    assert(read(watch,events,sizeof(events))==-1 && errno==EAGAIN && !close(watch));
    writer=required_call(&client,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)writable,O_WRONLY|O_TRUNC,0,0,0});
    struct stat truncated; assert(writer>=0 && !fstat(writer,&truncated) && !truncated.st_size);
    assert(!required_call(&client,SYS_close,(uint64_t[]){writer,0,0,0,0,0}));
    struct sigaction action={.sa_handler=native_signal}; sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR2,&action,NULL));
    native_client=&client; native_action=1;
    struct md_entry_call call={.number=SYS_openat,.args={AT_FDCWD,(uintptr_t)path,O_RDONLY|O_CLOEXEC},.kernel=native_checkpoint};
    assert(api->try_syscall(&client,&call)==MD_ENTRY_COMPLETED && call.result==-EINTR);
    assert(native_checks==1 && live_descriptors()==before);
    initial=open(writable,O_WRONLY); assert(initial>=0 && write(initial,"preserved",9)==9 && !close(initial));
    call.args[1]=(uintptr_t)writable; call.args[2]=O_WRONLY|O_TRUNC;
    assert(api->try_syscall(&client,&call)==MD_ENTRY_COMPLETED && call.result==-EINTR);
    assert(!stat(writable,&truncated) && truncated.st_size==9);
    assert(live_descriptors()==before && !unlink(writable));
    writer=required_call(&client,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)writable,O_CREAT|O_RDWR|O_TRUNC,0600,0,0});
    assert(writer>=0 && !fstat(writer,&truncated) && truncated.st_size==0);
    assert(write(writer,"created",7)==7);
    assert(!required_call(&client,SYS_close,(uint64_t[]){writer,0,0,0,0,0}));
    assert(!stat(writable,&truncated) && truncated.st_size==7 && !unlink(writable));
    call.args[2]=O_RDONLY|O_CLOEXEC;
    puts("PASS native writable plans: append flags, exact watch effects, truncate and pre-effect cancellation");
    int fd=open("/tmp/entry-pinned",O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"old",3)==3 && !close(fd));
    fd=open("/tmp/entry-replacement",O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"replacement",11)==11 && !close(fd));
    assert(!pthread_barrier_init(&native_barrier,NULL,2)); pthread_t peer;
    assert(!pthread_create(&peer,NULL,replace_pinned_file,NULL));
    native_action=2; call.args[1]=(uintptr_t)"/tmp/entry-pinned";
    assert(api->try_syscall(&client,&call)==MD_ENTRY_COMPLETED && call.result>=0);
    fd=(int)call.result; char data[4]={0}; struct stat st;
    assert(read(fd,data,3)==3 && !strcmp(data,"old"));
    assert(!fstat(fd,&st) && st.st_size==3);
    assert(!required_call(&client,SYS_close,(uint64_t[]){fd,0,0,0,0,0}));
    assert(!pthread_join(peer,NULL) && !pthread_barrier_destroy(&native_barrier));
    assert(!unlink("/tmp/entry-pinned"));
    for (unsigned i=0;i<8;++i) {
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            struct md_entry_client local={0}; native_client=&local; native_action=3;
            call.args[1]=(uintptr_t)path;
            api->try_syscall(&local,&call); _exit(90);
        }
        reap(child);
    }
    assert(live_descriptors()==before);
    puts("PASS native FD plans: 192 live opens, flags, dup, close_range, signal cancellation, replaced/unlinked pin and terminal retirement");
}
static void task_completion(void) {
    struct md_entry_client *local=&client;
    struct utsname names;
    assert(!required_call(local,SYS_uname,(uint64_t[]){(uintptr_t)&names,0,0,0,0,0}));
    assert(!strcmp(names.sysname,"Linux"));
    assert(required_call(local,SYS_getuid,(uint64_t[6]){0})==0);
    int pair[2];
    assert(!required_call(local,SYS_pipe2,(uint64_t[]){(uintptr_t)pair,O_CLOEXEC,0,0,0,0}));
    assert(fcntl(pair[0],F_GETFD)==FD_CLOEXEC && fcntl(pair[1],F_GETFD)==FD_CLOEXEC);
    assert(write(pair[1],"p",1)==1); char value;
    assert(read(pair[0],&value,1)==1 && value=='p'); close(pair[0]); close(pair[1]);
    assert(!required_call(local,SYS_socketpair,(uint64_t[]){AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,(uintptr_t)pair,0,0}));
    assert(write(pair[1],"s",1)==1 && read(pair[0],&value,1)==1 && value=='s');
    close(pair[0]); close(pair[1]);
    int fd=required_call(local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)path,O_PATH|O_CLOEXEC,0,0,0});
    assert(fd>=0 && (fcntl(fd,F_GETFL)&O_PATH) && fcntl(fd,F_GETFD)==FD_CLOEXEC);
    struct stat st; assert(!fstat(fd,&st) && st.st_size==7); close(fd);
    for (unsigned i=0;i<64;++i) {
        fd=required_call(local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)"/tmp/entry-once",O_CREAT|O_EXCL|O_RDWR,0600,0,0});
        assert(fd>=0); close(fd);
        assert(required_call(local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)"/tmp/entry-once",O_CREAT|O_EXCL|O_RDWR,0600,0,0})==-EEXIST);
        assert(!unlink("/tmp/entry-once"));
    }
    assert(local->opaque[MD_ENTRY_CLIENT_CHANNEL]);
    fd=required_call(local,SYS_fsopen,(uint64_t[]){(uintptr_t)"tmpfs",1,0,0,0,0});
    assert(fd>=0 && fcntl(fd,F_GETFD)==FD_CLOEXEC); close(fd);
    assert(required_call(local,SYS_fsopen,(uint64_t[]){(uintptr_t)"tmpfs",2,0,0,0,0})==-EINVAL);
    puts("PASS cooperative entry: task completion shares FD, O_PATH, pipe, socket, identity and UTS owners; fsopen custody");
}
static void create_admission(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client local={0};
        native_client=&local; native_action=0; native_checks=0;
        const char *name="/tmp/entry-create-probe";
        struct md_entry_call call={.number=SYS_openat,
            .args={AT_FDCWD,(uintptr_t)name,O_CREAT|O_RDWR,0600},.kernel=native_checkpoint};
        assert(api->try_syscall(&local,&call)==MD_ENTRY_COMPLETED && call.result>=0);
        assert(!close(call.result) && !native_checks);
        struct md_entry_channel *channel=(void *)local.opaque[MD_ENTRY_CLIENT_CHANNEL];
        assert(channel && channel->create_cooldown==128);
        mode_t expected=0;
        call.args[3]=0666;
        for (unsigned i=0;i<128;++i) {
            /* Alternate real births and existing names: the hint cannot return
             * a cached ENOENT, skip creation, or suppress later discovery. */
            mode_t mask=(i&2) ? 0077 : 0022;
            umask(mask);
            if (!(i&1)) { assert(!unlink(name)); expected=0666&~mask; }
            assert(api->try_syscall(&local,&call)==MD_ENTRY_COMPLETED && call.result>=0);
            struct stat st; assert(!fstat(call.result,&st) && (st.st_mode&0777)==expected);
            assert(write(call.result,"x",1)==1 && !close(call.result));
            assert(channel->create_cooldown==127-i && !native_checks);
        }
        assert(api->try_syscall(&local,&call)==MD_ENTRY_COMPLETED && call.result>=0);
        assert(!close(call.result) && native_checks==1);
        assert(!unlink(name));
        assert(api->try_syscall(&local,&call)==MD_ENTRY_COMPLETED && call.result>=0);
        assert(!close(call.result) && channel->create_cooldown==128);
        call.args[2]=O_RDONLY;
        assert(api->try_syscall(&local,&call)==MD_ENTRY_COMPLETED && call.result>=0);
        assert(!close(call.result) && native_checks==2 && channel->create_cooldown==128);
        assert(!unlink(name)); _exit(0);
    }
    reap(child);
    puts("PASS native create admission: bounded miss backoff, live umask, fresh birth/existing effects, resampling and independent readonly plans");
}
static void native_open_exhaustion(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client local={0};
        const char *name="/tmp/entry-emfile";
        int source=open(name,O_CREAT|O_EXCL|O_RDWR,0600);
        assert(source>=0 && write(source,"preserved",9)==9);
        struct stat st; long result;
        assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && !result);
        struct rlimit limit; assert(!getrlimit(RLIMIT_NOFILE,&limit) && limit.rlim_cur>=128);
        limit.rlim_cur=128; assert(!setrlimit(RLIMIT_NOFILE,&limit));
        int fillers[128],count=0;
        for (;;) {
            int fd=fcntl(source,F_DUPFD_CLOEXEC,0);
            if (fd<0) { assert(errno==EMFILE); break; }
            assert(count<128); fillers[count++]=fd;
        }
        assert(required_call(&local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)name,O_WRONLY|O_TRUNC,0,0,0})==-EMFILE);
        assert(!fstat(source,&st) && st.st_size==9);
        while (count) assert(!close(fillers[--count]));
        int fd=required_call(&local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)name,O_WRONLY|O_TRUNC,0,0,0});
        assert(fd>=0 && !fstat(source,&st) && !st.st_size);
        assert(!close(fd) && !close(source) && !unlink(name)); _exit(0);
    }
    reap(child);
    puts("PASS native open exhaustion: EMFILE precedes truncate; freed descriptor capacity admits a fresh effect");
}
static void filter_arguments(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client local={0}; struct stat st; long result;
        assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && !result);
        struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_openat,0,3),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
            BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,O_TRUNC,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
        };
        struct sock_fprog program={sizeof(code)/sizeof(*code),code};
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
        assert(required_call(&local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)path,O_RDWR|O_TRUNC,0,0,0})==-EACCES);
        assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && !result && st.st_size==7);
        int fd=required_call(&local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)path,O_RDONLY,0,0,0});
        assert(fd>=0); char content[8]={0}; assert(read(fd,content,7)==7 && !strcmp(content,"payload")); close(fd);
        _exit(0);
    }
    reap(child); puts("PASS cooperative entry: seccomp argument denial precedes mutation; allowed metadata/open still complete");
}
extern char entry_test_kernel_return[];
__attribute__((noinline)) static long caller_kernel(long number,const uint64_t *args) {
    register long x8 __asm__("x8")=number;
    register long x0 __asm__("x0")=args[0], x1 __asm__("x1")=args[1], x2 __asm__("x2")=args[2];
    register long x3 __asm__("x3")=args[3], x4 __asm__("x4")=args[4], x5 __asm__("x5")=args[5];
    __asm__ volatile("svc 0\n.global entry_test_kernel_return\nentry_test_kernel_return:"
        : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5) : "memory","cc");
    return x0;
}
static void filter_instruction(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        uintptr_t site=(uintptr_t)entry_test_kernel_return;
        struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getuid,0,4),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(site>>32),0,3),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)site,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES)
        };
        struct sock_fprog program={sizeof(code)/sizeof(*code),code};
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
        struct md_entry_client local={0};
        struct md_entry_call call={.number=SYS_getuid,.kernel=caller_kernel};
        assert(api->try_syscall(&local,&call)==MD_ENTRY_COMPLETED && !call.result);
        assert(syscall(SYS_getuid)==-1 && errno==EACCES);
        _exit(0);
    }
    reap(child); puts("PASS cooperative entry: kernel filters see the caller-owned instruction site");
}
static pthread_barrier_t capacity_barrier;
static atomic_uint capacity_completed,capacity_declined;
static void *capacity_peer(void *unused) {
    (void)unused;
    struct md_entry_client local={0}; struct stat st; long result;
    enum md_entry_outcome outcome=stat_try(&local,&st,&result);
    assert(outcome!=MD_ENTRY_UNKNOWN);
    assert(outcome==MD_ENTRY_COMPLETED && !result);
    if (local.opaque[MD_ENTRY_CLIENT_CHANNEL]) atomic_fetch_add(&capacity_completed,1);
    else atomic_fetch_add(&capacity_declined,1);
    barrier(&capacity_barrier); return NULL;
}
static void capacity(void) {
    pthread_t peers[16];
    for (unsigned wave=0;wave<2;++wave) {
        atomic_store(&capacity_completed,0); atomic_store(&capacity_declined,0);
        assert(!pthread_barrier_init(&capacity_barrier,NULL,17));
        for (unsigned i=0;i<16;++i) assert(!pthread_create(&peers[i],NULL,capacity_peer,NULL));
        barrier(&capacity_barrier);
        for (unsigned i=0;i<16;++i) assert(!pthread_join(peers[i],NULL));
        assert(!pthread_barrier_destroy(&capacity_barrier));
        assert(atomic_load(&capacity_completed)==7 && atomic_load(&capacity_declined)==9);
    }
    puts("PASS cooperative entry: bounded channel exhaustion falls back; exited threads release all seven borrowed slots");
}
static void *threaded(void *unused) {
    (void)unused;
    struct md_entry_client local={0}; struct stat st; long result;
    char directory[80],renamed[80];
    snprintf(directory,sizeof(directory),"tmp/entry-mutate-%ld",syscall(SYS_gettid));
    snprintf(renamed,sizeof(renamed),"%s-moved",directory);
    for (unsigned i=0;i<200;++i) {
        enum md_entry_outcome outcome=stat_try(&local,&st,&result);
        assert(outcome==MD_ENTRY_COMPLETED && !result && st.st_size==7);
        int fd=required_call(&local,SYS_openat,(uint64_t[]){AT_FDCWD,(uintptr_t)path,O_RDONLY|O_CLOEXEC,0,0,0});
        assert(fd>=0 && !fstat(fd,&st) && st.st_size==7);
        assert(!required_call(&local,SYS_close,(uint64_t[]){fd,0,0,0,0,0}));
        if (!(i%8)) {
            /* Relative mutations queue on the same table as peers' native
             * effects. A ready waiter must close any retained read window. */
            assert(!required_call(&local,SYS_mkdirat,(uint64_t[]){AT_FDCWD,(uintptr_t)directory,0700,0,0,0}));
            assert(!required_call(&local,SYS_renameat2,(uint64_t[]){AT_FDCWD,(uintptr_t)directory,AT_FDCWD,(uintptr_t)renamed,0,0}));
            long result=required_call(&local,SYS_unlinkat,(uint64_t[]){AT_FDCWD,(uintptr_t)renamed,AT_REMOVEDIR,0,0,0});
            if (result) fprintf(stderr,"queued mutation result=%ld path=%s\n",result,renamed);
            assert(!result);
        }
    }
    return NULL;
}
static volatile sig_atomic_t signals;
static volatile sig_atomic_t strict_reentry;
static void handler(int signal) {
    (void)signal;
    struct stat st; long result;
    enum md_entry_outcome outcome=stat_try(&client,&st,&result);
    assert(outcome!=MD_ENTRY_UNKNOWN);
    if (strict_reentry) assert(outcome==MD_ENTRY_DECLINED);
    if (outcome==MD_ENTRY_DECLINED) assert(!stat(path,&st));
    else assert(!result);
    ++signals;
}
static atomic_int signalling;
static pthread_t signal_target;
static void *signal_peer(void *unused) {
    (void)unused;
    for (unsigned i=0;i<1000 && atomic_load(&signalling);++i) {
        assert(!pthread_kill(signal_target,SIGUSR1)); sched_yield();
    }
    return NULL;
}
static void interrupted(void) {
    pthread_t peer; signal_target=pthread_self(); atomic_store(&signalling,1);
    assert(!pthread_create(&peer,NULL,signal_peer,NULL));
    for (unsigned i=0;i<1000;++i) {
        struct stat st; long result;
        assert(stat_try(&client,&st,&result)==MD_ENTRY_COMPLETED && !result && st.st_size==7);
    }
    atomic_store(&signalling,0); assert(!pthread_join(peer,NULL)); assert(signals>1);
    puts("PASS cooperative entry: in-flight signals, nested native fallback and original stack/output ownership");
}
static sigjmp_buf escape;
static volatile sig_atomic_t escape_armed;
static atomic_int escape_running;
static void escape_handler(int signal) {
    (void)signal;
    if (escape_armed) siglongjmp(escape,1);
}
static void *escape_sender(void *unused) {
    (void)unused;
    while (atomic_load(&escape_running)) {
        assert(!pthread_kill(signal_target,SIGUSR2)); sched_yield();
    }
    return NULL;
}
static void abandoned_memory(void) {
    for (unsigned wave=0;wave<16;++wave) {
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            struct sigaction action={.sa_handler=escape_handler}; sigemptyset(&action.sa_mask);
            assert(!sigaction(SIGUSR2,&action,NULL));
            void *memory=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            assert(memory!=MAP_FAILED);
            client=(struct md_entry_client){0};
            pthread_t peer; signal_target=pthread_self(); atomic_store(&escape_running,1);
            assert(!pthread_create(&peer,NULL,escape_sender,NULL));
            if (!sigsetjmp(escape,1)) {
                escape_armed=1;
                for (;;) {
                    long result;
                    assert(stat_try(&client,memory,&result)==MD_ENTRY_COMPLETED && !result);
                }
            }
            escape_armed=0; atomic_store(&escape_running,0);
            memset(memory,0xa5,4096);
            assert(!pthread_join(peer,NULL));
            struct md_entry_client fresh={0}; struct stat st; long result;
            for (unsigned i=0;i<128;++i)
                assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
            for (unsigned i=0;i<4096;++i) assert(((unsigned char *)memory)[i]==0xa5);
            assert(!munmap(memory,4096)); _exit(0);
        }
        reap(child);
    }
    puts("PASS cooperative entry: signal longjmp releases output ownership before caller memory reuse");
}
static void context_changes(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client fresh={0}; struct stat st; long result;
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
        assert(!unshare(CLONE_NEWNS));
        assert(!mkdir("/tmp/cooperative-view",0700));
        assert(!mount("/tmp","/tmp/cooperative-view",NULL,MS_BIND,NULL));
        path="/tmp/cooperative-view/cooperative-file";
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result && st.st_size==7);
        assert(!umount("/tmp/cooperative-view") && !rmdir("/tmp/cooperative-view"));
        assert(!chdir("/tmp") && !chroot(".")); path="/cooperative-file";
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result && st.st_size==7);
        assert(!stat(path,&st) && st.st_size==7);
        path="/bin/probe";
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && result==-ENOENT);
        _exit(0);
    }
    reap(child);
    child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client fresh={0}; struct stat st; long result;
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
        assert(!ptrace(PTRACE_TRACEME,0,NULL,NULL)); raise(SIGSTOP);
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result && !stat(path,&st));
        struct md_entry_client traced={0};
        assert(stat_try(&traced,&st,&result)==MD_ENTRY_COMPLETED && !result && !stat(path,&st)); _exit(0);
    }
    int status; assert(waitpid(child,&status,0)==child && WIFSTOPPED(status));
    assert(!ptrace(PTRACE_CONT,child,NULL,NULL)); reap(child);
    puts("PASS cooperative entry: private mount views, restricted root and debugger use the shared ownership/dispatch policy");
}
static void credentials(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client fresh={0}; struct stat st; long result;
        assert(!mkdir("/tmp/cooperative-private",0700)); path="/tmp/cooperative-private/.";
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
        assert(!seteuid(1000));
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && result==-EACCES);
        assert(!seteuid(0));
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
        assert(!rmdir("/tmp/cooperative-private")); _exit(0);
    }
    reap(child); puts("PASS cooperative entry: identity changes recheck directory permissions inside reused channels");
}
static void pid_namespace(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!unshare(CLONE_NEWPID));
        pid_t init=fork(); assert(init>=0);
        if (!init) {
            assert(getpid()==1 && syscall(SYS_gettid)==1);
            struct md_entry_client fresh={0}; struct stat st; long result;
            for (unsigned i=0;i<100;++i)
                assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result && st.st_size==7);
            _exit(0);
        }
        reap(init); _exit(0);
    }
    reap(child); puts("PASS cooperative entry: private PID 1 retains authenticated native thread identity across requests");
}
static void landlocked(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct md_entry_client fresh={0}; struct stat st; long result;
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
        struct landlock_ruleset_attr rule={.handled_access_fs=LANDLOCK_ACCESS_FS_READ_FILE};
        int set=syscall(SYS_landlock_create_ruleset,&rule,sizeof(rule),0); assert(set>=0);
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        assert(!syscall(SYS_landlock_restrict_self,set,0) && !close(set));
        /* Landlock restricts opening file data, not stat metadata. Both entry
         * routes must preserve that distinction after the domain changes. */
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result && st.st_size==7);
        assert(call6(SYS_openat,AT_FDCWD,(uintptr_t)path,O_RDONLY,0,0,0)==-EACCES);
        _exit(0);
    }
    reap(child); puts("PASS cooperative entry: Landlock keeps direct metadata and rejects file-data fallback");
}
static pthread_barrier_t teardown_barrier;
static void *teardown_peer(void *unused) {
    (void)unused;
    struct md_entry_client local={0}; struct stat st; long result;
    assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && !result);
    barrier(&teardown_barrier);
    for (;;) assert(stat_try(&local,&st,&result)==MD_ENTRY_COMPLETED && !result);
    return NULL;
}
static void teardown(void) {
    for (unsigned i=0;i<16;++i) {
        int ready[2]; assert(!pipe2(ready,O_CLOEXEC));
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            assert(!close(ready[0]));
            pthread_t peers[2];
            assert(!pthread_barrier_init(&teardown_barrier,NULL,3));
            for (unsigned j=0;j<2;++j) assert(!pthread_create(&peers[j],NULL,teardown_peer,NULL));
            barrier(&teardown_barrier);
            assert(write(ready[1],"r",1)==1);
            if (i%2) _exit(0);
            for (;;) pause();
        }
        assert(!close(ready[1]));
        char byte; ssize_t n;
        do { n=read(ready[0],&byte,1); } while (n<0 && errno==EINTR);
        assert(n==1 && byte=='r' && !close(ready[0]));
        if (i%2) reap(child);
        else {
            assert(!kill(child,SIGKILL));
            int status; pid_t waited;
            do { waited=waitpid(child,&status,0); } while (waited<0 && errno==EINTR);
            assert(waited==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
        }
        struct stat st; long result;
        assert(stat_try(&client,&st,&result)==MD_ENTRY_COMPLETED && !result);
    }
    puts("PASS cooperative entry: SIGKILL/exit_group retire active peers without leaking channel slots or stopping the owner");
}
static long direct6(int nr,unsigned long a,unsigned long b,unsigned long c,unsigned long d,unsigned long e,unsigned long f) {
    struct md_entry_call call={.number=nr,.args={a,b,c,d,e,f}};
    assert(api->try_syscall(&client,&call)==MD_ENTRY_COMPLETED);
    ++direct_calls; return call.result;
}
static void filesystem_operations(void) {
    const char *directory="/tmp/cooperative-directory", *moved="/tmp/cooperative-moved";
    assert(!direct6(SYS_mkdirat,AT_FDCWD,(uintptr_t)directory,0700,0,0,0));
    assert(direct6(SYS_mkdirat,AT_FDCWD,(uintptr_t)directory,0700,0,0,0)==-EEXIST);
    int base=open(directory,O_DIRECTORY|O_RDONLY|O_CLOEXEC); assert(base>=0);
    assert(!direct6(SYS_linkat,AT_FDCWD,(uintptr_t)path,base,(uintptr_t)"linked",0,0));
    assert(!direct6(SYS_symlinkat,(uintptr_t)"linked",base,(uintptr_t)"symlink",0,0,0));
    struct statx sx;
    assert(!direct6(SYS_statx,base,(uintptr_t)"linked",0,STATX_BASIC_STATS,(uintptr_t)&sx,0));
    struct stat st; assert(!stat(path,&st) && sx.stx_ino==st.st_ino && sx.stx_size==7 && sx.stx_nlink==2);
    assert(direct6(SYS_statx,base,(uintptr_t)"linked",AT_STATX_SYNC_TYPE,STATX_BASIC_STATS,(uintptr_t)&sx,0)==-EINVAL);
    assert(!direct6(SYS_faccessat,base,(uintptr_t)"linked",R_OK,0,0,0));
    assert(!direct6(SYS_fchmodat,base,(uintptr_t)"linked",0640,0,0,0));
    assert(!stat(path,&st) && (st.st_mode&0777)==0640);
    assert(!direct6(SYS_fchownat,base,(uintptr_t)"linked",123,456,0,0));
    assert(!stat(path,&st) && st.st_uid==123 && st.st_gid==456);
    assert(!direct6(SYS_fchownat,base,(uintptr_t)"linked",0,0,0,0));
    assert(!direct6(SYS_renameat,base,(uintptr_t)"linked",base,(uintptr_t)"renamed",0,0));
    assert(!direct6(SYS_unlinkat,base,(uintptr_t)"renamed",0,0,0,0));
    assert(!direct6(SYS_unlinkat,base,(uintptr_t)"symlink",0,0,0,0));
    assert(!chdir(directory));
    assert(!direct6(SYS_mkdirat,AT_FDCWD,(uintptr_t)"cwd-first",0700,0,0,0));
    assert(!direct6(SYS_renameat,AT_FDCWD,(uintptr_t)"cwd-first",AT_FDCWD,(uintptr_t)"cwd-second",0,0));
    assert(!direct6(SYS_unlinkat,AT_FDCWD,(uintptr_t)"cwd-second",AT_REMOVEDIR,0,0,0));
    assert(!chdir("/"));
    char entries[4096];
    assert(direct6(SYS_getdents64,base,1,sizeof(entries),0,0,0)==-EFAULT);
    assert(lseek(base,0,SEEK_CUR)==0);
    assert(direct6(SYS_getdents64,base,(uintptr_t)entries,sizeof(entries),0,0,0)>0);
    assert(lseek(base,0,SEEK_CUR)>0);
    assert(!direct6(SYS_getdents64,base,(uintptr_t)entries,sizeof(entries),0,0,0));
    assert(!close(base));
    assert(!direct6(SYS_renameat2,AT_FDCWD,(uintptr_t)directory,AT_FDCWD,(uintptr_t)moved,0,0));
    assert(!direct6(SYS_unlinkat,AT_FDCWD,(uintptr_t)moved,AT_REMOVEDIR,0,0,0));
    assert(!stat(path,&st) && st.st_nlink==1);
    puts("PASS cooperative entry: direct mutations, relative dirfds/cwd, statx, access, permissions and acknowledged directory cursor");
}
static void contracts(const char *executable) {
    assert(sizeof(struct md_entry_client)==3*sizeof(uintptr_t));
    struct md_entry_api invalid=*api;
    assert(md_entry_api_valid(&invalid));
    invalid.version++; assert(!md_entry_api_valid(&invalid)); invalid=*api;
    invalid.size=sizeof(invalid)-1; assert(!md_entry_api_valid(&invalid)); invalid=*api;
    invalid.try_syscall=NULL; assert(!md_entry_api_valid(&invalid)); invalid=*api;
    invalid.offers=NULL; assert(!md_entry_api_valid(&invalid)); invalid=*api;
    invalid.reserved=1; assert(!md_entry_api_valid(&invalid)); invalid=*api;
    invalid.size+=16; assert(md_entry_api_valid(&invalid));
    assert(!md_entry_api_valid(NULL) && !md_entry_offered(NULL,SYS_openat,MD_ENTRY_ORDINARY));
    assert(!md_entry_offered(api,-1,MD_ENTRY_ORDINARY));
    assert(!md_entry_offered(api,api->syscall_count,MD_ENTRY_ORDINARY));
    for (unsigned nr=0;nr<api->syscall_count;++nr) {
        enum md_entry_route route=md_entry_route(nr);
        assert(!!md_entry_offered(api,nr,MD_ENTRY_ORDINARY)==(route!=MD_ENTRY_CALLER));
        assert(!!md_entry_offered(api,nr,MD_ENTRY_CANCELLATION)==(route==MD_ENTRY_FD));
    }
    puts("PASS cooperative ABI: runtime-owned offers, opaque client, bounds and descriptor admission");
    struct md_entry_client unused={0};
    for (int nr=-1;nr<512;++nr) {
        if (md_entry_supported(nr)) continue;
        struct md_entry_call call={.number=nr};
        assert(api->try_syscall(&unused,&call)==MD_ENTRY_DECLINED);
        assert(!unused.opaque[0] && !unused.opaque[1] && !unused.opaque[2]);
    }
    long fd=call6(SYS_openat,AT_FDCWD,(uintptr_t)path,O_CREAT|O_RDWR|O_TRUNC,0600,0,0); assert(fd>=0);
    assert(call6(SYS_write,fd,(uintptr_t)"payload",7,0,0,0)==7);
    native_descriptors();
    task_completion(); create_admission(); native_open_exhaustion(); filter_arguments(); filter_instruction();
    struct stat st,native; long result;
    enum md_entry_outcome first=stat_try(&client,&st,&result);
    assert(first==MD_ENTRY_COMPLETED && !result && st.st_size==7);
    assert(!stat(path,&native) && st.st_ino==native.st_ino && st.st_mode==native.st_mode);
    assert(call6(SYS_fstat,fd,(uintptr_t)&st,0,0,0,0)==0 && st.st_size==7);
    assert(call6(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,1,0,0,0)==-EFAULT);
    assert(call6(SYS_newfstatat,AT_FDCWD,1,(uintptr_t)&st,0,0,0)==-EFAULT);
    size_t page=(size_t)getpagesize();
    char *memory=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED && !mprotect(memory+page,page,PROT_NONE));
    assert(call6(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)(memory+page-16),0,0,0)==-EFAULT);
    assert(!munmap(memory,2*page));
    unlink("/tmp/cooperative-link"); assert(!symlink("cooperative-file","/tmp/cooperative-link"));
    char link[64]={0};
    assert(call6(SYS_readlinkat,AT_FDCWD,(uintptr_t)"/tmp/cooperative-link",(uintptr_t)link,sizeof(link),0,0)==16);
    assert(!strcmp(link,"cooperative-file"));
    assert(call6(SYS_readlinkat,AT_FDCWD,(uintptr_t)"/tmp/cooperative-link",(uintptr_t)link,0,0,0)==-EINVAL);
    assert(!unlink("/tmp/cooperative-link"));
    assert(!call6(SYS_close,fd,0,0,0,0,0));
    assert(call6(SYS_fstat,fd,(uintptr_t)&st,0,0,0,0)==-EBADF);
    filesystem_operations();
    struct sigaction action={.sa_handler=handler}; sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1,&action,NULL));
    strict_reentry=1;
    client.opaque[MD_ENTRY_CLIENT_CONTROL]=MD_ENTRY_CLIENT_BUSY;
    assert(!raise(SIGUSR1) && signals==1);
    client.opaque[MD_ENTRY_CLIENT_CONTROL]=0; strict_reentry=0;
    struct md_entry_call unsupported={.number=SYS_clone};
    assert(api->try_syscall(&client,&unsupported)==MD_ENTRY_DECLINED);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(stat_try(&client,&st,&result)==MD_ENTRY_DECLINED);
        struct md_entry_client fresh={0};
        assert(stat_try(&fresh,&st,&result)==MD_ENTRY_COMPLETED && !result);
        execl(executable,executable,"exec",NULL); _exit(90);
    }
    reap(child);
    pthread_t peers[4];
    for (unsigned i=0;i<4;++i) assert(!pthread_create(&peers[i],NULL,threaded,NULL));
    for (unsigned i=0;i<4;++i) assert(!pthread_join(peers[i],NULL));
    capacity(); interrupted(); abandoned_memory(); context_changes(); credentials(); pid_namespace(); landlocked(); teardown();
    assert(!prctl(PR_SET_DUMPABLE,0));
    assert(!call6(SYS_newfstatat,AT_FDCWD,(uintptr_t)path,(uintptr_t)&st,0,0,0) && st.st_size==7);
    assert(!prctl(PR_SET_DUMPABLE,1));
    filters();
    assert(!call6(SYS_renameat2,AT_FDCWD,(uintptr_t)path,AT_FDCWD,(uintptr_t)"/tmp/cooperative-renamed",0,0));
    assert(!call6(SYS_unlinkat,AT_FDCWD,(uintptr_t)"/tmp/cooperative-renamed",0,0,0,0));
    assert(direct_calls && fallback_calls);
    puts("PASS cooperative entry: metadata, pointers, native IO/FDs, signal reentry, fork/exec, threads and nondumpable fallback");
}
int main(int argc,char **argv) {
    alarm(60); setbuf(stdout,NULL);
    api=(void *)getauxval(MD_AT_COOPERATIVE);
    assert(md_entry_api_valid(api));
    if (argc>1 && !strcmp(argv[1],"exec")) {
        struct stat st; long result;
        assert(stat_try(&client,&st,&result)==MD_ENTRY_COMPLETED && !result);
        puts("PASS cooperative entry: fresh auxv and channel after exec"); return 0;
    }
    contracts(argv[0]); return 0;
}
