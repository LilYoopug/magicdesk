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
#include <sys/wait.h>
#include <unistd.h>

static long (*call)(void);
static unsigned number;
extern long image_uid(void);
extern long live_uid(void);
extern long live_open(long,const char *,long,long);
__asm__(".pushsection .text\n.p2align 16\n.global image_uid\n"
    "image_uid:\nmov x8,#174\nsvc #0\nret\n.p2align 16\n"
    ".global live_uid\nlive_uid:\nmov x8,#174\nsvc #0\nret\n"
    ".global live_open\nlive_open:\nmov x8,#56\nsvc #0\nret\n.popsection");
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
                assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&program));
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
