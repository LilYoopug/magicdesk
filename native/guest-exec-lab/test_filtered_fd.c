#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { perror(#x); return 1; } } while (0)
extern long filtered_openat(int, const char *, int, int);
extern const char filtered_openat_return[];
__asm__(".text\n"
        ".global filtered_openat\n"
        "filtered_openat:\n"
        "mov x8, #56\n"
        "svc #0\n"
        ".global filtered_openat_return\n"
        "filtered_openat_return:\n"
        "ret\n");

int main(int argc, char **argv) {
    CHECK(argc == 2);
    int read_flags=O_RDONLY|O_CLOEXEC, create_flags=O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC;
    int fd=filtered_openat(AT_FDCWD,"/etc/os-release",read_flags,0);
    CHECK(fd>=0 && !close(fd));
    uintptr_t pc=(uintptr_t)filtered_openat_return;
    unsigned forbidden=getenv("MD_FILTER_TRAP") ? SECCOMP_RET_TRAP : SECCOMP_RET_KILL_PROCESS;
    struct sock_filter rules[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,forbidden),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_gettid,0,1),
        BPF_STMT(BPF_RET|BPF_K,forbidden),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,0,1),
        BPF_STMT(BPF_RET|BPF_K,forbidden),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_sendmsg,0,1),
        BPF_STMT(BPF_RET|BPF_K,forbidden),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_openat,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(pc>>32),1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)pc,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,read_flags,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,create_flags,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program={sizeof(rules)/sizeof(*rules),rules};
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    CHECK(!prctl(PR_SET_DUMPABLE,0));
    CHECK(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    CHECK(prctl(PR_GET_DUMPABLE)==0);
    for (unsigned i=0;i<64;++i) {
        fd=filtered_openat(AT_FDCWD,"/etc/os-release",read_flags,0);
        CHECK(fd>=0);
        char data[16];
        CHECK(read(fd,data,sizeof(data))>0);
        if (!i) {
            const char *mapped=mmap(NULL,4096,PROT_READ,MAP_PRIVATE,fd,0);
            CHECK(mapped!=MAP_FAILED && mapped[0]==data[0]);
            CHECK(!munmap((void *)mapped,4096));
        }
        CHECK(fcntl(fd,F_GETFD)==FD_CLOEXEC && !close(fd));
    }
    CHECK(filtered_openat(AT_FDCWD,"/etc/os-release",O_WRONLY,0)==-EACCES);
    errno=0;
    CHECK(open("/etc/os-release",read_flags)==-1 && errno==EACCES);
    /* A second native execution of this open would fail with EEXIST. */
    fd=filtered_openat(AT_FDCWD,argv[1],create_flags,0600);
    CHECK(fd>=0 && write(fd,"ok",2)==2 && !close(fd));
    CHECK(!unlink(argv[1]));
    struct stat stream, copied;
    CHECK(!fstat(STDOUT_FILENO,&stream));
    fd=dup(STDOUT_FILENO);
    CHECK(fd>=0 && !fstat(fd,&copied) && !close(fd));
    CHECK(stream.st_dev==copied.st_dev && stream.st_ino==copied.st_ino);
    puts("PASS filtered FD: dumpable=0, forbidden carriers/helpers, original IP/flags, mmap, stream dup and one create");
    return 0;
}
