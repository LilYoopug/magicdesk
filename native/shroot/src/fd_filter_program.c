#define _GNU_SOURCE
#include "fd_filter_program.h"
#include "interception.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>

int md_fd_filter_build(enum md_fd_selector_kind kind,int fd,
        const struct md_fd_filter_gates *gates,struct md_fd_filter_program *out) {
    if (!out) return -EINVAL;
    out->count=0;
    if (!gates || fd< -1 || kind<0 || kind>=MD_FD_SELECTOR_KINDS) return -EINVAL;
    unsigned mask=fd==-1 ? 0 : MD_FD_SELECTOR_MASK;
#define GATE(address) \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)((address)>>32),0,3), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)(address),0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
#define PREFIX \
    GATE(gates->raw) GATE(gates->watch) GATE(gates->task) \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#define ADAPT(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH),
#define DUPLICATES \
    ADAPT(dup) ADAPT(dup3) \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,4), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD,1,0), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD_CLOEXEC,0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
#define CONTROL(n,argument,cookie) \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,5), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[argument])), \
    BPF_STMT(BPF_ALU|BPF_AND|BPF_K,mask), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)fd&mask,0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|(cookie)), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#define PROC(n,argument) CONTROL(n,argument,MD_INTERCEPT_PROC)
#define COPY_PROGRAM(...) do { \
    struct sock_filter code[]={__VA_ARGS__}; \
    _Static_assert(sizeof(code)/sizeof(*code)<=MD_FD_FILTER_INSTRUCTIONS,"FD filter capacity"); \
    out->count=sizeof(code)/sizeof(*code); \
    for (unsigned i=0;i<out->count;++i) out->code[i]=code[i]; \
    return 0; \
} while (0)
    if (kind==MD_FD_SELECTOR_WATCH) COPY_PROGRAM(
        PREFIX
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_read,5,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_readv,4,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ioctl,3,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_splice,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_tee,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_sendfile,2,7),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_STMT(BPF_JMP|BPF_JA,1),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_STMT(BPF_ALU|BPF_AND|BPF_K,mask),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)fd&mask,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_WATCH),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        DUPLICATES
    );
    if (kind==MD_FD_SELECTOR_PROC) COPY_PROGRAM(
        PREFIX
        PROC(read,0) PROC(write,0) PROC(readv,0) PROC(writev,0)
        PROC(pread64,0) PROC(pwrite64,0)
        PROC(preadv,0) PROC(pwritev,0) PROC(preadv2,0) PROC(pwritev2,0)
        PROC(lseek,0) PROC(ioctl,0)
        /* Anonymous mmap ignores the FD, including adapter stack allocation. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mmap,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[3])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,MAP_ANONYMOUS,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        PROC(mmap,4) PROC(getdents64,0) PROC(fstatfs,0)
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,9),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GETFL,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETFL,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GET_SEALS,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_STMT(BPF_ALU|BPF_AND|BPF_K,mask),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)fd&mask,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_PROC),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        PROC(ftruncate,0) PROC(fsync,0) PROC(fdatasync,0)
        PROC(sendfile,0) PROC(sendfile,1) PROC(splice,0) PROC(splice,2)
        PROC(tee,0) PROC(tee,1) PROC(copy_file_range,0) PROC(copy_file_range,2)
        DUPLICATES
    );
    if (kind==MD_FD_SELECTOR_EPOLL_TARGET) COPY_PROGRAM(
        PREFIX
        CONTROL(epoll_ctl,2,MD_INTERCEPT_READINESS)
        DUPLICATES
    );
    if (kind==MD_FD_SELECTOR_EPOLL) COPY_PROGRAM(
        PREFIX
        CONTROL(epoll_ctl,0,MD_INTERCEPT_READINESS)
        CONTROL(epoll_pwait,0,MD_INTERCEPT_READINESS)
        CONTROL(epoll_pwait2,0,MD_INTERCEPT_READINESS)
        DUPLICATES
    );
    if (kind==MD_FD_SELECTOR_POLL) COPY_PROGRAM(
        PREFIX ADAPT(ppoll) ADAPT(pselect6)
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    );
    return -EINVAL;
#undef COPY_PROGRAM
#undef PROC
#undef CONTROL
#undef DUPLICATES
#undef ADAPT
#undef PREFIX
#undef GATE
}
