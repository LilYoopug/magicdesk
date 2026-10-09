#define _GNU_SOURCE
#include "fd_filter.h"
#include "fd_client.h"
#include "interception.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>

long md_fd_filter_prepared(unsigned selectors) {
    if (selectors&~((1U<<MD_FD_SELECTOR_KINDS)-1)) return -EINVAL;
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) if (selectors&(1U<<kind)) {
        long ready=md_fd_control(MD_FD_SELECTOR_QUERY,kind,-1,0);
        if (ready<=0) return ready;
    }
    return 1;
}

long md_fd_filter_arm_mask(unsigned selectors, int fd) {
    if (selectors&~((1U<<MD_FD_SELECTOR_KINDS)-1)) return -EINVAL;
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) if (selectors&(1U<<kind)) {
        long error=md_fd_filter_arm((enum md_fd_selector_kind)kind,fd);
        if (error) return error;
    }
    return 0;
}

static long arm(enum md_fd_selector_kind kind, int fd) {
    if (fd< -1 || kind<0 || kind>=MD_FD_SELECTOR_KINDS) return -EINVAL;
#ifdef MD_USE_LIBC
    return -ENOTSUP;
#else
    long result=md_fd_control(MD_FD_SELECTOR_QUERY,kind,fd,0);
    if (result) return result<0 ? result : 0;
    unsigned mask=fd==-1 ? 0 : MD_FD_SELECTOR_MASK;
    uintptr_t gate=(uintptr_t)md_raw_return;
    extern char md_guest_watch_return[];
    extern char md_guest_task_return[];
    uintptr_t watch=(uintptr_t)md_guest_watch_return;
    uintptr_t task=(uintptr_t)md_guest_task_return;
#define GATE(address) \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)((address)>>32),0,3), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)(address),0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
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
    struct sock_filter watch_code[]={
        GATE(gate) GATE(watch) GATE(task)
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
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
    };
#define CONTROL(n, argument) \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,5), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[argument])), \
    BPF_STMT(BPF_ALU|BPF_AND|BPF_K,mask), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)fd&mask,0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_PROC), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
    struct sock_filter proc_code[]={
        GATE(gate) GATE(watch) GATE(task)
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        CONTROL(read,0) CONTROL(write,0) CONTROL(readv,0) CONTROL(writev,0)
        CONTROL(pread64,0) CONTROL(pwrite64,0)
        CONTROL(preadv,0) CONTROL(pwritev,0) CONTROL(preadv2,0) CONTROL(pwritev2,0)
        CONTROL(lseek,0) CONTROL(ioctl,0)
        /* Anonymous mmap ignores its FD, including adapter stack allocation.
         * Leave its existing memory owner and native fast path unchanged. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mmap,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[3])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,MAP_ANONYMOUS,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        CONTROL(mmap,4) CONTROL(getdents64,0)
        CONTROL(fstatfs,0)
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
        CONTROL(ftruncate,0) CONTROL(fsync,0) CONTROL(fdatasync,0)
        CONTROL(sendfile,0) CONTROL(sendfile,1) CONTROL(splice,0) CONTROL(splice,2)
        CONTROL(tee,0) CONTROL(tee,1) CONTROL(copy_file_range,0) CONTROL(copy_file_range,2)
        DUPLICATES
    };
#undef CONTROL
#undef DUPLICATES
#undef ADAPT
#undef GATE
    struct sock_fprog program=kind==MD_FD_SELECTOR_WATCH
        ? (struct sock_fprog){sizeof(watch_code)/sizeof(*watch_code),watch_code}
        : (struct sock_fprog){sizeof(proc_code)/sizeof(*proc_code),proc_code};
    result=RAW3(seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&program);
    /* The selector is published only after every sibling accepted its filter. */
    if (result>0) return -ENOTSUP;
    return result ? result : md_fd_control(MD_FD_SELECTOR_MARK,kind,fd,0);
#endif
}
long md_fd_filter_arm(enum md_fd_selector_kind kind, int fd) {
    return fd<0 ? -EINVAL : arm(kind,fd);
}
long md_fd_filter_prepare_sandbox(void) {
    /* One filter admits future received/duplicated typed FDs before an
     * application can deny seccomp. Its ERRNO/TRAP/KILL decisions still win.
     * Unsandboxed workloads keep the selective per-number path. */
    return arm(MD_FD_SELECTOR_PROC,-1);
}
