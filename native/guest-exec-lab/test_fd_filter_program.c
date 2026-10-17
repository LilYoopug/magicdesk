#define _GNU_SOURCE
#include "fd_filter_program.h"
#include "interception.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static unsigned evaluate(const struct md_fd_filter_program *p,const struct seccomp_data *d) {
    unsigned a=0;
    for (unsigned pc=0,steps=0;pc<p->count && steps++<p->count;++pc) {
        const struct sock_filter *i=&p->code[pc];
        switch (i->code) {
        case BPF_LD|BPF_W|BPF_ABS:
            assert(i->k<=sizeof(*d)-sizeof(a) && !(i->k&3));
            memcpy(&a,(const char *)d+i->k,sizeof(a)); break;
        case BPF_ALU|BPF_AND|BPF_K: a&=i->k; break;
        case BPF_ALU|BPF_OR|BPF_K: a|=i->k; break;
        case BPF_JMP|BPF_JEQ|BPF_K: pc+=a==i->k ? i->jt : i->jf; break;
        case BPF_JMP|BPF_JGT|BPF_K: pc+=a>i->k ? i->jt : i->jf; break;
        case BPF_JMP|BPF_JSET|BPF_K: pc+=a&i->k ? i->jt : i->jf; break;
        case BPF_JMP|BPF_JA: pc+=i->k; break;
        case BPF_RET|BPF_K: return i->k;
        case BPF_RET|BPF_A: return a;
        default: assert(!"unexpected FD filter instruction");
        }
    }
    assert(!"FD filter did not terminate"); return 0;
}
static unsigned expected(unsigned kind,int fd,const struct seccomp_data *d) {
    if (kind==MD_FD_SELECTOR_POLL)
        return d->nr==SYS_ppoll || d->nr==SYS_pselect6
            ? SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH : SECCOMP_RET_ALLOW;
    if (d->nr==SYS_dup || d->nr==SYS_dup3 || (d->nr==SYS_fcntl
            && ((unsigned)d->args[1]==F_DUPFD || (unsigned)d->args[1]==F_DUPFD_CLOEXEC)))
        return SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH;
    unsigned selected=0;
    if (kind==MD_FD_SELECTOR_WATCH) {
        switch (d->nr) {
        case SYS_read: case SYS_readv: case SYS_ioctl: case SYS_splice: case SYS_tee: selected=1; break;
        case SYS_sendfile: selected=2; break;
        }
    } else if (kind==MD_FD_SELECTOR_PROC) {
        switch (d->nr) {
        case SYS_read: case SYS_write: case SYS_readv: case SYS_writev:
        case SYS_pread64: case SYS_pwrite64: case SYS_preadv: case SYS_pwritev:
        case SYS_preadv2: case SYS_pwritev2: case SYS_lseek: case SYS_ioctl:
        case SYS_getdents64: case SYS_fstatfs: case SYS_ftruncate: case SYS_fsync:
        case SYS_fdatasync: selected=1; break;
        case SYS_sendfile: case SYS_tee: selected=3; break;
        case SYS_splice: case SYS_copy_file_range: selected=5; break;
        case SYS_mmap: if (!(d->args[3]&MAP_ANONYMOUS)) selected=1u<<4; break;
        case SYS_fcntl:
            if ((unsigned)d->args[1]==F_GETFL || (unsigned)d->args[1]==F_SETFL
                    || (unsigned)d->args[1]==F_GET_SEALS) selected=1;
            break;
        }
    } else if (kind==MD_FD_SELECTOR_EPOLL_TARGET) {
        if (d->nr==SYS_epoll_ctl) selected=1u<<2;
    } else if (kind==MD_FD_SELECTOR_EPOLL) {
        if (d->nr==SYS_epoll_ctl || d->nr==SYS_epoll_pwait || d->nr==SYS_epoll_pwait2) selected=1;
    }
    for (unsigned n=0;n<6;++n) if ((selected&(1u<<n))
            && (fd==-1 || (d->args[n]&MD_FD_SELECTOR_MASK)==((unsigned)fd&MD_FD_SELECTOR_MASK)))
        return SECCOMP_RET_TRACE|(kind==MD_FD_SELECTOR_WATCH ? MD_INTERCEPT_WATCH
            : kind==MD_FD_SELECTOR_PROC ? MD_INTERCEPT_PROC : MD_INTERCEPT_READINESS);
    return SECCOMP_RET_ALLOW;
}
void test_fd_filter_program(void) {
    const struct sock_filter close_code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        MD_FD_CLOSE_FILTER,
        BPF_STMT(BPF_RET|BPF_A,0)
    };
    struct md_fd_filter_program close_filter={.count=sizeof(close_code)/sizeof(*close_code)};
    memcpy(close_filter.code,close_code,sizeof(close_code));
    const uint64_t numbers[]={0,3,511,32767,32768,UINT32_MAX,UINT64_C(1)<<32,(UINT64_C(1)<<32)|511};
    for (unsigned nr=0;nr<512;++nr) for (unsigned n=0;n<sizeof(numbers)/sizeof(*numbers);++n) {
        struct seccomp_data d={.nr=(int)nr,.args={numbers[n],UINT64_MAX,123}};
        unsigned fd=(unsigned)numbers[n];
        unsigned want=nr!=SYS_close ? nr : SECCOMP_RET_TRACE|(fd<=MD_INTERCEPT_CLOSE_MAX
            ? MD_INTERCEPT_CLOSE|fd : MD_INTERCEPT_FD);
        assert(evaluate(&close_filter,&d)==want);
    }
    puts("PASS compact close cookies: exact low-int FD, boundary/negative fallback, other syscall accumulator preserved");
    const struct md_fd_filter_gates gates={0x1112345678,0x2212345678,0x3312345678,0x5512345678};
    const uintptr_t exempt[]={gates.raw,gates.watch,gates.task,gates.native};
    const int fds[]={0,190,511,512,1024*1024,-1};
    const unsigned commands[]={0,F_GETFL,F_SETFL,F_GETFD,F_GET_SEALS,F_DUPFD,F_DUPFD_CLOEXEC};
    struct md_fd_filter_program built;
    assert(md_fd_filter_build(MD_FD_SELECTOR_PROC,0,&gates,NULL)==-EINVAL);
    assert(md_fd_filter_build(MD_FD_SELECTOR_PROC,0,NULL,&built)==-EINVAL && !built.count);
    assert(md_fd_filter_build(MD_FD_SELECTOR_PROC,-2,&gates,&built)==-EINVAL && !built.count);
    assert(md_fd_filter_build(MD_FD_SELECTOR_KINDS,0,&gates,&built)==-EINVAL && !built.count);
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind)
        for (unsigned f=0;f<sizeof(fds)/sizeof(*fds);++f) {
            int fd=fds[f];
            assert(!md_fd_filter_build(kind,fd,&gates,&built));
            assert(built.count && built.count<=MD_FD_FILTER_INSTRUCTIONS);
            for (unsigned nr=0;nr<512;++nr) for (unsigned arg=0;arg<6;++arg)
                for (unsigned alias=0;alias<3;++alias) for (unsigned c=0;c<sizeof(commands)/sizeof(*commands);++c) {
                    struct seccomp_data d={.nr=(int)nr,.instruction_pointer=0x4412345678};
                    for (unsigned n=0;n<6;++n) d.args[n]=(unsigned)(fd+1);
                    d.args[arg]=(unsigned)fd+alias*(MD_FD_SELECTOR_MASK+1u);
                    if (nr==SYS_fcntl) d.args[1]=commands[c]|(UINT64_C(1)<<32);
                    if (nr==SYS_mmap) d.args[3]=(c&1) ? MAP_ANONYMOUS : 0;
                    assert(evaluate(&built,&d)==expected(kind,fd,&d));
                    for (unsigned gate=0;gate<sizeof(exempt)/sizeof(*exempt);++gate) {
                        d.instruction_pointer=exempt[gate];
                        assert(evaluate(&built,&d)==SECCOMP_RET_ALLOW);
                        d.instruction_pointer=exempt[gate]+4;
                        assert(evaluate(&built,&d)==expected(kind,fd,&d));
                    }
                }
        }
    const struct md_fd_filter_gates grouped[]={
        {0},
        {0x2010000000,0x2010000010,0x2010000020,0x2010000030},
        {0x2010000000,0x2010000000,0x2010000000,0x2010000000},
        {0x2010000000,0x3010000000,0x2010000010,0}
    };
    for (unsigned p=0;p<sizeof(grouped)/sizeof(*grouped);++p)
        for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) {
            const struct md_fd_filter_gates *g=&grouped[p];
            const uintptr_t addresses[]={g->raw,g->watch,g->task,g->native};
            struct md_fd_filter_program separate;
            assert(!md_fd_filter_build(kind,190,&gates,&separate));
            assert(!md_fd_filter_build(kind,190,g,&built));
            assert(built.count<separate.count);
            if (p==1) assert(built.count+9==separate.count);
            for (unsigned nr=0;nr<512;++nr) for (unsigned i=0;i<4;++i)
                for (unsigned adjacent=0;adjacent<2;++adjacent) {
                    struct seccomp_data d={.nr=(int)nr,.instruction_pointer=addresses[i]+4*adjacent,
                        .args={190,F_DUPFD,190,0,190,0}};
                    int exempted=0;
                    for (unsigned j=0;j<4;++j)
                        exempted|=addresses[j] && addresses[j]==d.instruction_pointer;
                    assert(evaluate(&built,&d)==(exempted ? SECCOMP_RET_ALLOW : expected(kind,190,&d)));
                }
        }
    puts("PASS FD filter decisions: classes, aliases, argument positions, grouped/absent/duplicate gates and native waits");
}
