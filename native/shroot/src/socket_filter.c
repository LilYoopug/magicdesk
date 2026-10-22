#define _GNU_SOURCE
#include "socket_filter.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct translation {
    struct sock_filter *code;
    unsigned count, prefix, temporary;
};
static int emit(struct translation *out,struct sock_filter instruction) {
    if (out->count==BPF_MAXINSNS) return -E2BIG;
    out->code[out->count++]=instruction; return 0;
}
#define EMIT(code,k) do { int e=emit(out,(struct sock_filter)BPF_STMT(code,k)); if (e) return e; } while (0)
#define JUMP(code,k,t,f) do { int e=emit(out,(struct sock_filter)BPF_JUMP(code,k,t,f)); if (e) return e; } while (0)

static int instruction(struct translation *out,struct sock_filter in) {
    unsigned code=in.code,kind=BPF_CLASS(code),mode=BPF_MODE(code),h=out->prefix;
    if ((kind==BPF_LD || kind==BPF_LDX) && (mode==BPF_ABS || mode==BPF_IND || mode==BPF_MSH)) {
        /* Ancillary pseudo-offsets describe the carrier, not the logical
         * netlink socket. Do not silently substitute its AF_UNIX metadata. */
        if (in.k>INT_MAX-h) return -EOPNOTSUPP;
        if (mode==BPF_IND) {
            if (out->temporary==BPF_MEMWORDS) return -EOPNOTSUPP;
            EMIT(BPF_ST,out->temporary);
            EMIT(BPF_LD|BPF_IMM,INT_MAX-h-in.k);
            JUMP(BPF_JMP|BPF_JGE|BPF_X,0,1,0);
            EMIT(BPF_RET|BPF_K,0);
            EMIT(BPF_LD|BPF_MEM,out->temporary);
        }
        in.k+=h; return emit(out,in);
    }
    if ((kind==BPF_LD || kind==BPF_LDX) && mode==BPF_LEN) {
        if (kind==BPF_LDX) {
            if (out->temporary==BPF_MEMWORDS) return -EOPNOTSUPP;
            EMIT(BPF_ST,out->temporary);
        }
        EMIT(BPF_LD|BPF_W|BPF_LEN,0);
        EMIT(BPF_ALU|BPF_SUB|BPF_K,h);
        if (kind==BPF_LDX) {
            EMIT(BPF_MISC|BPF_TAX,0);
            EMIT(BPF_LD|BPF_MEM,out->temporary);
        }
        return 0;
    }
    if (kind==BPF_RET) {
        if (BPF_RVAL(code)==BPF_K) {
            if (in.k) in.k=in.k>UINT32_MAX-h ? UINT32_MAX : in.k+h;
            return emit(out,in);
        }
        JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,3,0);
        JUMP(BPF_JMP|BPF_JGT|BPF_K,UINT32_MAX-h,0,1);
        EMIT(BPF_RET|BPF_K,UINT32_MAX);
        EMIT(BPF_ALU|BPF_ADD|BPF_K,h);
        EMIT(BPF_RET|BPF_A,0);
        return 0;
    }
    if (kind==BPF_JMP && BPF_OP(code)!=BPF_JA) {
        /* Conditional jumps have eight-bit offsets. Two long trampolines
         * retain the original targets even when intervening loads expand. */
        in.jt=0; in.jf=1;
        int e=emit(out,in); if (e) return e;
        EMIT(BPF_JMP|BPF_JA,0); EMIT(BPF_JMP|BPF_JA,0); return 0;
    }
    return emit(out,in);
}
static int translate(const struct sock_filter *code,unsigned count,unsigned prefix,struct sock_fprog *program) {
    struct translation out={.prefix=prefix,.temporary=BPF_MEMWORDS};
    unsigned used=0;
    for (unsigned i=0;i<count;++i) {
        unsigned kind=BPF_CLASS(code[i].code);
        if (kind==BPF_ST || kind==BPF_STX
                || ((kind==BPF_LD || kind==BPF_LDX) && BPF_MODE(code[i].code)==BPF_MEM))
            used|=1U<<code[i].k;
    }
    for (unsigned i=0;i<BPF_MEMWORDS;++i) if (!(used&(1U<<i))) { out.temporary=i; break; }
    unsigned *offsets=malloc((count+1)*sizeof(*offsets));
    out.code=malloc(BPF_MAXINSNS*sizeof(*out.code));
    if (!offsets || !out.code) { free(offsets); free(out.code); return -ENOMEM; }
    int error=0;
    for (unsigned i=0;i<count && !error;++i) {
        offsets[i]=out.count; error=instruction(&out,code[i]);
    }
    offsets[count]=out.count;
    for (unsigned i=0;i<count && !error;++i) {
        if (BPF_CLASS(code[i].code)!=BPF_JMP) continue;
        unsigned at=offsets[i];
        if (BPF_OP(code[i].code)==BPF_JA)
            out.code[at].k=offsets[i+1+code[i].k]-at-1;
        else {
            out.code[at+1].k=offsets[i+1+code[i].jt]-at-2;
            out.code[at+2].k=offsets[i+1+code[i].jf]-at-3;
        }
    }
    free(offsets);
    if (error) free(out.code);
    else *program=(struct sock_fprog){.len=(unsigned short)out.count,.filter=out.code};
    return error;
}
void md_socket_filter_clear(struct md_socket_filter *filter) {
    free(filter->code); *filter=(struct md_socket_filter){0};
}
int md_socket_filter_attach(struct md_socket_filter *filter,int fd,const void *data,size_t size,unsigned prefix) {
    if (!size || size%sizeof(struct sock_filter) || size/sizeof(struct sock_filter)>BPF_MAXINSNS
            || prefix>INT_MAX) return -EINVAL;
    struct sock_filter *original=malloc(size);
    if (!original) return -ENOMEM;
    memcpy(original,data,size);
    struct sock_fprog program={.len=(unsigned short)(size/sizeof(*original)),.filter=original};
    /* Validate the original control flow, scratch initialization and opcodes
     * before transforming it. A rejected replacement leaves the live OFD alone. */
    int validator=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0);
    int error=validator<0 ? -errno : 0;
    if (!error && setsockopt(validator,SOL_SOCKET,SO_ATTACH_FILTER,&program,sizeof(program))) error=-errno;
    if (validator>=0) close(validator);
    struct sock_fprog translated={0};
    if (!error) error=translate(original,program.len,prefix,&translated);
    if (!error && setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&translated,sizeof(translated))) error=-errno;
    free(translated.filter);
    if (error) free(original);
    else { md_socket_filter_clear(filter); filter->code=original; filter->count=program.len; }
    return error;
}
int md_socket_filter_detach(struct md_socket_filter *filter,int fd) {
    int zero=0;
    if (setsockopt(fd,SOL_SOCKET,SO_DETACH_FILTER,&zero,sizeof(zero))) return -errno;
    md_socket_filter_clear(filter); return 0;
}
