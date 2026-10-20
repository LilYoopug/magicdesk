#include "svc_filter.h"
#include <assert.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>

/* Independent test interpreter: compare the original program on logical data
 * with the projected program on physical data, including all scratch words. */
static uint32_t evaluate(const struct sock_filter *code,size_t count,const struct seccomp_data *data) {
    uint32_t a=0,x=0,m[BPF_MEMWORDS]={0};
    for (size_t pc=0;pc<count;++pc) {
        const struct sock_filter *p=code+pc;
        uint32_t value=BPF_SRC(p->code)==BPF_X ? x : p->k;
        switch (BPF_CLASS(p->code)) {
        case BPF_LD:
        case BPF_LDX: {
            uint32_t v;
            assert(BPF_SIZE(p->code)==BPF_W);
            switch (BPF_MODE(p->code)) {
            case BPF_IMM: v=p->k; break;
            case BPF_ABS:
                assert(p->k<=sizeof(*data)-4 && !(p->k&3));
                memcpy(&v,(const char *)data+p->k,4); break;
            case BPF_MEM: assert(p->k<BPF_MEMWORDS); v=m[p->k]; break;
            case BPF_LEN: v=sizeof(*data); break;
            default: assert(0); v=0;
            }
            if (BPF_CLASS(p->code)==BPF_LD) a=v; else x=v;
            break;
        }
        case BPF_ST: assert(p->k<BPF_MEMWORDS); m[p->k]=a; break;
        case BPF_STX: assert(p->k<BPF_MEMWORDS); m[p->k]=x; break;
        case BPF_ALU:
            switch (BPF_OP(p->code)) {
            case BPF_ADD: a+=value; break;
            case BPF_SUB: a-=value; break;
            case BPF_MUL: a*=value; break;
            case BPF_DIV: if (!value) return 0; a/=value; break;
            case BPF_MOD: if (!value) return 0; a%=value; break;
            case BPF_OR: a|=value; break;
            case BPF_AND: a&=value; break;
            case BPF_XOR: a^=value; break;
            case BPF_LSH: assert(value<32); a<<=value; break;
            case BPF_RSH: assert(value<32); a>>=value; break;
            case BPF_NEG: a=0u-a; break;
            default: assert(0);
            }
            break;
        case BPF_JMP:
            switch (BPF_OP(p->code)) {
            case BPF_JA: pc+=p->k; break;
            case BPF_JEQ: pc+=a==value ? p->jt : p->jf; break;
            case BPF_JGT: pc+=a>value ? p->jt : p->jf; break;
            case BPF_JGE: pc+=a>=value ? p->jt : p->jf; break;
            case BPF_JSET: pc+=(a&value) ? p->jt : p->jf; break;
            default: assert(0);
            }
            break;
        case BPF_RET: return BPF_RVAL(p->code)==BPF_A ? a : p->k;
        case BPF_MISC:
            if (BPF_MISCOP(p->code)==BPF_TAX) x=a;
            else { assert(BPF_MISCOP(p->code)==BPF_TXA); a=x; }
            break;
        default: assert(0);
        }
    }
    assert(0 && "filter must return"); return 0;
}
static uint32_t random_word(uint32_t *seed) {
    uint32_t x=*seed; x^=x<<13; x^=x>>17; x^=x<<5; return *seed=x;
}
int main(void) {
    struct md_svc_filter_alias aliases[12];
    for (unsigned i=0;i<12;++i) aliases[i]=(struct md_svc_filter_alias){
        UINT64_C(0x123400000000)+(uint64_t)(i/4)*UINT64_C(0x100000000)+i*16,
        UINT64_C(0x765400000000)+(uint64_t)(i%3)*UINT64_C(0x100000000)+i*128};
    struct sock_filter source[256],out[BPF_MAXINSNS];
    size_t count=0,written;
#define PUT(...) source[count++]=(struct sock_filter){__VA_ARGS__}
    for (unsigned i=0;i<BPF_MEMWORDS;++i) {
        PUT(BPF_LD|BPF_W|BPF_IMM,0,0,UINT32_C(0x9e3779b9)*(i+1));
        PUT(BPF_ST,0,0,i);
    }
    PUT(BPF_LDX|BPF_W|BPF_IMM,0,0,UINT32_C(0xa5a5a5a5));
    PUT(BPF_LD|BPF_W|BPF_ABS,0,0,offsetof(struct seccomp_data,nr));
    size_t branch=count;
    PUT(BPF_JMP|BPF_JEQ|BPF_K,0,0,7);
    for (unsigned i=0;i<24;++i) {
        PUT(BPF_LD|BPF_W|BPF_ABS,0,0,offsetof(struct seccomp_data,instruction_pointer)+(i%2)*4);
        PUT(BPF_ALU|BPF_XOR|BPF_X,0,0,0);
        PUT(BPF_ST,0,0,i%BPF_MEMWORDS);
        PUT(BPF_MISC|BPF_TAX,0,0,0);
    }
    assert(count-branch-1<=255);
    source[branch].jt=(unsigned char)(count-branch-1);
    /* Forward conditional and unconditional branches span expanded IP loads.
     * X and all 16 original M words must remain available to the program. */
    PUT(BPF_LD|BPF_W|BPF_ABS,0,0,offsetof(struct seccomp_data,args[0]));
    PUT(BPF_JMP|BPF_JSET|BPF_K,0,1,1);
    PUT(BPF_JMP|BPF_JA,0,0,1);
    PUT(BPF_ALU|BPF_ADD|BPF_X,0,0,0);
    for (unsigned i=0;i<BPF_MEMWORDS;++i) {
        PUT(BPF_LDX|BPF_W|BPF_MEM,0,0,i);
        PUT(BPF_ALU|BPF_XOR|BPF_X,0,0,0);
        PUT(BPF_ALU|BPF_ADD|BPF_K,0,0,i);
    }
    PUT(BPF_JMP|BPF_JGE|BPF_X,0,1,0);
    PUT(BPF_ALU|BPF_NEG,0,0,0);
    PUT(BPF_RET|BPF_A,0,0,0);
#undef PUT
    assert(!md_svc_filter_project(source,count,aliases,12,out,BPF_MAXINSNS,&written));
    assert(written>count+255);
    uint32_t seed=UINT32_C(0x4837a1c9);
    unsigned comparisons=0;
    for (unsigned i=0;i<4096;++i) {
        struct seccomp_data physical={0};
        unsigned char *bytes=(void *)&physical;
        for (size_t j=0;j<sizeof(physical);j+=4) {
            uint32_t value=random_word(&seed); memcpy(bytes+j,&value,4);
        }
        if (i%17<12) physical.instruction_pointer=aliases[i%17].physical;
        else if (i%17==12) physical.instruction_pointer=aliases[0].physical+4;
        else if (i%17==13) physical.instruction_pointer=aliases[0].physical+UINT64_C(0x1000000000);
        physical.nr=i%2 ? 7 : 56;
        struct seccomp_data logical=physical;
        for (unsigned j=0;j<12;++j)
            if (logical.instruction_pointer==aliases[j].physical) {
                logical.instruction_pointer=aliases[j].logical; break;
            }
        assert(evaluate(source,count,&logical)==evaluate(out,written,&physical));
        ++comparisons;
    }
    assert(!md_svc_filter_project(source,count,NULL,0,out,BPF_MAXINSNS,&written)
        && written==count && !memcmp(source,out,count*sizeof(*out)));
    struct sock_filter plain[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,56,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    assert(!md_svc_filter_project(plain,4,aliases,12,out,BPF_MAXINSNS,&written)
        && written==4 && !memcmp(plain,out,sizeof(plain)));
    assert(md_svc_filter_project(source,count,aliases,12,out,1,&written)==-ENOSPC && !written);
    struct sock_filter long_program[1024];
    for (unsigned i=0;i<1023;++i)
        long_program[i]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
            offsetof(struct seccomp_data,instruction_pointer));
    long_program[1023]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_A,0);
    assert(md_svc_filter_project(long_program,1024,aliases,12,out,BPF_MAXINSNS,&written)==-E2BIG && !written);
    source[branch].jt=255;
    assert(md_svc_filter_project(source,count,aliases,12,out,BPF_MAXINSNS,&written)==-EINVAL && !written);
    aliases[1]=aliases[0];
    assert(md_svc_filter_project(source,count,aliases,12,out,BPF_MAXINSNS,&written)==-EEXIST && !written);
    printf("SVC_FILTER comparisons=%u scratchWords=16 longBranches=1 unchangedNoIP=1 bounds=1\n",comparisons);
    return 0;
}
