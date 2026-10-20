#include "svc_filter.h"
#include <errno.h>
#include <linux/seccomp.h>
#include <stdlib.h>
#include <string.h>

static int ip_load(const struct sock_filter *p) {
    return p->code==(BPF_LD|BPF_W|BPF_ABS)
        && (p->k==offsetof(struct seccomp_data,instruction_pointer)
            || p->k==offsetof(struct seccomp_data,instruction_pointer)+4);
}
int md_svc_filter_project(const struct sock_filter *source,size_t count,
        const struct md_svc_filter_alias *aliases,size_t alias_count,
        struct sock_filter *out,size_t capacity,size_t *written) {
    if (!source || !out || !written || !count || count>BPF_MAXINSNS
            || (alias_count && !aliases)) return -EINVAL;
    *written=0;
    if (alias_count>BPF_MAXINSNS/6) return -E2BIG;
    for (size_t i=0;i<alias_count;++i) {
        if ((aliases[i].physical|aliases[i].logical)&3) return -EINVAL;
        for (size_t j=0;j<i;++j)
            if (aliases[i].physical==aliases[j].physical) return -EEXIST;
    }
    int needed=0;
    for (size_t i=0;i<count;++i) needed|=ip_load(source+i);
    if (!needed || !alias_count) {
        if (count>capacity) return -ENOSPC;
        memcpy(out,source,count*sizeof(*out)); *written=count;
        return 0;
    }
    size_t *offset=calloc(count+1,sizeof(*offset));
    if (!offset) return -ENOMEM;
    int error=0;
    for (size_t i=0;i<count;++i) {
        const struct sock_filter *p=source+i;
        size_t size=1;
        if (BPF_CLASS(p->code)==BPF_JMP) {
            if (BPF_OP(p->code)==BPF_JA) {
                if (p->k>=count-i-1) { error=-EINVAL; goto done; }
            } else {
                if (p->jt>=count-i-1 || p->jf>=count-i-1) { error=-EINVAL; goto done; }
                size=3;
            }
        } else if (ip_load(p)) size+=6*alias_count;
        offset[i+1]=offset[i]+size;
        if (offset[i+1]>BPF_MAXINSNS) { error=-E2BIG; goto done; }
    }
    if (offset[count]>capacity) { error=-ENOSPC; goto done; }
    for (size_t i=0;i<count;++i) {
        const struct sock_filter *p=source+i;
        size_t at=offset[i];
        if (BPF_CLASS(p->code)==BPF_JMP) {
            if (BPF_OP(p->code)==BPF_JA) {
                out[at]=*p; out[at].k=(uint32_t)(offset[i+1+p->k]-at-1);
            } else {
                /* Long forward branches avoid the classic-BPF 8-bit jt/jf
                 * limit after expansion, without using A, X or scratch M. */
                out[at]=*p; out[at].jt=0; out[at].jf=1;
                out[at+1]=(struct sock_filter)BPF_STMT(BPF_JMP|BPF_JA,
                    (uint32_t)(offset[i+1+p->jt]-at-2));
                out[at+2]=(struct sock_filter)BPF_STMT(BPF_JMP|BPF_JA,
                    (uint32_t)(offset[i+1+p->jf]-at-3));
            }
        } else if (ip_load(p)) {
            for (size_t j=0;j<alias_count;++j,at+=6) {
                const struct md_svc_filter_alias *a=aliases+j;
                out[at]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                    offsetof(struct seccomp_data,instruction_pointer)+4);
                out[at+1]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,
                    (uint32_t)(a->physical>>32),0,4);
                out[at+2]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                    offsetof(struct seccomp_data,instruction_pointer));
                out[at+3]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,
                    (uint32_t)a->physical,0,2);
                out[at+4]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_IMM,
                    (uint32_t)(a->logical>>(p->k==offsetof(struct seccomp_data,instruction_pointer) ? 0 : 32)));
                out[at+5]=(struct sock_filter)BPF_STMT(BPF_JMP|BPF_JA,
                    (uint32_t)(offset[i+1]-at-6));
            }
            out[at]=*p;
        } else out[at]=*p;
    }
    *written=offset[count];
done:
    free(offset);
    return error;
}
