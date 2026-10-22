#define _GNU_SOURCE
#include "cgroup_program.h"
#include "bpf_handle.h"
#include "guest_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct md_cgroup_programs {
    atomic_uint refs;
    pthread_mutex_t lock;
    struct md_cgroup_program *first;
    uint32_t next;
    unsigned count;
    struct md_bpf_maps *maps;
};
struct md_cgroup_program {
    struct md_cgroup_program *next;
    struct md_cgroup_programs *owner;
    unsigned refs,count,type;
    uint32_t id;
    char name[BPF_OBJ_NAME_LEN];
    struct md_bpf_map *maps[MD_BPF_MAPS_PER_PROGRAM];
    unsigned map_count;
    struct bpf_insn instructions[];
};
struct md_cgroup_programs *md_cgroup_programs_new(void) {
    struct md_cgroup_programs *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    int r=pthread_mutex_init(&p->lock,NULL);
    if (r) { free(p); errno=r; return NULL; }
    atomic_init(&p->refs,1); return p;
}
struct md_cgroup_programs *md_cgroup_programs_retain(struct md_cgroup_programs *p) {
    if (p) atomic_fetch_add(&p->refs,1); return p;
}
void md_cgroup_programs_release(struct md_cgroup_programs *p) {
    if (!p || atomic_fetch_sub(&p->refs,1)!=1) return;
    md_bpf_maps_release(p->maps);
    pthread_mutex_destroy(&p->lock); free(p);
}
struct md_bpf_maps *md_cgroup_program_maps(struct md_cgroup_programs *p,int create) {
    if (!p) return NULL;
    pthread_mutex_lock(&p->lock);
    if (!p->maps && create) p->maps=md_bpf_maps_new();
    struct md_bpf_maps *maps=md_bpf_maps_retain(p->maps);
    pthread_mutex_unlock(&p->lock); return maps;
}
/* Bounded forward-only predicates, stack operands and map lookup. These
 * instructions are retained as metadata, never executed against host memory.
 * This is admission for a permissive provider,
 * not a kernel verifier or a promise to execute a security policy. */
static int validate(unsigned type,const struct bpf_insn *v,unsigned n,const char *name) {
    if (!md_bpf_program_type(type)) return -EOPNOTSUPP;
    if (!n || n>MD_BPF_INSTRUCTIONS_MAX) return -E2BIG;
    if (strnlen(name,BPF_OBJ_NAME_LEN)==BPF_OBJ_NAME_LEN) return -EINVAL;
    for (const char *s=name;*s;++s)
        if (!((*s>='a' && *s<='z') || (*s>='A' && *s<='Z') || (*s>='0' && *s<='9')
                || *s=='_' || *s=='.')) return -EINVAL;
    for (unsigned i=0;i<n;++i) {
        struct bpf_insn instruction; memcpy(&instruction,(const char *)v+i*sizeof(instruction),sizeof(instruction));
        const struct bpf_insn *p=&instruction;
        unsigned cls=BPF_CLASS(p->code),op=BPF_OP(p->code);
        if (p->dst_reg>10 || p->src_reg>10) return -EINVAL;
        if (p->code==(BPF_LD|BPF_IMM|BPF_DW)) {
            if (i+1>=n || p->dst_reg==10 || p->off
                    || (p->src_reg && p->src_reg!=BPF_PSEUDO_MAP_FD)) return -EINVAL;
            struct bpf_insn high; memcpy(&high,v+i+1,sizeof(high));
            if (high.code || high.dst_reg || high.src_reg || high.off
                    || (p->src_reg && (high.imm || p->imm<=0))) return -EINVAL;
            ++i;
        } else if (cls==BPF_LDX && BPF_MODE(p->code)==BPF_MEM) {
            if (type!=BPF_PROG_TYPE_CGROUP_DEVICE) return -EOPNOTSUPP;
            if (p->dst_reg==10 || p->imm) return -EINVAL;
            if (p->src_reg==10) {
                unsigned size=1U<<(BPF_SIZE(p->code)==BPF_DW ? 3 : BPF_SIZE(p->code)==BPF_W ? 2
                    : BPF_SIZE(p->code)==BPF_H ? 1 : 0);
                if (p->off < -512 || p->off>-(int)size) return -EINVAL;
            } else if (p->off<0 || p->off>MD_BPF_MAP_VALUE_MAX-8) return -EINVAL;
        } else if ((cls==BPF_STX || cls==BPF_ST) && BPF_MODE(p->code)==BPF_MEM) {
            unsigned size=1U<<(BPF_SIZE(p->code)==BPF_DW ? 3 : BPF_SIZE(p->code)==BPF_W ? 2
                : BPF_SIZE(p->code)==BPF_H ? 1 : 0);
            if (p->dst_reg!=10 || p->off < -512 || p->off>-(int)size
                    || (cls==BPF_STX ? p->imm : p->src_reg)) return -EINVAL;
        } else if (cls==BPF_ALU || cls==BPF_ALU64) {
            if (p->dst_reg==10 || p->off || op==BPF_END) return -EOPNOTSUPP;
            if (op!=BPF_MOV && op!=BPF_AND && op!=BPF_OR && op!=BPF_XOR && op!=BPF_ADD
                    && op!=BPF_SUB && op!=BPF_LSH && op!=BPF_RSH) return -EOPNOTSUPP;
        } else if (cls==BPF_JMP || cls==BPF_JMP32) {
            if (p->code==(BPF_JMP|BPF_CALL)) {
                if (p->dst_reg || p->src_reg || p->off) return -EINVAL;
                if (p->imm!=BPF_FUNC_map_lookup_elem || type!=BPF_PROG_TYPE_CGROUP_DEVICE) return -EOPNOTSUPP;
                if (i==n-1) return -EINVAL;
                continue;
            }
            if (p->code==(BPF_JMP|BPF_EXIT)) {
                if (p->dst_reg || p->src_reg || p->off || p->imm) return -EINVAL;
                continue;
            }
            if (op!=BPF_JA && op!=BPF_JEQ && op!=BPF_JNE && op!=BPF_JGT && op!=BPF_JGE
                    && op!=BPF_JLT && op!=BPF_JLE && op!=BPF_JSET) return -EOPNOTSUPP;
            if (p->off<0 || (unsigned)p->off>=n-i-1) return -EINVAL;
            if (!v[i+1+p->off].code) return -EINVAL;
        } else return -EOPNOTSUPP;
        if (i==n-1) return -EINVAL;
    }
    return 0;
}
struct md_cgroup_program *md_cgroup_program_new(struct md_cgroup_programs *owner,
        unsigned type,const struct bpf_insn *v,unsigned n,const char *name) {
    int r=validate(type,v,n,name);
    if (r) { errno=-r; return NULL; }
    struct md_cgroup_program *p=calloc(1,sizeof(*p)+n*sizeof(*v));
    if (!p) return NULL;
    p->owner=owner; p->refs=1; p->count=n; p->type=type; strcpy(p->name,name);
    /* Map operands have already been resolved to retained registry IDs, as
     * exposed by Linux's sanitized instruction dump, never host pointers. */
    memcpy(p->instructions,v,n*sizeof(*v));
    struct md_bpf_maps *maps=md_cgroup_program_maps(owner,0);
    for (unsigned i=0;!r && i<n;++i) if (v[i].code==(BPF_LD|BPF_IMM|BPF_DW)) {
        if (v[i].src_reg==BPF_PSEUDO_MAP_FD) {
            struct md_bpf_map *m=md_bpf_map_find(maps,(uint32_t)v[i].imm);
            if (!m) r=-EBADF;
            else {
                unsigned j=0; while (j<p->map_count && p->maps[j]!=m) ++j;
                if (j<p->map_count) md_bpf_map_release(m);
                else if (p->map_count==MD_BPF_MAPS_PER_PROGRAM) { md_bpf_map_release(m); r=-E2BIG; }
                else p->maps[p->map_count++]=m;
            }
        }
        ++i;
    }
    md_bpf_maps_release(maps);
    if (r) {
        for (unsigned i=0;i<p->map_count;++i) md_bpf_map_release(p->maps[i]);
        free(p); errno=-r; return NULL;
    }
    pthread_mutex_lock(&owner->lock);
    if (owner->count>=4096 || owner->next==UINT32_MAX) r=-ENOSPC;
    else {
        p->id=++owner->next; p->next=owner->first; owner->first=p; ++owner->count;
        md_cgroup_programs_retain(owner);
    }
    pthread_mutex_unlock(&owner->lock);
    if (r) {
        for (unsigned i=0;i<p->map_count;++i) md_bpf_map_release(p->maps[i]);
        free(p); errno=-r; return NULL;
    } return p;
}
struct md_cgroup_program *md_cgroup_program_retain(struct md_cgroup_program *p) {
    if (p) { pthread_mutex_lock(&p->owner->lock); ++p->refs; pthread_mutex_unlock(&p->owner->lock); }
    return p;
}
void md_cgroup_program_release(struct md_cgroup_program *p) {
    if (!p) return;
    struct md_cgroup_programs *owner=p->owner;
    pthread_mutex_lock(&owner->lock);
    int last=!--p->refs;
    if (last) {
        struct md_cgroup_program **at=&owner->first;
        while (*at!=p) at=&(*at)->next;
        *at=p->next; --owner->count;
    }
    pthread_mutex_unlock(&owner->lock);
    if (last) {
        for (unsigned i=0;i<p->map_count;++i) md_bpf_map_release(p->maps[i]);
        free(p); md_cgroup_programs_release(owner);
    }
}
struct md_cgroup_program *md_cgroup_program_find(struct md_cgroup_programs *owner,uint32_t id) {
    if (!owner) return NULL;
    pthread_mutex_lock(&owner->lock);
    struct md_cgroup_program *p=owner->first;
    while (p && p->id!=id) p=p->next;
    if (p) ++p->refs;
    pthread_mutex_unlock(&owner->lock); return p;
}
uint32_t md_cgroup_program_id(const struct md_cgroup_program *p) { return p->id; }
unsigned md_cgroup_program_type(const struct md_cgroup_program *p) { return p->type; }
int md_cgroup_program_belongs(const struct md_cgroup_program *p,const struct md_cgroup_programs *owner) {
    return p && p->owner==owner;
}
void md_cgroup_program_info(const struct md_cgroup_program *p,struct bpf_prog_info *info) {
    *info=(struct bpf_prog_info){.type=p->type,.id=p->id,
        .xlated_prog_len=p->count*sizeof(struct bpf_insn),.nr_map_ids=p->map_count};
    memcpy(info->name,p->name,sizeof(info->name));
}
void md_cgroup_program_map_ids(const struct md_cgroup_program *p,uint32_t *ids) {
    for (unsigned i=0;i<p->map_count;++i) {
        struct bpf_map_info info; md_bpf_map_info(p->maps[i],&info); ids[i]=info.id;
    }
}
size_t md_cgroup_program_instructions(const struct md_cgroup_program *p,void *out,size_t capacity) {
    size_t size=p->count*sizeof(*p->instructions);
    if (size>capacity) size=capacity;
    memcpy(out,p->instructions,size); return size;
}
static void *retain_program(void *p) { return md_cgroup_program_retain(p); }
static void release_program(void *p) { md_cgroup_program_release(p); }
static const struct md_bpf_handle_type handle_type={retain_program,release_program};
struct md_cgroup_program *md_cgroup_program_control(struct md_control_file file) {
    return md_bpf_handle_object(file,&handle_type);
}
int md_cgroup_program_open(struct md_cgroup_program *p,const struct md_identity *id,
        const struct md_control_file_ops **operations,void **context) {
    return md_bpf_handle_open(&handle_type,p,id,operations,context);
}
