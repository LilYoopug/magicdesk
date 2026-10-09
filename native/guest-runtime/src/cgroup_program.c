#define _GNU_SOURCE
#include "cgroup_program.h"
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
};
struct md_cgroup_program {
    struct md_cgroup_program *next;
    struct md_cgroup_programs *owner;
    unsigned refs,count,type;
    uint32_t id;
    char name[BPF_OBJ_NAME_LEN];
};
struct opened { atomic_uint refs; struct md_cgroup_program *program; struct stat stat; };
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
    pthread_mutex_destroy(&p->lock); free(p);
}
/* Bounded forward-only device predicates, without maps, helper calls, stack
 * access or arbitrary memory. This is admission for a permissive provider,
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
        if (p->dst_reg>9 || p->src_reg>9) return -EINVAL;
        if (p->code==(BPF_LDX|BPF_MEM|BPF_W)) {
            if (type!=BPF_PROG_TYPE_CGROUP_DEVICE) return -EOPNOTSUPP;
            if (p->src_reg!=1 || p->off<0 || p->off>8 || p->off%4 || p->imm) return -EINVAL;
        } else if (cls==BPF_ALU || cls==BPF_ALU64) {
            if (p->off || op==BPF_END) return -EOPNOTSUPP;
            if (op!=BPF_MOV && op!=BPF_AND && op!=BPF_OR && op!=BPF_XOR && op!=BPF_ADD
                    && op!=BPF_SUB && op!=BPF_LSH && op!=BPF_RSH) return -EOPNOTSUPP;
        } else if (cls==BPF_JMP || cls==BPF_JMP32) {
            if (p->code==(BPF_JMP|BPF_EXIT)) {
                if (p->dst_reg || p->src_reg || p->off || p->imm) return -EINVAL;
                continue;
            }
            if (op!=BPF_JA && op!=BPF_JEQ && op!=BPF_JNE && op!=BPF_JGT && op!=BPF_JGE
                    && op!=BPF_JLT && op!=BPF_JLE && op!=BPF_JSET) return -EOPNOTSUPP;
            if (p->off<0 || (unsigned)p->off>=n-i-1) return -EINVAL;
        } else return -EOPNOTSUPP;
        if (i==n-1) return -EINVAL;
    }
    return 0;
}
struct md_cgroup_program *md_cgroup_program_new(struct md_cgroup_programs *owner,
        unsigned type,const struct bpf_insn *v,unsigned n,const char *name) {
    int r=validate(type,v,n,name);
    if (r) { errno=-r; return NULL; }
    struct md_cgroup_program *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    p->owner=owner; p->refs=1; p->count=n; p->type=type; strcpy(p->name,name);
    pthread_mutex_lock(&owner->lock);
    if (owner->count>=4096 || owner->next==UINT32_MAX) r=-ENOSPC;
    else {
        p->id=++owner->next; p->next=owner->first; owner->first=p; ++owner->count;
        md_cgroup_programs_retain(owner);
    }
    pthread_mutex_unlock(&owner->lock);
    if (r) { free(p); errno=-r; return NULL; } return p;
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
    if (last) { free(p); md_cgroup_programs_release(owner); }
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
        .xlated_prog_len=p->count*sizeof(struct bpf_insn)};
    memcpy(info->name,p->name,sizeof(info->name));
}
static void *opened_retain(void *data) { struct opened *o=data; atomic_fetch_add(&o->refs,1); return o; }
static void opened_release(void *data) {
    struct opened *o=data;
    if (atomic_fetch_sub(&o->refs,1)==1) { md_cgroup_program_release(o->program); free(o); }
}
static int opened_stat(void *data,struct stat *st) { *st=((struct opened *)data)->stat; return 0; }
static int opened_access(void *data,const struct md_identity *id,unsigned mode) {
    const struct stat *st=&((struct opened *)data)->stat;
    if (mode&X_OK) return -EACCES;
    return !mode || id->uid.fs==st->st_uid
        || md_identity_file_capable(id,st->st_uid,st->st_gid,CAP_DAC_OVERRIDE) ? 0 : -EACCES;
}
static long opened_read(void *data,const struct md_control_actor *actor,void *out,size_t size,int64_t off) {
    (void)data; (void)actor; (void)out; (void)size; (void)off; return -EINVAL;
}
static long opened_write(void *data,const struct md_control_actor *actor,const void *in,size_t size,int64_t offset) {
    (void)offset;
    (void)data; (void)actor; (void)in; (void)size; return -EINVAL;
}
static const struct md_control_file_ops ops={.retain=opened_retain,.release=opened_release,
    .access=opened_access,.stat=opened_stat,.read=opened_read,.write=opened_write,
    .filesystem=ANON_INODE_FS_MAGIC,.nonseekable=1};
struct md_cgroup_program *md_cgroup_program_control(struct md_control_file file) {
    return file.ops==&ops ? ((struct opened *)file.context)->program : NULL;
}
int md_cgroup_program_open(struct md_cgroup_program *p,const struct md_identity *id,
        const struct md_control_file_ops **operations,void **context) {
    struct opened *o=calloc(1,sizeof(*o));
    if (!o) return -ENOMEM;
    atomic_init(&o->refs,1); o->program=md_cgroup_program_retain(p);
    int fd=memfd_create("cgroup-program",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    int r=fd<0 ? -errno : fstat(fd,&o->stat) ? -errno : 0;
    if (!r && fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)) r=-errno;
    o->stat.st_mode=S_IFREG|0600;
    o->stat.st_uid=id->uid.fs; o->stat.st_gid=id->gid.fs;
    if (r) { if (fd>=0) close(fd); opened_release(o); return r; }
    *operations=&ops; *context=o; return fd;
}
