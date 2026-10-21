#define _GNU_SOURCE
#include "svc_registry.h"
#include "entry_route.h"
#include "mapping_reader.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>

int md_svc_registry_read(pid_t pid,uintptr_t at,void *data,size_t size) {
    if (size>UINTPTR_MAX-at) return -EFAULT;
    struct iovec local={data,size},remote={(void *)at,size};
    if (process_vm_readv(pid,&local,1,&remote,1,0)==(ssize_t)size) return 0;
    for (size_t i=0;i<size;) {
        uintptr_t aligned=(at+i)&~(uintptr_t)7;
        size_t skip=(at+i)-aligned,bytes=8-skip;
        if (bytes>size-i) bytes=size-i;
        errno=0; uint64_t value=ptrace(PTRACE_PEEKTEXT,pid,(void *)aligned,NULL);
        if (errno) return -errno;
        memcpy((char *)data+i,(char *)&value+skip,bytes); i+=bytes;
    }
    return 0;
}
int md_svc_registry_write(pid_t pid,uintptr_t at,const void *data,size_t size) {
    if (size>UINTPTR_MAX-at) return -EFAULT;
    for (size_t i=0;i<size;) {
        uintptr_t aligned=(at+i)&~(uintptr_t)7;
        size_t skip=(at+i)-aligned,bytes=8-skip;
        if (bytes>size-i) bytes=size-i;
        uint64_t value=0;
        if (skip || bytes<8) {
            int error=md_svc_registry_read(pid,aligned,&value,8);
            if (error) return error;
        }
        memcpy((char *)&value+skip,(const char *)data+i,bytes);
        if (ptrace(PTRACE_POKETEXT,pid,(void *)aligned,(void *)value)<0) return -errno;
        i+=bytes;
    }
    return 0;
}
int md_svc_registry_executable(pid_t pid,uintptr_t address,size_t size) {
    if (!size || size>UINTPTR_MAX-address) return 0;
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/maps",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC); if (fd<0) return 0;
    struct md_mapping_reader reader={.fd=fd}; struct md_mapping_record v;
    uintptr_t cursor=address,end=address+size;
    while (cursor<end && md_mapping_next(&reader,&v)>0) {
        if (cursor<v.first) break;
        if (cursor>=v.end) continue;
        if ((v.protection&(PROT_WRITE|PROT_EXEC))!=PROT_EXEC || v.shared) break;
        cursor=v.end<end ? v.end : end;
    }
    close(fd); return cursor==end;
}
static struct md_svc_site *head(struct md_svc_registry *r,uintptr_t svc) {
    if (r) for (unsigned i=r->count;i;--i)
        if (r->sites[i-1].direct.svc==svc && r->sites[i-1].state==MD_SVC_PUBLISHED)
            return &r->sites[i-1];
    return NULL;
}
int md_svc_registry_active(struct md_svc_registry *r,uintptr_t svc) {
    return r && !r->disabled && head(r,svc);
}
static int extend(struct md_svc_registry *r,pid_t pid,uintptr_t svc,uint64_t number,
        struct md_svc_site *previous) {
    if (!r || r->disabled || (svc&3) || svc<4 || r->count==MD_SVC_SITES
            || (svc>=r->native_begin && svc<r->native_end)) return 0;
    for (unsigned i=0;i<r->pool_count;++i)
        if (svc-r->pools[i].address<MD_SVC_CODE_BYTES) return 0;
    struct md_svc_site *s=&r->sites[r->count++];
    s->state=MD_SVC_RETIRED;
    s->direct.svc=svc;
    uint32_t original;
    if (md_svc_registry_read(pid,svc,&original,4) || original!=UINT32_C(0xd4000001)
            || !md_svc_registry_executable(pid,svc,4)) return 0;
    size_t size=md_svc_direct_signal_size();
    unsigned char code[2048];
    if (size+8>sizeof(code)) return -E2BIG;
    for (unsigned i=0;i<r->pool_count;++i) {
        struct md_svc_code_pool *pool=&r->pools[i];
        if (pool->used+size+8>MD_SVC_CODE_BYTES) continue;
        uintptr_t gate=pool->address+pool->used,alias=gate+size;
        struct md_svc_direct_context context={svc,gate,r->frames,number};
        struct md_svc_direct_fallback exits={previous ? previous->direct.gate : alias,alias,alias};
        uint32_t replacement;
        int error=md_svc_direct_signal_plan(&context,r->dispatch,exits,code,sizeof(code),&replacement);
        if (!error) error=md_svc_direct_kernel(svc,alias,(void *)(code+size));
        if (error) continue;
        error=md_svc_registry_write(pid,gate,code,size+8);
        if (error) return error;
        /* Publish only after the complete resident gate is visible. The
         * caller is stopped at this exact SVC; no predecessor is rewritten. */
        error=md_svc_registry_write(pid,svc,&replacement,4);
        if (error) return error;
        s->direct=context;
        s->original=original; s->replacement=replacement; s->kernel_alias=alias;
        s->state=MD_SVC_PUBLISHED;
        pool->used+=(size+8+15)&~(size_t)15;
        return 1;
    }
    return 0;
}
int md_svc_registry_direct(struct md_svc_registry *r,pid_t pid,uintptr_t svc,uint64_t number) {
    if (!r) return 0;
    for (unsigned i=0;i<r->count;++i) if (r->sites[i].direct.svc==svc) return 0;
    return extend(r,pid,svc,number,NULL);
}
int md_svc_registry_suspend(struct md_svc_registry *r,pid_t pid,uintptr_t svc) {
    struct md_svc_site *s=head(r,svc);
    if (!s) return 0;
    uint32_t current;
    int error=md_svc_registry_read(pid,svc,&current,4);
    if (!error && current==s->replacement)
        error=md_svc_registry_write(pid,svc,&s->original,4);
    return error;
}
int md_svc_registry_resume(struct md_svc_registry *r,pid_t pid,uintptr_t svc,uint64_t number) {
    struct md_svc_site *s=head(r,svc);
    if (!s || r->disabled) return 0;
    uint32_t current;
    int error=md_svc_registry_read(pid,svc,&current,4);
    if (error || current!=s->original) return error;
    int known=0;
    for (unsigned i=0;i<r->count;++i)
        known|=r->sites[i].state==MD_SVC_PUBLISHED && r->sites[i].direct.svc==svc
            && r->sites[i].direct.number==number;
    if (!known && md_entry_supported((int)number)) {
        error=extend(r,pid,svc,number,s);
        if (error) return error<0 ? error : 0;
    }
    return md_svc_registry_write(pid,svc,&s->replacement,4);
}
struct md_svc_site *md_svc_registry_direct_at(struct md_svc_registry *r,pid_t pid,uintptr_t pc,uintptr_t sp) {
    if (!r) return NULL;
    uintptr_t owner=0;
    if (sp>r->frames && sp<=r->frames+MD_SVC_POOL_SIZE) {
        uintptr_t frame=(sp-1)&~(uintptr_t)(MD_SVC_SLOT_SIZE-1);
        uint64_t busy;
        if (md_svc_registry_read(pid,frame,&busy,8) || !busy
                || md_svc_registry_read(pid,frame+MD_SVC_OWNER_OFFSET,&owner,8)) owner=0;
    }
    for (unsigned i=0;i<r->count;++i) {
        struct md_svc_site *s=&r->sites[i];
        /* Retirement removes entry, not a peer's resident continuation. */
        if (s->direct.gate && (owner==s->direct.gate
                || (pc>=s->direct.gate && pc<=s->kernel_alias+4))) return s;
    }
    return NULL;
}
uintptr_t md_svc_registry_call_origin(const struct md_svc_registry *r,uintptr_t pc) {
    if (!r) return pc;
    int resident=0;
    for (unsigned i=0;i<r->pool_count;++i)
        resident|=pc-r->pools[i].address<r->pools[i].used;
    if (!resident) return pc;
    for (unsigned i=0;i<r->count;++i) {
        const struct md_svc_site *s=&r->sites[i];
        /* A retired gate can still hold a peer's interrupted syscall. Only
         * its exact post-SVC PC has the original call's identity. */
        if (s->direct.gate && pc==s->kernel_alias+4) return s->direct.svc+4;
    }
    return pc;
}
int md_svc_registry_retire(struct md_svc_registry *r,struct md_svc_site *s,pid_t pid) {
    if (!r || !s || s->state!=MD_SVC_PUBLISHED) return 0;
    uint32_t current;
    int error=md_svc_registry_read(pid,s->direct.svc,&current,4);
    if (!error && current==s->replacement)
        error=md_svc_registry_write(pid,s->direct.svc,&s->original,4);
    if (!error) s->state=MD_SVC_RETIRED;
    return error;
}
int md_svc_registry_revoke(struct md_svc_registry *r,pid_t pid) {
    if (!r || r->disabled) return 0;
    r->disabled=1;
    uint64_t zero=0;
    int error=md_svc_registry_write(pid,r->frames+MD_SVC_POOL_SIZE+
        offsetof(struct md_svc_payload_state,admitted),&zero,8);
    for (unsigned i=0;!error && i<r->count;++i) error=md_svc_registry_retire(r,&r->sites[i],pid);
    return error;
}
int md_svc_registry_unpatch(struct md_svc_registry *r,pid_t pid,uintptr_t start,size_t size) {
    if (!r || !size) return 0;
    for (unsigned i=0;i<r->count;++i) {
        struct md_svc_site *s=&r->sites[i];
        if (s->direct.svc>=start && s->direct.svc-start<size) {
            int error=md_svc_registry_retire(r,s,pid);
            if (error) return error;
        }
    }
    return 0;
}
int md_svc_registry_retire_client(pid_t pid,uintptr_t base) {
    struct md_svc_payload_state state;
    if (md_svc_registry_read(pid,base,&state,sizeof(state))) return 0;
    for (unsigned i=0;i<MD_SVC_PAYLOAD_CLIENTS;++i) if (state.clients[i].tid==(uint64_t)pid) {
        uintptr_t at=base+offsetof(struct md_svc_payload_state,clients)+i*sizeof(state.clients[0]);
        uint64_t zero=0;
        /* Publish the empty owner last: another thread can then claim this
         * slot without inheriting the retiring thread's opaque handle. */
        for (size_t j=sizeof(state.clients[0]);j;j-=sizeof(zero)) {
            int error=md_svc_registry_write(pid,at+j-sizeof(zero),&zero,sizeof(zero));
            if (error) return error;
        }
        ++state.retired_clients;
        return md_svc_registry_write(pid,base+offsetof(struct md_svc_payload_state,retired_clients),
            &state.retired_clients,sizeof(state.retired_clients));
    }
    return 0;
}
struct md_svc_registry *md_svc_registry_new(uintptr_t frames,uintptr_t dispatch) {
    if (!frames || (frames&(MD_SVC_POOL_SIZE-1)) || !dispatch || (dispatch&3)
            || frames>UINTPTR_MAX-MD_SVC_POOL_SIZE-MD_SVC_PAYLOAD_SIZE) return NULL;
    struct md_svc_registry *r=calloc(1,sizeof(*r));
    if (r) { r->frames=frames; r->dispatch=dispatch; }
    return r;
}
struct md_svc_registry *md_svc_registry_copy(const struct md_svc_registry *r) {
    if (!r) return NULL;
    struct md_svc_registry *copy=malloc(sizeof(*copy));
    if (copy) *copy=*r;
    return copy;
}
int md_svc_registry_pool(struct md_svc_registry *r,uintptr_t address) {
    if (!r || !address || (address&65535) || address>UINTPTR_MAX-MD_SVC_CODE_BYTES) return -EINVAL;
    for (unsigned i=0;i<r->pool_count;++i)
        if (r->pools[i].address==address) return -EEXIST;
    if (r->pool_count==MD_SVC_CODE_POOLS) return -ENOSPC;
    r->pools[r->pool_count++]=(struct md_svc_code_pool){.address=address}; return 0;
}
