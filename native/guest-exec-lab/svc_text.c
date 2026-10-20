#define _GNU_SOURCE
#include "svc_text.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void md_svc_text_release(struct md_svc_text *text) {
    if (text->staging) munmap(text->staging,text->size);
    if (text->writer) munmap(text->writer,text->size);
    if (text->fd>=0) close(text->fd);
    *text=(struct md_svc_text){.fd=-1};
}
int md_svc_text_prepare(struct md_svc_text *text,int source,uint64_t offset,uintptr_t address,size_t size) {
    size_t page=(size_t)getpagesize();
    if (text->fd>=0 || text->writer || text->staging || !size || ((size|address|offset)&(page-1))
            || size>INT64_MAX || address>UINTPTR_MAX-size || offset>(uint64_t)INT64_MAX-size) return -EINVAL;
    struct md_svc_text next={.fd=-1,.address=address,.size=size};
    next.fd=memfd_create("svc-text",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (next.fd<0) return -errno;
    if (ftruncate(next.fd,(off_t)size)) goto failed;
    next.writer=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED,next.fd,0);
    if (next.writer==MAP_FAILED) { next.writer=NULL; goto failed; }
    size_t done=0;
    while (done<size) {
        ssize_t n=pread(source,(char *)next.writer+done,size-done,(off_t)(offset+done));
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { if (!n) errno=EIO; goto failed; }
        done+=(size_t)n;
    }
    if (fcntl(next.fd,F_ADD_SEALS,F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_FUTURE_WRITE|F_SEAL_SEAL)) goto failed;
    __builtin___clear_cache(next.writer,(char *)next.writer+size);
    next.staging=mmap(NULL,size,PROT_READ|PROT_EXEC,MAP_PRIVATE,next.fd,0);
    if (next.staging==MAP_FAILED) { next.staging=NULL; goto failed; }
    __builtin___clear_cache(next.staging,(char *)next.staging+size);
    *text=next;
    return 0;
failed: {
        int error=errno;
        md_svc_text_release(&next);
        return -error;
    }
}
int md_svc_text_activate(struct md_svc_text *text) {
    if (!text->staging) return -EINVAL;
    if (mremap(text->staging,text->size,text->size,MREMAP_MAYMOVE|MREMAP_FIXED,
            (void *)text->address)==MAP_FAILED) return -errno;
    text->staging=NULL;
    return 0;
}
int md_svc_text_map_new(struct md_svc_text *text) {
    if (!text->staging) return -EINVAL;
    void *mapped=mmap((void *)text->address,text->size,PROT_READ|PROT_EXEC,
        MAP_PRIVATE|MAP_FIXED_NOREPLACE,text->fd,0);
    if (mapped==MAP_FAILED) return -errno;
    if (mapped!=(void *)text->address) {
        munmap(mapped,text->size);
        return -EEXIST;
    }
    __builtin___clear_cache(mapped,(char *)mapped+text->size);
    munmap(text->staging,text->size);
    text->staging=NULL;
    return 0;
}
int md_svc_text_install(struct md_svc_text *text,int source,uint64_t offset,uintptr_t address,size_t size) {
    int result=md_svc_text_prepare(text,source,offset,address,size);
    if (result) return result;
    result=md_svc_text_activate(text);
    if (result) md_svc_text_release(text);
    return result;
}
static int eligible(uint32_t word) {
    return word==UINT32_C(0xd4000001) || (word&UINT32_C(0xfc000000))==UINT32_C(0x14000000);
}
int md_svc_text_publish(struct md_svc_text *text,uintptr_t site,uint32_t instruction) {
    if (!text->writer || text->staging || text->size<4 || (site&3) || site<text->address
            || site-text->address>text->size-4 || !eligible(instruction)) return -EINVAL;
    uint32_t *alias=(void *)((char *)text->writer+(site-text->address));
    if (!eligible(__atomic_load_n(alias,__ATOMIC_RELAXED))) return -EINVAL;
    __atomic_store_n(alias,instruction,__ATOMIC_RELEASE);
    /* Clean the writable alias before invalidating the executable alias.
     * Both aliases refer to one file page; no private COW is introduced. */
    __builtin___clear_cache((char *)alias,(char *)alias+4);
    __builtin___clear_cache((char *)site,(char *)site+4);
    return 0;
}
