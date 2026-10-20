#ifndef MD_SVC_TEXT_H
#define MD_SVC_TEXT_H
#include <stddef.h>
#include <stdint.h>

/* Lab backing owner. The caller supplies an immutable, pristine file range and
 * serializes mapping mutations. This does not admit externally writable code. */
struct md_svc_text {
    int fd;
    void *writer;
    void *staging;
    uintptr_t address;
    size_t size;
};
int md_svc_text_prepare(struct md_svc_text *,int source,uint64_t offset,uintptr_t address,size_t size);
int md_svc_text_map_new(struct md_svc_text *);
/* Live replacement is an experiment, not failure-atomic admission: the kernel
 * can discard the destination before a later allocation fails. A loader uses
 * map_new (or its own not-yet-published reservation) instead. */
int md_svc_text_activate(struct md_svc_text *);
int md_svc_text_install(struct md_svc_text *,int source,uint64_t offset,uintptr_t address,size_t size);
int md_svc_text_publish(struct md_svc_text *,uintptr_t site,uint32_t instruction);
void md_svc_text_release(struct md_svc_text *);
#endif
