#ifndef MD_LAB_SVC_EDGE_H
#define MD_LAB_SVC_EDGE_H
#include <stdint.h>
#include <stddef.h>
/* Relocates only an untouched private-frame template, before guest literals. */
int md_svc_frame_relocate(unsigned char *,size_t,uintptr_t);

struct md_svc_edge {
    uintptr_t call,callee,svc,stub,frames;
    size_t size,prefix_offset,prefix_count;
};
size_t md_svc_edge_size(void);
size_t md_svc_single_size(void);
/* A witnessed nonfaulting overwrite of x1..x29, reproducible after result x0
 * has changed. No read of the old destination or x0; never an adjacent literal. */
int md_svc_single_plan(uintptr_t svc,uint32_t prefix,uintptr_t destination,uintptr_t dispatch,uintptr_t frames,
    void *code,size_t capacity,uint32_t *replacement,struct md_svc_edge *entry);
/* Pure code generation, never mapping/admission. The owner must witness the
 * BL edge and retain the complete callee prefix's executable mapping identity.
 * No assumptions about symbol names, libc, language, or the caller's stack. */
int md_svc_edge_plan(uintptr_t call,uint32_t instruction,uintptr_t callee,
    const uint32_t *prefix,size_t count,uintptr_t destination,uintptr_t dispatch,uintptr_t frames,
    void *code,size_t capacity,uint32_t *replacement,struct md_svc_edge *edge);
/* Only the relocated prefix, before register capture or any syscall effect.
 * A matching owner may restore LR=call+4, release its frame, then deliver the
 * fault at this PC. Other phases need completion-aware signal ownership. */
uintptr_t md_svc_edge_prefix_pc(const struct md_svc_edge *edge,uintptr_t pc);
#endif
