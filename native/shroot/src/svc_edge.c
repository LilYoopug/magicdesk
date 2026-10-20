#include "svc_edge.h"
#include "svc_patch.h"
#include "svc_borrowed.h"
#include <errno.h>
#include <string.h>
extern const unsigned char md_svc_edge_begin[],md_svc_edge_end[],md_svc_edge_prefix[];
extern const unsigned char md_svc_edge_return[],md_svc_edge_dispatch[];
extern const unsigned char md_svc_edge_state[];
extern const unsigned char md_svc_edge_done_branch[],md_svc_edge_kernel_branch[],md_svc_edge_busy_branch[];
size_t md_svc_edge_size(void) { return (size_t)(md_svc_edge_end-md_svc_edge_begin); }
uintptr_t md_svc_edge_prefix_pc(const struct md_svc_edge *e,uintptr_t pc) {
    uintptr_t first=e->stub+e->prefix_offset;
    if ((pc&3) || pc<first || pc-first>=e->prefix_count*4) return pc;
    return e->callee+pc-first;
}
static size_t offset(const unsigned char *label) { return (size_t)(label-md_svc_edge_begin); }
/* Only our untouched templates are relocated here, before inserting guest
 * instructions or literals. Every MOVK belongs to a frame-base construction. */
int md_svc_frame_relocate(unsigned char *code,size_t size,uintptr_t frames) {
    if (!frames || (frames&(MD_SVC_POOL_SIZE-1)) || frames>UINTPTR_MAX-MD_SVC_POOL_SIZE-65536)
        return -EINVAL;
    unsigned pieces[3]={0};
    for (size_t at=0;at+4<=size;at+=4) {
        uint32_t word; memcpy(&word,code+at,4);
        if ((word&UINT32_C(0xff800000))!=UINT32_C(0xf2800000)) continue;
        unsigned half=(word>>21)&3;
        if (!half) return -EINVAL;
        word=(word&~UINT32_C(0x001fffe0))|(((frames>>(half*16))&65535)<<5);
        memcpy(code+at,&word,4); ++pieces[half-1];
    }
    return pieces[0] && pieces[0]==pieces[1] && pieces[1]==pieces[2] ? 0 : -EINVAL;
}
static int branch(unsigned char *code,uintptr_t base,const unsigned char *label,uintptr_t target) {
    uint32_t instruction;
    int error=md_svc_branch(base+offset(label),target,&instruction);
    if (!error) memcpy(code+offset(label),&instruction,sizeof(instruction));
    return error;
}
int md_svc_edge_plan(uintptr_t call,uint32_t instruction,uintptr_t callee,
        const uint32_t *prefix,size_t count,uintptr_t destination,uintptr_t dispatch,uintptr_t frames,
        void *output,size_t capacity,uint32_t *replacement,struct md_svc_edge *edge) {
    size_t size=md_svc_edge_size();
    if (!prefix || !count || count>17 || !output || !replacement || !edge || !dispatch
            || ((call|callee|destination|dispatch)&3) || call>UINTPTR_MAX-4
            || callee>UINTPTR_MAX-count*4 || destination>UINTPTR_MAX-size) return -EINVAL;
    if (capacity<size) return -ENOSPC;
    uint32_t original;
    int error=md_svc_branch(call,callee,&original);
    if (error || instruction!=(original|UINT32_C(0x80000000))) return -EINVAL;
    if (prefix[count-1]!=UINT32_C(0xd4000001)) return -EINVAL;
    for (size_t i=0;i<count-1;++i) {
        struct md_svc_instruction d=md_svc_decode(prefix[i]);
        if (!d.kind || (d.writes&(UINT32_C(3)<<30))) return -ENOTSUP;
    }
    uint32_t replacement_word;
    error=md_svc_branch(call,destination,&replacement_word);
    if (error) return error;
    unsigned char *code=output;
    memcpy(code,md_svc_edge_begin,size);
    error=md_svc_frame_relocate(code,size,frames);
    if (error) return error;
    memcpy(code+offset(md_svc_edge_prefix),prefix,(count-1)*4);
    uintptr_t resume=call+4,svc=callee+(count-1)*4;
    memcpy(code+offset(md_svc_edge_return),&resume,sizeof(resume));
    memcpy(code+offset(md_svc_edge_dispatch),&dispatch,sizeof(dispatch));
    uintptr_t state=frames+MD_SVC_POOL_SIZE;
    memcpy(code+offset(md_svc_edge_state),&state,sizeof(state));
    error=branch(code,destination,md_svc_edge_done_branch,svc+4);
    if (!error) error=branch(code,destination,md_svc_edge_kernel_branch,svc);
    if (!error) error=branch(code,destination,md_svc_edge_busy_branch,callee);
    if (error) return error;
    *replacement=replacement_word;
    *edge=(struct md_svc_edge){call,callee,svc,destination,frames,size,offset(md_svc_edge_prefix),count-1};
    return 0;
}
extern const unsigned char md_svc_single_begin[],md_svc_single_end[],md_svc_single_prefix[],md_svc_single_dispatch[];
extern const unsigned char md_svc_single_state[];
extern const unsigned char md_svc_single_owner[];
extern const unsigned char md_svc_single_done_branch[],md_svc_single_kernel_branch[],md_svc_single_busy_branch[];
extern const unsigned char md_svc_single_done_replay[],md_svc_single_kernel_replay[],md_svc_single_busy_replay[];
size_t md_svc_single_size(void) { return (size_t)(md_svc_single_end-md_svc_single_begin); }
int md_svc_single_plan(uintptr_t svc,uint32_t prefix,uintptr_t destination,uintptr_t dispatch,uintptr_t frames,
        void *output,size_t capacity,uint32_t *replacement,struct md_svc_edge *entry) {
    size_t size=md_svc_single_size();
    if (!output || !replacement || !entry || !dispatch || svc<4 || svc>UINTPTR_MAX-4
            || ((svc|destination|dispatch)&3) || destination>UINTPTR_MAX-size) return -EINVAL;
    if (capacity<size) return -ENOSPC;
    struct md_svc_instruction d=md_svc_decode(prefix);
    unsigned scratch=prefix&31;
    if ((d.kind!=MD_SVC_MOV_IMMEDIATE && d.kind!=MD_SVC_MOV_REGISTER)
            || scratch<1 || scratch>29 || d.writes!=(1u<<scratch)
            || (d.reads&((1u<<scratch)|1))) return -ENOTSUP;
    uint32_t word;
    int error=md_svc_branch(svc-4,destination,&word);
    if (error) return error;
    unsigned char *code=output;
    memcpy(code,md_svc_single_begin+(scratch-1)*size,size);
    error=md_svc_frame_relocate(code,size,frames);
    if (error) return error;
    const unsigned char *replay[]={md_svc_single_prefix,md_svc_single_done_replay,
        md_svc_single_kernel_replay,md_svc_single_busy_replay};
    for (unsigned i=0;i<4;++i) memcpy(code+(replay[i]-md_svc_single_begin),&prefix,4);
    memcpy(code+(md_svc_single_dispatch-md_svc_single_begin),&dispatch,sizeof(dispatch));
    uintptr_t state=frames+MD_SVC_POOL_SIZE;
    memcpy(code+(md_svc_single_state-md_svc_single_begin),&state,sizeof(state));
    uintptr_t owner=svc-4;
    memcpy(code+(md_svc_single_owner-md_svc_single_begin),&owner,sizeof(owner));
    const unsigned char *branches[]={md_svc_single_done_branch,md_svc_single_kernel_branch,md_svc_single_busy_branch};
    for (unsigned i=0;i<3;++i) {
        size_t at=(size_t)(branches[i]-md_svc_single_begin);
        uint32_t jump;
        error=md_svc_branch(destination+at,svc+(i ? 0 : 4),&jump);
        if (error) return error;
        memcpy(code+at,&jump,4);
    }
    *replacement=word;
    *entry=(struct md_svc_edge){svc-4,svc,svc,destination,frames,size,0,0};
    return 0;
}
