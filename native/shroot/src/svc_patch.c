#include "svc_patch.h"
#include <errno.h>
#include <limits.h>

struct md_svc_instruction md_svc_decode(uint32_t i) {
    struct md_svc_instruction result={0};
    unsigned dest=i&31,source=(i>>16)&31;
    uint32_t write=dest==31 ? 0 : UINT32_C(1)<<dest;
    /* MOVZ/MOVN/MOVK, with architectural width/shift validation.
     * This can prepare an argument, not just x8.
     * Recognition is ISA-based; it does not assume a libc syscall wrapper. */
    if ((i&UINT32_C(0x1f800000))==UINT32_C(0x12800000)
            && ((i>>29)&3)!=1 && ((i>>31) || !((i>>22)&1)))
        return (struct md_svc_instruction){MD_SVC_MOV_IMMEDIATE,((i>>29)&3)==3 ? write : 0,write};
    /* MOV Wd/Wn or Xd/Xn (ORR with ZR). Do not accept shifted operands. */
    if ((i&UINT32_C(0xffe0ffe0))==UINT32_C(0xaa0003e0)
            || (i&UINT32_C(0xffe0ffe0))==UINT32_C(0x2a0003e0))
        return (struct md_svc_instruction){MD_SVC_MOV_REGISTER,source==31 ? 0 : UINT32_C(1)<<source,write};
    /* ORR Xd/Wd, ZR, #bitmask (another assembler encoding of MOV). */
    if ((i&UINT32_C(0xff8003e0))==UINT32_C(0xb20003e0)
            || (i&UINT32_C(0xff8003e0))==UINT32_C(0x320003e0)) {
        unsigned imms=(i>>10)&63,n=(i>>22)&1,bits=(n<<6)|(~imms&63),length=0;
        while (bits>>1) { bits>>=1; ++length; }
        unsigned levels=(1u<<length)-1;
        if (length && ((i>>31) || (length<=5 && !n)) && (imms&levels)!=levels)
            return (struct md_svc_instruction){MD_SVC_MOV_IMMEDIATE,0,write};
    }
    /* LDR Wd/Xd, [Xn/SP, #unsigned-offset], without writeback. Trampoline
     * executes this before changing SP/registers. Its fault PC is relocated. */
    if ((i&UINT32_C(0xffc00000))==UINT32_C(0xf9400000)
            || (i&UINT32_C(0xffc00000))==UINT32_C(0xb9400000))
        return (struct md_svc_instruction){MD_SVC_LOAD,1u<<((i>>5)&31),write};
    return result;
}
enum md_svc_prefix md_svc_prefix(uint32_t i) { return md_svc_decode(i).kind; }
struct md_svc_window md_svc_window(const uint32_t *code,size_t count) {
    struct md_svc_window result={0};
    if (!code || !count || code[count-1]!=UINT32_C(0xd4000001)) return result;
    for (size_t at=count-1;at;--at) {
        struct md_svc_instruction instruction=md_svc_decode(code[at-1]);
        if (!instruction.kind) break;
        ++result.understood;
        if (!result.number_distance && (instruction.writes&(1u<<8)))
            result.number_distance=result.understood;
    }
    return result;
}
int md_svc_branch(uintptr_t from,uintptr_t to,uint32_t *out) {
    if (!out || ((from|to)&3)) return -EINVAL;
    uint64_t distance=from>to ? from-to : to-from;
    if (distance>(UINT64_C(1)<<27)-(to>=from ? 4 : 0)) return -ERANGE;
    int64_t words=to>=from ? (int64_t)(distance/4) : -(int64_t)(distance/4);
    *out=UINT32_C(0x14000000)|((uint32_t)words&UINT32_C(0x03ffffff));
    return 0;
}
int md_svc_forward(uintptr_t svc,uintptr_t trampoline,const uint32_t original[2],
        uint32_t *replacement,uint32_t code[2]) {
    if (!original || !replacement || !code || svc<4 || trampoline>UINTPTR_MAX-4
            || original[1]!=UINT32_C(0xd4000001) || !md_svc_prefix(original[0])) return -EINVAL;
    uint32_t jump,back;
    int error=md_svc_branch(svc-4,trampoline,&jump);
    if (!error) error=md_svc_branch(trampoline+4,svc,&back);
    if (error) return error;
    code[0]=original[0]; code[1]=back; *replacement=jump;
    return 0;
}
uintptr_t md_svc_original_pc(uintptr_t svc,uintptr_t stub,uintptr_t pc,int counted) {
    if (pc==stub) return svc-4;
    if (pc==stub+4 || (counted && pc==stub+8)) return svc;
    return pc;
}
