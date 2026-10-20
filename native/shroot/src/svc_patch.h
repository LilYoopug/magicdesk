#ifndef MD_LAB_SVC_PATCH_H
#define MD_LAB_SVC_PATCH_H
#include <stdint.h>
#include <stddef.h>

/* A planner, not a disassembler or an authority to modify executable memory.
 * The owner must establish an executed SVC, mapping identity and publication. */
enum md_svc_prefix { MD_SVC_UNSUPPORTED, MD_SVC_MOV_IMMEDIATE, MD_SVC_MOV_REGISTER, MD_SVC_LOAD };
struct md_svc_instruction { enum md_svc_prefix kind; uint32_t reads,writes; };
struct md_svc_instruction md_svc_decode(uint32_t instruction);
enum md_svc_prefix md_svc_prefix(uint32_t instruction);
/* Number of adjacent, understood instructions preparing the SVC, and the
 * distance to the last x8 definition. Candidate evidence, not permission to
 * replace multiple instructions or evidence of executed predecessor edges. */
struct md_svc_window { unsigned understood,number_distance; };
struct md_svc_window md_svc_window(const uint32_t *instructions,size_t count);
int md_svc_branch(uintptr_t from,uintptr_t to,uint32_t *instruction);
int md_svc_forward(uintptr_t svc,uintptr_t trampoline,const uint32_t original[2],
        uint32_t *replacement,uint32_t code[2]);
/* Signals must see original instruction boundaries. Especially for loads,
 * recognition without this relocation map is NOT sufficient to publish. */
uintptr_t md_svc_original_pc(uintptr_t svc,uintptr_t stub,uintptr_t pc,int counted);
#endif
