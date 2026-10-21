#ifndef MD_SVC_PATCH_H
#define MD_SVC_PATCH_H
#include <stdint.h>

/* Encoding only; the registry owns executable mapping admission/publication. */
int md_svc_branch(uintptr_t from,uintptr_t to,uint32_t *instruction);
#endif
