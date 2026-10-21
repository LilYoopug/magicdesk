#ifndef MD_SVC_REGISTRY_H
#define MD_SVC_REGISTRY_H
#include "svc_payload.h"
#include "svc_runtime.h"
#include "svc_direct.h"
#include <sys/types.h>

enum { MD_SVC_SITES=128 };
struct md_svc_code_pool { uintptr_t address; size_t used; };
struct md_svc_site {
    struct md_svc_direct_context direct;
    uintptr_t kernel_alias;
    uint32_t original, replacement;
    unsigned state;
};
enum { MD_SVC_PUBLISHED, MD_SVC_RETIRED };
/* Owned by interception_memory. CLONE_VM shares the owner; fork copies it.
 * No guest-writable receipt is authority for code publication or retirement. */
struct md_svc_registry {
    uintptr_t frames, dispatch, native_begin, native_end;
    struct md_svc_code_pool pools[MD_SVC_CODE_POOLS];
    unsigned pool_count, count, disabled, entry_fence_drained;
    struct md_svc_site sites[MD_SVC_SITES];
};
struct md_svc_registry *md_svc_registry_new(uintptr_t frames,uintptr_t dispatch);
struct md_svc_registry *md_svc_registry_copy(const struct md_svc_registry *);
int md_svc_registry_pool(struct md_svc_registry *,uintptr_t);
int md_svc_registry_read(pid_t,uintptr_t,void *,size_t);
int md_svc_registry_write(pid_t,uintptr_t,const void *,size_t);
int md_svc_registry_executable(pid_t,uintptr_t,size_t);
int md_svc_registry_direct(struct md_svc_registry *,pid_t,uintptr_t svc,uint64_t number);
struct md_svc_site *md_svc_registry_direct_at(struct md_svc_registry *,pid_t,uintptr_t pc,uintptr_t sp);
uintptr_t md_svc_registry_call_origin(const struct md_svc_registry *,uintptr_t pc);
/* Decode a captured word for syscall replay, never arbitrary code at a former
 * site. Only an exact resident replacement has an owned original instruction. */
uint32_t md_svc_registry_instruction(const struct md_svc_registry *,uintptr_t pc,uint32_t word);
int md_svc_registry_retire(struct md_svc_registry *,struct md_svc_site *,pid_t);
int md_svc_registry_revoke(struct md_svc_registry *,pid_t);
/* Retired source instructions can still have peers inside resident gates. */
int md_svc_registry_resident(const struct md_svc_registry *);
int md_svc_registry_unpatch(struct md_svc_registry *,pid_t,uintptr_t,size_t);
int md_svc_registry_retire_client(pid_t,uintptr_t state);
int md_svc_registry_suspend(struct md_svc_registry *,pid_t,uintptr_t svc);
int md_svc_registry_resume(struct md_svc_registry *,pid_t,uintptr_t svc,uint64_t number);
#endif
