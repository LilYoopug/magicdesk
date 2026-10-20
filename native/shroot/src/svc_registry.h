#ifndef MD_SVC_REGISTRY_H
#define MD_SVC_REGISTRY_H
#include "svc_payload.h"
#include "svc_runtime.h"
#include "svc_direct.h"
#include <sys/types.h>

enum { MD_SVC_SITES=128 };
struct md_svc_code_pool { uintptr_t address; size_t used; };
struct md_svc_site {
    struct md_svc_signal_window window;
    uint32_t prefix[17];
    unsigned count, observations, state;
    struct md_svc_direct_context direct;
};
enum { MD_SVC_CANDIDATE, MD_SVC_WITNESSED, MD_SVC_PUBLISHED, MD_SVC_RETIRED };
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
struct md_svc_site *md_svc_registry_observe(struct md_svc_registry *,uintptr_t svc);
/* Caller owns a stopped task and the address-space turn. An unsupported range
 * or exhausted code pool is optional admission loss, never a fatal launch. */
int md_svc_registry_plan(struct md_svc_registry *,struct md_svc_site *,pid_t,uintptr_t lr);
int md_svc_registry_publish(struct md_svc_registry *,struct md_svc_site *,pid_t);
const struct md_svc_signal_window *md_svc_registry_at(const struct md_svc_registry *,uintptr_t pc);
int md_svc_registry_read(pid_t,uintptr_t,void *,size_t);
int md_svc_registry_write(pid_t,uintptr_t,const void *,size_t);
int md_svc_registry_executable(pid_t,uintptr_t,size_t);
int md_svc_registry_direct(struct md_svc_registry *,pid_t,uintptr_t svc,uint64_t number);
struct md_svc_site *md_svc_registry_direct_at(struct md_svc_registry *,pid_t,uintptr_t pc,uintptr_t sp);
uintptr_t md_svc_registry_call_origin(const struct md_svc_registry *,uintptr_t pc);
int md_svc_registry_retire(struct md_svc_registry *,struct md_svc_site *,pid_t);
int md_svc_registry_revoke(struct md_svc_registry *,pid_t);
int md_svc_registry_unpatch(struct md_svc_registry *,pid_t,uintptr_t,size_t);
int md_svc_registry_retire_client(pid_t,uintptr_t state);
int md_svc_registry_suspend(struct md_svc_registry *,pid_t,uintptr_t svc);
int md_svc_registry_resume(struct md_svc_registry *,pid_t,uintptr_t svc,uint64_t number);
int md_svc_registry_active(struct md_svc_registry *,uintptr_t svc);
#endif
