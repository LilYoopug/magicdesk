#ifndef MD_SVC_DISCOVERY_H
#define MD_SVC_DISCOVERY_H
#include "svc_registry.h"
#include <asm/ptrace.h>
struct md_svc_witness {
    struct md_svc_site *site;
    struct user_hwdebug_state debug;
};
int md_svc_discovery_observe(struct md_svc_registry *,struct md_svc_witness *,pid_t,uintptr_t,uintptr_t);
int md_svc_discovery_event(struct md_svc_witness *,pid_t,int);
int md_svc_discovery_cancel(struct md_svc_witness *,pid_t);
#endif
