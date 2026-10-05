#ifndef MD_TASK_REGISTRY_H
#define MD_TASK_REGISTRY_H
#include "guest_identity.h"
#include "guest_domain.h"

struct md_task_registry;
struct md_task_registry *md_task_registry_create(void);
void md_task_registry_destroy(struct md_task_registry *);
int md_task_registry_publish(struct md_task_registry *, pid_t tid, pid_t tgid,
        const struct md_identity *, struct md_guest_domain *);
void md_task_registry_forget(struct md_task_registry *, pid_t tid);
/* peer==0 is a kernel-notification/internal caller. RPC callers must own the
 * TID's thread group; the supervisor may request on behalf of its tracee. */
int md_task_registry_read(struct md_task_registry *, pid_t tid, pid_t peer,
        struct md_identity *, char root[33]);
int md_task_registry_set_root(struct md_task_registry *, pid_t tid, pid_t peer, const char root[33]);
#endif
