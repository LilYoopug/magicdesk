#ifndef MD_LAB_SVC_LIFECYCLE_H
#define MD_LAB_SVC_LIFECYCLE_H
#include "svc_payload.h"
#include <sys/resource.h>

/* Cold prototype owner. The supervisor selects members by its existing mm
 * identity; the shared lab receipt is never used to infer CLONE_VM ownership. */
struct md_svc_lifecycle;
struct md_svc_registry;
struct md_svc_site;
struct md_svc_lifecycle *md_svc_lifecycle_update(pid_t,int,const struct rusage *,
    struct md_svc_registry *,struct md_svc_site *,long (*)(int,pid_t,void *,void *));
int md_svc_lifecycle_publication(const struct md_svc_lifecycle *);
int md_svc_lifecycle_overlap(const struct md_svc_signal_window *,long,const uint64_t *);
int md_svc_lifecycle_patched(pid_t,const struct md_svc_signal_window *);
struct md_svc_lifecycle *md_svc_lifecycle_new(pid_t,pid_t,int,const struct rusage *,
    const struct md_svc_signal_window *,long (*)(int,pid_t,void *,void *));
int md_svc_lifecycle_add(struct md_svc_lifecycle *,pid_t,int,int,int,uintptr_t,uintptr_t);
struct md_task_quiesce *md_svc_lifecycle_barrier(struct md_svc_lifecycle *);
int md_svc_lifecycle_starting(const struct md_svc_lifecycle *);
int md_svc_lifecycle_stop(struct md_svc_lifecycle *);
int md_svc_lifecycle_event(struct md_svc_lifecycle *,pid_t,int,const struct rusage *);
int md_svc_lifecycle_progress(struct md_svc_lifecycle *);
pid_t md_svc_lifecycle_take(struct md_svc_lifecycle *,int *,struct rusage *);
int md_svc_lifecycle_done(const struct md_svc_lifecycle *);
void md_svc_lifecycle_destroy(struct md_svc_lifecycle *);
#endif
