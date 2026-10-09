#ifndef MD_TASK_QUIESCE_H
#define MD_TASK_QUIESCE_H
#include <sys/resource.h>
#include <sys/types.h>

struct md_task_quiesce;
/* A cold launch-tree barrier. Real wait events retain their exact order and
 * rusage for the normal dispatcher; only our synthetic interrupt is consumed.
 * Already stopped/listening tasks stay stopped. A kernel-blocked vfork parent
 * also qualifies: mandatory TRACEVFORKDONE stops it before userspace resumes.
 * No policy callbacks run here. */
struct md_task_quiesce *md_task_quiesce_new(long (*trace)(int,pid_t,void *,void *));
void md_task_quiesce_destroy(struct md_task_quiesce *);
/* Zero resume_request means an external owner already awaits a stop (including
 * a requested interrupt or newborn). Do not interrupt or resume it ourselves. */
int md_task_quiesce_add(struct md_task_quiesce *, pid_t, int stopped, int resume_request);
int md_task_quiesce_stop(struct md_task_quiesce *);
int md_task_quiesce_ready(const struct md_task_quiesce *);
void md_task_quiesce_describe(const struct md_task_quiesce *, int fd);
int md_task_quiesce_event(struct md_task_quiesce *, pid_t, int, const struct rusage *);
/* Releases only synthetic stops. Deferred events remain owned until take. */
int md_task_quiesce_release(struct md_task_quiesce *);
pid_t md_task_quiesce_take(struct md_task_quiesce *, int *, struct rusage *);
int md_task_quiesce_newborn(struct md_task_quiesce *, pid_t);
#endif
