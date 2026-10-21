#ifndef MD_TASK_CHECKPOINT_H
#define MD_TASK_CHECKPOINT_H
#include <stdint.h>
#include <sys/types.h>

/* Internal event, not a kernel signal or an application debugger stop. */
#define MD_TASK_CHECKPOINT_EVENT 256
#define MD_INTERCEPT_CHECKPOINT 55
#define MD_TASK_CHECKPOINT_BUCKETS 256
struct md_task_checkpoint;
struct md_task_checkpoints {
    struct md_task_checkpoint *buckets[MD_TASK_CHECKPOINT_BUCKETS];
    unsigned count;
    long (*trace)(int,pid_t,void *,void *);
    int (*restricted)(pid_t);
    int (*marker)(uintptr_t);
    uintptr_t begin,end;
};
long md_task_checkpoint_trace(struct md_task_checkpoints *,int,pid_t,void *,void *);
/* 1 consumed an intermediate stop; 0 publishes the original or typed
 * checkpoint event. Negative errno retains the actor for caller cleanup. */
int md_task_checkpoint_event(struct md_task_checkpoints *,pid_t,int *);
void md_task_checkpoints_clear(struct md_task_checkpoints *);
#endif
