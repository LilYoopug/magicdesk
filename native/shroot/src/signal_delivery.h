#ifndef MD_SIGNAL_DELIVERY_H
#define MD_SIGNAL_DELIVERY_H
#include <signal.h>
#include <sys/types.h>
#include <stdint.h>

struct md_signal_delivery_node;
struct md_signal_delivery {
    struct md_signal_delivery_node *first,*last;
    struct md_signal_delivery_node *realtime;
    unsigned carriers[NSIG];
    uintptr_t carrier_cookie;
    uint64_t mask, kernel_mask;
    int active;
};
/* Standard signals coalesce without losing the first siginfo. Realtime
 * instances retain FIFO order per signal, ahead of subsequent kernel arrivals. */
int md_signal_delivery_hold(struct md_signal_delivery *,const siginfo_t *);
/* A shielded delivery stop: retain a signal in the queue, or return
 * the same blocked job-control signal for native requeue. Negative errno is a
 * failure. The caller must resume with the nonnegative return value. */
int md_signal_delivery_retain(struct md_signal_delivery *,pid_t,const siginfo_t *);
static inline int md_signal_delivery_pending(const struct md_signal_delivery *q) {
    return q->first || q->realtime || q->kernel_mask;
}
/* Start only at a restored guest boundary; resume with CONT. The kernel admits
 * an unexecuted syscall normally and owns its restart/EINTR decision. Chained
 * real signal stops retain context without service instructions or registers. */
int md_signal_delivery_publish(struct md_signal_delivery *,pid_t tid,pid_t group);
/* 1 owns this delivery stop and supplies its resume signal, 0 leaves an
 * unrelated event unchanged, negative errno reports failure. Realtime siginfo
 * is normalized before any internal owner can retain that delivery again. */
int md_signal_delivery_event(struct md_signal_delivery *,pid_t tid,int signal,int *deliver);
void md_signal_delivery_clear(struct md_signal_delivery *);
#endif
