#ifndef MD_SVC_LIVE_BODY_H
#define MD_SVC_LIVE_BODY_H
#include <stdint.h>

/* One serialized publisher; concurrent callers acquire before reading either
 * pointer. The resident caller releases only after returning from body code. */
struct md_svc_live_body {
    uint64_t admission;
    uintptr_t entry;
    void *context;
};
void md_svc_live_body_init(struct md_svc_live_body *);
int md_svc_live_body_publish(struct md_svc_live_body *,uintptr_t,void *);
int md_svc_live_body_acquire(struct md_svc_live_body *,uintptr_t *,void **);
void md_svc_live_body_release(struct md_svc_live_body *);
/* Closes admission immediately; EAGAIN means existing calls still own code.
 * No thread is interrupted, parked, or required to acknowledge an epoch. */
int md_svc_live_body_close(struct md_svc_live_body *);
int md_svc_live_body_drained(const struct md_svc_live_body *);
#endif
