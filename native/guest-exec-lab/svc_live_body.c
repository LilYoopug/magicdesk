#include "svc_live_body.h"
#include <assert.h>
#include <errno.h>

#define CLOSED (UINT64_C(1)<<63)
void md_svc_live_body_init(struct md_svc_live_body *body) {
    *body=(struct md_svc_live_body){.admission=CLOSED};
}
int md_svc_live_body_publish(struct md_svc_live_body *body,uintptr_t entry,void *context) {
    if (!entry) return -EINVAL;
    if (__atomic_load_n(&body->admission,__ATOMIC_ACQUIRE)!=CLOSED) return -EBUSY;
    body->entry=entry; body->context=context;
    __atomic_store_n(&body->admission,0,__ATOMIC_RELEASE);
    return 0;
}
int md_svc_live_body_acquire(struct md_svc_live_body *body,uintptr_t *entry,void **context) {
    uint64_t value=__atomic_load_n(&body->admission,__ATOMIC_RELAXED);
    for (;;) {
        if ((value&CLOSED) || value==CLOSED-1) return 0;
        if (__atomic_compare_exchange_n(&body->admission,&value,value+1,1,
                __ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) break;
    }
    *entry=body->entry; *context=body->context;
    return 1;
}
void md_svc_live_body_release(struct md_svc_live_body *body) {
    uint64_t value=__atomic_fetch_sub(&body->admission,1,__ATOMIC_RELEASE);
    assert(value&~CLOSED);
}
int md_svc_live_body_close(struct md_svc_live_body *body) {
    uint64_t value=__atomic_fetch_or(&body->admission,CLOSED,__ATOMIC_ACQ_REL);
    return (value&~CLOSED) ? -EAGAIN : 0;
}
int md_svc_live_body_drained(const struct md_svc_live_body *body) {
    return __atomic_load_n(&body->admission,__ATOMIC_ACQUIRE)==CLOSED;
}
