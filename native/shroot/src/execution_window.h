#ifndef MD_EXECUTION_WINDOW_H
#define MD_EXECUTION_WINDOW_H
#include <errno.h>
#include <stdint.h>

/* Executor-owned bounded reuse, independent of transport and subsystem. The
 * provider retains authority; this window caches neither results nor policy.
 * End before parking, changing provider, or delegating. The provider's contract
 * decides whether independent mutations can complete inside the window. */
struct md_execution_window {
    void *owner;
    int (*release)(void *);
    uint64_t deadline;
    unsigned count;
};
static inline int md_execution_window_end(struct md_execution_window *w) {
    void *owner=w->owner;
    int (*release)(void *)=w->release;
    *w=(struct md_execution_window){0};
    return owner ? release(owner) : 0;
}
static inline int md_execution_window_admit(struct md_execution_window *w,void *owner,
        int (*acquire)(void *),int (*release)(void *),uint64_t now,
        unsigned count_limit,uint64_t duration) {
    if (owner && (!acquire || !release || !count_limit || !duration || duration>UINT64_MAX-now)) {
        int error=md_execution_window_end(w);
        return error ? error : -EINVAL;
    }
    if (w->owner && (w->owner!=owner || w->release!=release
            || w->count>=count_limit || now>=w->deadline)) {
        int error=md_execution_window_end(w); if (error) return error;
    }
    if (!owner) return 0;
    if (!w->owner) {
        int error=acquire(owner); if (error) return error;
        *w=(struct md_execution_window){owner,release,now+duration,0};
    }
    ++w->count; return 0;
}
#endif
