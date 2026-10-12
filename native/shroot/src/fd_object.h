#ifndef MD_FD_OBJECT_H
#define MD_FD_OBJECT_H
#include <stdatomic.h>

/* Embedded in the descriptor's typed authority, never a second allocation.
 * It owns provenance/lifetime, not a duplicate of the application's data OFD. */
struct md_fd_object;
struct md_fd_weak;
/* Last-reference notification; ordinary authorities have no weak state. */
void md_fd_weak_retire(struct md_fd_weak *);
struct md_fd_object_type {
    void (*destroy)(struct md_fd_object *);
    unsigned selectors;
};
struct md_fd_object {
    atomic_uint references;
    const struct md_fd_object_type *type;
    _Atomic(struct md_fd_weak *) weak;
};
static inline void md_fd_object_init(struct md_fd_object *o, const struct md_fd_object_type *type) {
    atomic_init(&o->references,1); o->type=type; atomic_init(&o->weak,0);
}
static inline struct md_fd_object *md_fd_object_retain(struct md_fd_object *o) {
    if (o) atomic_fetch_add_explicit(&o->references,1,memory_order_relaxed);
    return o;
}
static inline void md_fd_object_release(struct md_fd_object *o) {
    if (o && atomic_fetch_sub_explicit(&o->references,1,memory_order_acq_rel)==1) {
        struct md_fd_weak *weak=atomic_load_explicit(&o->weak,memory_order_acquire);
        if (weak) md_fd_weak_retire(weak);
        o->type->destroy(o);
    }
}
#endif
