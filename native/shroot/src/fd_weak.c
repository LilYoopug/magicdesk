#define _GNU_SOURCE
#include "fd_weak.h"
#include "event_signal.h"
#include <pthread.h>
#include <stdlib.h>
#include <sys/eventfd.h>

struct md_fd_weak {
    atomic_uint references;
    pthread_mutex_t lock;
    struct md_fd_object *object;
    int wake;
};
void md_fd_weak_release(struct md_fd_weak *w) {
    if (!w || atomic_fetch_sub_explicit(&w->references,1,memory_order_acq_rel)!=1) return;
    close(w->wake); pthread_mutex_destroy(&w->lock); free(w);
}
struct md_fd_weak *md_fd_weak_observe(struct md_fd_object *object) {
    if (!object) { errno=EINVAL; return NULL; }
    struct md_fd_weak *w=atomic_load_explicit(&object->weak,memory_order_acquire);
    if (!w) {
        struct md_fd_weak *next=calloc(1,sizeof(*next));
        if (!next) return NULL;
        int error=pthread_mutex_init(&next->lock,NULL);
        if (error) { free(next); errno=error; return NULL; }
        next->wake=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
        if (next->wake<0) {
            int saved=errno; pthread_mutex_destroy(&next->lock); free(next); errno=saved; return NULL;
        }
        atomic_init(&next->references,1); next->object=object;
        if (atomic_compare_exchange_strong_explicit(&object->weak,&w,next,memory_order_acq_rel,memory_order_acquire))
            w=next;
        else md_fd_weak_release(next);
    }
    atomic_fetch_add_explicit(&w->references,1,memory_order_relaxed);
    return w;
}
struct md_fd_object *md_fd_weak_lock(struct md_fd_weak *w) {
    if (!w) return NULL;
    pthread_mutex_lock(&w->lock);
    struct md_fd_object *object=w->object;
    if (object) {
        unsigned count=atomic_load_explicit(&object->references,memory_order_relaxed);
        while (count && !atomic_compare_exchange_weak_explicit(&object->references,&count,count+1,
                memory_order_relaxed,memory_order_relaxed)) {}
        if (!count) object=NULL;
    }
    pthread_mutex_unlock(&w->lock);
    return object;
}
int md_fd_weak_expired(struct md_fd_weak *w) {
    if (!w) return 1;
    pthread_mutex_lock(&w->lock);
    int expired=!w->object || !atomic_load_explicit(&w->object->references,memory_order_relaxed);
    pthread_mutex_unlock(&w->lock);
    return expired;
}
int md_fd_weak_descriptor(const struct md_fd_weak *w) { return w ? w->wake : -1; }
void md_fd_weak_retire(struct md_fd_weak *w) {
    pthread_mutex_lock(&w->lock);
    w->object=NULL;
    /* This private eventfd remains owned by the object's weak reference until
     * after publication. Consumers duplicate but never close or drain it. */
    md_event_signal(w->wake);
    pthread_mutex_unlock(&w->lock);
    md_fd_weak_release(w);
}
