#define _GNU_SOURCE
#include "control_event.h"
#include "event_signal.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/eventfd.h>

struct md_control_event {
    atomic_uint references;
    pthread_mutex_t lock;
    uint64_t generation;
    struct md_control_cursor *first;
};
struct md_control_event *md_control_event_new(void) {
    struct md_control_event *s=calloc(1,sizeof(*s));
    if (!s) return NULL;
    int error=pthread_mutex_init(&s->lock,NULL);
    if (error) { free(s); errno=error; return NULL; }
    atomic_init(&s->references,1);
    return s;
}
struct md_control_event *md_control_event_retain(struct md_control_event *s) {
    if (s) atomic_fetch_add_explicit(&s->references,1,memory_order_relaxed);
    return s;
}
void md_control_event_release(struct md_control_event *s) {
    if (!s || atomic_fetch_sub_explicit(&s->references,1,memory_order_acq_rel)!=1) return;
    pthread_mutex_destroy(&s->lock);
    free(s);
}
int md_control_event_publish(struct md_control_event *s) {
    if (!s) return -EINVAL;
    pthread_mutex_lock(&s->lock);
    uint64_t previous=s->generation++;
    int error=0;
    for (struct md_control_cursor *c=s->first;c;c=c->next) {
        if (c->generation!=previous) continue;
        int r=md_event_signal(c->wake);
        if (r && !error) error=r;
    }
    pthread_mutex_unlock(&s->lock);
    return error;
}
void md_control_cursor_open(struct md_control_cursor *c,struct md_control_event *s) {
    *c=(struct md_control_cursor){.source=md_control_event_retain(s),.wake=-1};
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    c->generation=s->generation;
    pthread_mutex_unlock(&s->lock);
}
void md_control_cursor_close(struct md_control_cursor *c) {
    struct md_control_event *s=c->source;
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    int fd=c->wake;
    if (fd>=0) {
        if (c->previous) c->previous->next=c->next; else s->first=c->next;
        if (c->next) c->next->previous=c->previous;
    }
    *c=(struct md_control_cursor){.wake=-1};
    pthread_mutex_unlock(&s->lock);
    if (fd>=0) close(fd);
    md_control_event_release(s);
}
int md_control_cursor_watch(struct md_control_cursor *c) {
    struct md_control_event *s=c->source;
    if (!s) return -EINVAL;
    pthread_mutex_lock(&s->lock);
    int fd=c->wake;
    int error=0;
    if (fd<0) {
        fd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
        if (fd<0) error=-errno;
        else if (c->generation!=s->generation) error=md_event_signal(fd);
        if (error) { if (fd>=0) close(fd); }
        else {
            c->wake=fd; c->next=s->first;
            if (s->first) s->first->previous=c;
            s->first=c;
        }
    }
    pthread_mutex_unlock(&s->lock);
    return error ? error : fd;
}
int md_control_cursor_poll(struct md_control_cursor *c) {
    struct md_control_event *s=c->source;
    if (!s) return -EINVAL;
    pthread_mutex_lock(&s->lock);
    int changed=c->generation!=s->generation;
    int error=c->wake<0 || !changed ? 0 : md_event_acknowledge(c->wake);
    if (!error) c->generation=s->generation;
    pthread_mutex_unlock(&s->lock);
    return error ? error : changed;
}
