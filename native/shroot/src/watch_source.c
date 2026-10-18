#define _GNU_SOURCE
#include "watch_source.h"
#include "event_signal.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

enum { EVENT_LIMIT=16384, INTEREST_BUCKETS=64 };
struct record { struct record *next; struct md_watch_event event; };
struct md_watch_interest {
    struct md_watch_interest *next;
    uint64_t object;
    unsigned mask;
};
struct md_watch_listener {
    struct md_watch_listener *next;
    struct md_watch_source *source;
    struct record *first,*last;
    unsigned count;
    int event,overflow;
    uint64_t unmount;
    struct md_watch_interest *interests[INTEREST_BUCKETS];
};
static unsigned interest_bucket(uint64_t object) {
    return (object^(object>>32))%INTEREST_BUCKETS;
}
struct md_watch_source {
    atomic_uint references,listeners;
    pthread_mutex_t lock;
    uint64_t sequence;
    int ended;
    struct md_watch_listener *first;
};
int md_watch_source_new(struct md_watch_source **out) {
    *out=NULL;
    struct md_watch_source *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    int error=pthread_mutex_init(&s->lock,NULL);
    if (error) { free(s); return -error; }
    atomic_init(&s->references,1); atomic_init(&s->listeners,0); *out=s; return 0;
}
struct md_watch_source *md_watch_source_retain(struct md_watch_source *s) {
    if (s) atomic_fetch_add_explicit(&s->references,1,memory_order_relaxed);
    return s;
}
void md_watch_source_release(struct md_watch_source *s) {
    if (!s || atomic_fetch_sub_explicit(&s->references,1,memory_order_acq_rel)!=1) return;
    pthread_mutex_destroy(&s->lock); free(s);
}
int md_watch_source_subscribe(struct md_watch_source *s,struct md_watch_listener **out) {
    *out=NULL;
    struct md_watch_listener *p=calloc(1,sizeof(*p));
    if (!p) return -ENOMEM;
    p->event=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    if (p->event<0) { int error=-errno; free(p); return error; }
    p->source=md_watch_source_retain(s);
    pthread_mutex_lock(&s->lock);
    if (s->ended) {
        pthread_mutex_unlock(&s->lock);
        close(p->event); free(p); md_watch_source_release(s); return -ENODEV;
    }
    p->next=s->first; s->first=p;
    atomic_fetch_add_explicit(&s->listeners,1,memory_order_release);
    pthread_mutex_unlock(&s->lock); *out=p; return 0;
}
void md_watch_source_unsubscribe(struct md_watch_listener *p) {
    if (!p) return;
    struct md_watch_source *s=p->source;
    pthread_mutex_lock(&s->lock);
    struct md_watch_listener **link=&s->first;
    while (*link!=p) link=&(*link)->next;
    *link=p->next;
    atomic_fetch_sub_explicit(&s->listeners,1,memory_order_release);
    pthread_mutex_unlock(&s->lock);
    while (p->first) { struct record *r=p->first; p->first=r->next; free(r); }
    for (unsigned b=0;b<INTEREST_BUCKETS;++b) while (p->interests[b]) {
        struct md_watch_interest *i=p->interests[b]; p->interests[b]=i->next; free(i);
    }
    close(p->event); free(p); md_watch_source_release(s);
}
int md_watch_listener_descriptor(struct md_watch_listener *p) { return p->event; }
int md_watch_listener_admit(struct md_watch_listener *p,uint64_t object,unsigned mask,
        struct md_watch_interest **out,uint64_t *sequence) {
    *out=NULL;
    struct md_watch_interest *i=malloc(sizeof(*i));
    if (!i) return -ENOMEM;
    struct md_watch_source *s=p->source;
    pthread_mutex_lock(&s->lock);
    int error=s->ended ? -ENODEV : 0;
    if (!error) {
        unsigned b=interest_bucket(object);
        *i=(struct md_watch_interest){.object=object,.mask=mask,.next=p->interests[b]};
        p->interests[b]=i; *sequence=s->sequence; *out=i;
    }
    pthread_mutex_unlock(&s->lock);
    if (error) free(i);
    return error;
}
void md_watch_listener_update(struct md_watch_listener *p,struct md_watch_interest *i,unsigned mask) {
    pthread_mutex_lock(&p->source->lock); i->mask=mask; pthread_mutex_unlock(&p->source->lock);
}
void md_watch_listener_forget(struct md_watch_listener *p,struct md_watch_interest *i) {
    pthread_mutex_lock(&p->source->lock);
    struct md_watch_interest **link=&p->interests[interest_bucket(i->object)];
    while (*link!=i) link=&(*link)->next;
    *link=i->next;
    pthread_mutex_unlock(&p->source->lock); free(i);
}
static int interested(struct md_watch_listener *p,uint64_t object,unsigned mask,int unlinked) {
    for (struct md_watch_interest *i=p->interests[interest_bucket(object)];i;i=i->next)
        if (i->object==object && !(unlinked && (i->mask&IN_EXCL_UNLINK))
                && ((mask&i->mask&IN_ALL_EVENTS) || (mask&(IN_DELETE_SELF|IN_IGNORED)))) return 1;
    return 0;
}
void md_watch_source_emit(struct md_watch_source *s,uint64_t object,unsigned mask,unsigned cookie,
        const char *name,int unlinked) {
    if (!s || (!(mask&IN_UNMOUNT) && !atomic_load_explicit(&s->listeners,memory_order_acquire))) return;
    pthread_mutex_lock(&s->lock);
    if (s->ended) { pthread_mutex_unlock(&s->lock); return; }
    uint64_t sequence=++s->sequence;
    if (mask&IN_UNMOUNT) s->ended=1;
    for (struct md_watch_listener *p=s->first;p;p=p->next) {
        if (mask&IN_UNMOUNT) { p->unmount=sequence; md_event_signal(p->event); continue; }
        if (!interested(p,object,mask,unlinked)) continue;
        if (p->overflow) continue;
        struct record *r=p->count<EVENT_LIMIT ? malloc(sizeof(*r)) : NULL;
        if (!r) p->overflow=1;
        else {
            *r=(struct record){.event={.sequence=sequence,.object=object,.mask=mask,.cookie=cookie,.unlinked=unlinked}};
            if (name) { size_t length=strnlen(name,sizeof(r->event.name)-1); memcpy(r->event.name,name,length); }
            if (p->last) p->last->next=r; else p->first=r;
            p->last=r; ++p->count;
        }
        md_event_signal(p->event);
    }
    pthread_mutex_unlock(&s->lock);
}
int md_watch_listener_next(struct md_watch_listener *p,struct md_watch_event *out) {
    pthread_mutex_lock(&p->source->lock);
    int found=0;
    if (p->first) {
        struct record *r=p->first; p->first=r->next; --p->count;
        if (!p->first) p->last=NULL;
        *out=r->event; free(r); found=1;
    } else if (p->overflow) {
        *out=(struct md_watch_event){.mask=IN_Q_OVERFLOW,.sequence=p->source->sequence};
        p->overflow=0; found=1;
    } else if (p->unmount) {
        *out=(struct md_watch_event){.mask=IN_UNMOUNT,.sequence=p->unmount};
        p->unmount=0; found=1;
    }
    if (!p->first && !p->overflow && !p->unmount) md_event_acknowledge(p->event);
    pthread_mutex_unlock(&p->source->lock); return found;
}
