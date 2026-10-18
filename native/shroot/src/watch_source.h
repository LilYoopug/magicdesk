#ifndef MD_WATCH_SOURCE_H
#define MD_WATCH_SOURCE_H
#include <stdint.h>

/* Typed provider events. Publishers may run on a different event loop;
 * subscriptions are drained only by the filesystem watch owner. */
struct md_watch_source;
struct md_watch_listener;
struct md_watch_interest;
struct md_watch_event {
    uint64_t sequence,object;
    unsigned mask,cookie;
    int unlinked;
    char name[256];
};
int md_watch_source_new(struct md_watch_source **);
struct md_watch_source *md_watch_source_retain(struct md_watch_source *);
void md_watch_source_release(struct md_watch_source *);
void md_watch_source_emit(struct md_watch_source *,uint64_t,unsigned,unsigned,const char *,int unlinked);
int md_watch_source_subscribe(struct md_watch_source *,struct md_watch_listener **);
void md_watch_source_unsubscribe(struct md_watch_listener *);
int md_watch_listener_descriptor(struct md_watch_listener *);
/* Registration linearizes here; an ended provider cannot admit a new watch.
 * Interests filter before queuing, not in the publisher's filesystem owner. */
int md_watch_listener_admit(struct md_watch_listener *,uint64_t object,unsigned mask,
    struct md_watch_interest **,uint64_t *sequence);
void md_watch_listener_update(struct md_watch_listener *,struct md_watch_interest *,unsigned mask);
void md_watch_listener_forget(struct md_watch_listener *,struct md_watch_interest *);
int md_watch_listener_next(struct md_watch_listener *,struct md_watch_event *);
#endif
