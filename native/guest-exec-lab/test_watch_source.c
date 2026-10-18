#include "watch_source.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/inotify.h>

void md_test_watch_source(void) {
    struct md_watch_source *source=NULL;
    assert(!md_watch_source_new(&source));
    md_watch_source_emit(source,1,IN_MODIFY,0,NULL,0);
    uint64_t sequence=UINT64_MAX;
    struct md_watch_listener *first=NULL,*second=NULL;
    assert(!md_watch_source_subscribe(source,&first));
    assert(!md_watch_source_subscribe(source,&second));
    struct md_watch_interest *first_interest=NULL,*second_interest=NULL;
    assert(!md_watch_listener_admit(first,7,IN_ALL_EVENTS,&first_interest,&sequence) && !sequence);
    assert(!md_watch_listener_admit(second,7,IN_ALL_EVENTS,&second_interest,&sequence) && !sequence);
    struct pollfd poller={.fd=md_watch_listener_descriptor(first),.events=POLLIN};
    assert(!poll(&poller,1,0));
    md_watch_source_emit(source,7,IN_MOVED_FROM,123,"name",0);
    assert(poll(&poller,1,0)==1 && (poller.revents&POLLIN));
    struct md_watch_event event;
    assert(md_watch_listener_next(first,&event) && event.object==7 && event.cookie==123);
    assert(!md_watch_listener_next(first,&event) && !poll(&poller,1,0));
    assert(md_watch_listener_next(second,&event) && event.object==7 && event.cookie==123);
    md_watch_source_unsubscribe(second);
    for (unsigned i=0;i<20000;++i) md_watch_source_emit(source,8,IN_MODIFY,0,NULL,0);
    assert(!md_watch_listener_next(first,&event) && !poll(&poller,1,0));
    md_watch_listener_update(first,first_interest,IN_OPEN|IN_EXCL_UNLINK);
    for (unsigned i=0;i<20000;++i) md_watch_source_emit(source,7,IN_MODIFY,0,NULL,0);
    md_watch_source_emit(source,7,IN_OPEN,0,"detached",1);
    assert(!md_watch_listener_next(first,&event) && !poll(&poller,1,0));
    /* A second watch can still request the same object's excluded event. */
    assert(!md_watch_listener_admit(first,7,IN_OPEN,&second_interest,&sequence));
    md_watch_source_emit(source,7,IN_OPEN,0,"detached",1);
    assert(md_watch_listener_next(first,&event) && event.mask==IN_OPEN && event.unlinked);
    md_watch_listener_forget(first,second_interest);
    md_watch_source_emit(source,7,IN_OPEN,0,"detached",1);
    assert(!md_watch_listener_next(first,&event));
    md_watch_source_emit(source,7,IN_DELETE_SELF,0,NULL,0);
    assert(md_watch_listener_next(first,&event) && event.mask==IN_DELETE_SELF);
    md_watch_listener_update(first,first_interest,IN_ALL_EVENTS);
    for (unsigned i=0;i<20000;++i) md_watch_source_emit(source,7,IN_MODIFY,0,NULL,0);
    md_watch_source_emit(source,0,IN_UNMOUNT,0,NULL,0);
    assert(md_watch_listener_admit(first,7,IN_OPEN,&second_interest,&sequence)==-ENODEV && !second_interest);
    assert(md_watch_source_subscribe(source,&second)==-ENODEV && !second);
    md_watch_source_release(source);
    unsigned changes=0,overflow=0,unmount=0;
    while (md_watch_listener_next(first,&event)) {
        if (event.mask==IN_MODIFY) { assert(!overflow && !unmount); ++changes; }
        else if (event.mask==IN_Q_OVERFLOW) { assert(!unmount); ++overflow; }
        else { assert(event.mask==IN_UNMOUNT); ++unmount; }
    }
    assert(changes==16384 && overflow==1 && unmount==1 && !poll(&poller,1,0));
    md_watch_source_unsubscribe(first);
    puts("PASS provider watch source: readiness, interest filtering, bounded overflow and retained teardown");
}
