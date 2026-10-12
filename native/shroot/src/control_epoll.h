#ifndef MD_CONTROL_EPOLL_H
#define MD_CONTROL_EPOLL_H
#include "control_file.h"
#include "fd_object.h"
#include <sys/epoll.h>

/* Typed epoll OFD authority. Native registrations remain in their
 * original kernel epoll; neither their data nor their identity is rewritten.
 * This object owns no duplicate of that kernel epoll. Tables and queued
 * transfers retain the same authority across dup/fork/receive. The supervisor
 * serializes subscription operations; refcounts alone are thread-safe.
 * File-table capture/admission and guest result copying belong to that caller. */
struct md_control_epoll;
/* Metadata only. Wake descriptors are allocated on the first virtual ADD. */
struct md_control_epoll *md_control_epoll_new(void);
void md_control_epoll_release(struct md_control_epoll *);
struct md_fd_object *md_control_epoll_object(struct md_control_epoll *);
struct md_control_epoll *md_control_epoll_from_object(struct md_fd_object *);
/* Readiness hint, not an application epoll: collect revalidates providers.
 * -1 before successful virtual admission. Once published, this borrowed FD
 * stays valid until owner release, including after the last interest's DEL.
 * A wake can be stale, and need not yield an application event. */
int md_control_epoll_descriptor(const struct md_control_epoll *);
/* Linux interest identity is (open description, registering FD), not data.u64.
 * The caller retains identity during ctl; provider is owned by that identity.
 * ADD weakly observes identity, so the subscription cannot keep its target
 * alive. Collector calls borrow a strong reference before touching provider.
 * MOD/DEL use the exact identity.
 * Unsupported exclusive/wakeup policies fail before changing an interest. */
int md_control_epoll_ctl(struct md_control_epoll *,int operation,int fd,
    struct md_fd_object *,struct md_control_file,const struct epoll_event *);
/* Nonblocking, allocation-free. At most one bounded ready-list turn per call.
 * Caller provides a separate result slice from native epoll_wait output. */
int md_control_epoll_collect(struct md_control_epoll *,struct epoll_event *,int capacity);
#endif
