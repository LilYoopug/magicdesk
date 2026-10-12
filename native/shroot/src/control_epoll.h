#ifndef MD_CONTROL_EPOLL_H
#define MD_CONTROL_EPOLL_H
#include "control_file.h"
#include "fd_object.h"
#include <sys/epoll.h>

/* Supervisor-owned virtual interests. Native registrations remain in their
 * original kernel epoll; neither their data nor their identity is rewritten.
 * The caller serializes operations and retains the enclosing epoll OFD.
 * File-table capture/admission and guest result copying belong to that caller. */
struct md_control_epoll;
struct md_control_epoll *md_control_epoll_new(void);
void md_control_epoll_free(struct md_control_epoll *);
/* Readiness hint, not an application epoll: collect revalidates providers.
 * A wake can be stale, and need not yield an application event. */
int md_control_epoll_descriptor(const struct md_control_epoll *);
/* Linux interest identity is (open description, registering FD), not data.u64.
 * ADD retains both the identity and provider; MOD/DEL use the exact identity.
 * Unsupported exclusive/wakeup policies fail before changing an interest. */
int md_control_epoll_ctl(struct md_control_epoll *,int operation,int fd,
    struct md_fd_object *,struct md_control_file,const struct epoll_event *);
/* Nonblocking, allocation-free. At most one bounded ready-list turn per call.
 * Caller provides a separate result slice from native epoll_wait output. */
int md_control_epoll_collect(struct md_control_epoll *,struct epoll_event *,int capacity);
/* Confirmed monitored OFD retirement, not close of an arbitrary dup or a
 * provider reference-count transition. The descriptor custodian owns that
 * decision, including queued transfers and kernel aliases. */
void md_control_epoll_retire(struct md_control_epoll *,const struct md_fd_object *);
#endif
