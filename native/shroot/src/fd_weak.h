#ifndef MD_FD_WEAK_H
#define MD_FD_WEAK_H
#include "fd_object.h"

/* Caller holds a strong reference while obtaining a weak reference. Allocates
 * only on first observation; neither the token nor its readiness FD retains
 * the authority or the application's native open description. */
struct md_fd_weak *md_fd_weak_observe(struct md_fd_object *);
void md_fd_weak_release(struct md_fd_weak *);
/* A strong reference, or NULL after final release. Cannot resurrect an object
 * whose destructor is in progress. Independent of descriptor-number reuse. */
struct md_fd_object *md_fd_weak_lock(struct md_fd_weak *);
int md_fd_weak_expired(struct md_fd_weak *);
/* Borrowed nonblocking CLOEXEC eventfd, readable after final strong release.
 * Consumers must not read it: expiration remains level-ready for all observers. */
int md_fd_weak_descriptor(const struct md_fd_weak *);
#endif
