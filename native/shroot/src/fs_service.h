#ifndef MD_FS_SERVICE_H
#define MD_FS_SERVICE_H
#include "inode_store.h"
#include "fs_engine.h"
#include "fs_wire.h"
#include <poll.h>
#include <time.h>
struct md_image_catalogue;
struct md_fs_service;
int md_fs_listen(const char *abstract_name);
struct md_fs_work_source {
    int fd;
    struct md_resource_wakeup *wakeup;
    void *context;
    void (*ready)(void *, struct md_filesystem *);
    int (*notification_fd)(void *);
    int (*notification)(void *, struct md_filesystem *, short);
    /* Revoke shared-memory awake publication and recheck pending work. A true
     * result uses a zero-time FD poll, preserving fairness before dispatch. */
    int (*prepare_wait)(void *);
    /* A confirmed pause admits only work-control and stop readiness. No peer,
     * watch, notification or filesystem callback runs until it is released. */
    int (*paused)(void *);
};
/* One owner serializes preparation, readiness dispatch and close. Filesystem,
 * work source and listener/stop FDs remain borrowed until close. Preparation
 * advances deferred operations before publishing the next readiness snapshot;
 * it does not promise nonblocking filesystem IO. */
struct md_fs_service_poll {
    struct pollfd *fds;
    unsigned count;
    const struct timespec *timeout;
};
int md_fs_service_open(struct md_filesystem *, int listener, int stop_fd,
        unsigned timeout_ms, struct md_fs_statistics *, const struct md_fs_work_source *, struct md_fs_service **);
/* Borrowed snapshot until the next prepare/dispatch/close. A wait writes only
 * revents; interrupted waits may prepare again without replaying a request. */
int md_fs_service_prepare(struct md_fs_service *, struct md_fs_service_poll *);
/* Zero continues, one acknowledges stop readiness, negative is a failure. */
int md_fs_service_dispatch(struct md_fs_service *);
void md_fs_service_close(struct md_fs_service *);
/* Standalone loop over the same lifecycle. Calling thread exclusively owns
 * store. Peer requests never own the service lifetime. */
int md_fs_serve(struct md_filesystem *, int listener, int stop_fd,
        unsigned timeout_ms, struct md_fs_statistics *, const struct md_fs_work_source *);
#ifdef MD_FS_TESTING
enum md_fs_checkpoint { MD_FS_BEFORE_DISPATCH, MD_FS_AFTER_DISPATCH, MD_FS_REPLY_SENT, MD_FS_CONNECTION_CLOSED };
void md_fs_observe(void (*)(enum md_fs_checkpoint, const struct md_fs_packet *, void *), void *);
#endif
#endif
