#ifndef MD_NOTIFICATION_RESULT_H
#define MD_NOTIFICATION_RESULT_H
#include "fd_install.h"
#include <linux/seccomp.h>

/* One serialized owner retains the completed operation independently of its
 * notification. Cancellation expires delivery, never the operation's result.
 * The provider keeps source alive through clear; table/origin pins live here. */
struct md_notification_result {
    struct md_fd_origins *files;
    struct md_fd_object *origin;
    struct md_fd_install install;
    struct seccomp_data call;
    int source, active, delivered, pending;
    int listener;
    uint64_t notification;
    long value;
    unsigned flags;
};
enum { MD_NOTIFICATION_WAIT=1, MD_NOTIFICATION_DELIVERED, MD_NOTIFICATION_CANCELLED,
    MD_NOTIFICATION_STATUS };
int md_notification_result_status(struct md_notification_result *,const struct seccomp_data *,long);
int md_notification_result_fd(struct md_notification_result *,const struct seccomp_data *,
    struct md_fd_origins *,int,struct md_fd_object *,unsigned);
int md_notification_result_matches(const struct md_notification_result *,const struct seccomp_data *);
int md_notification_result_offer(struct md_notification_result *,int,uint64_t,struct md_resource_wakeup *);
int md_notification_result_progress(struct md_notification_result *);
/* Scalar SEND acceptance does not prove consumption when a signal races it.
 * Only a shielded receiver or an owner observing syscall exit may use this. */
int md_notification_result_reply(struct md_notification_result *);
int md_notification_result_clear(struct md_notification_result *);
#endif
