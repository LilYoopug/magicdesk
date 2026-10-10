#ifndef MD_DEVICE_EVENTS_H
#define MD_DEVICE_EVENTS_H
#include "fd_object.h"
struct md_device_events;
/* Launch-owned, read-only device notifications. Never subscribes to Android's
 * global uevents and never permits a guest to impersonate the publisher. */
struct md_device_events *md_device_events_new(void);
struct md_device_events *md_device_events_retain(struct md_device_events *);
void md_device_events_release(struct md_device_events *);
void md_device_events_stop(struct md_device_events *);
int md_device_events_publish(struct md_device_events *,const char *action,const char *path,
    const char *subsystem,const char *properties,size_t size);
int md_device_events_socket(struct md_device_events *,int type,struct md_fd_object **,int *fd);
int md_device_events_is(const struct md_fd_object *);
long md_device_events_call(struct md_fd_object *,long nr,const unsigned long *,void *,size_t,size_t,pid_t);
#endif
