#ifndef MD_SYSFS_UEVENT_H
#define MD_SYSFS_UEVENT_H
#include "control_file.h"
struct md_device_events;
struct md_provider_tree;
/* Only immutable, launch-published upper nodes can supply event properties. */
int md_sysfs_uevent(struct md_provider_tree *,struct md_device_events *,int,struct md_control_file *);
#endif
