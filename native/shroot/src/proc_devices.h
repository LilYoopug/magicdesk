#ifndef MD_PROC_DEVICES_H
#define MD_PROC_DEVICES_H
#include "control_file.h"
struct md_user_namespace;
struct md_control_file md_proc_devices_new(struct md_user_namespace *,struct md_fs_anchor *);
#endif
