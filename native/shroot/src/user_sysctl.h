#ifndef MD_USER_SYSCTL_H
#define MD_USER_SYSCTL_H
#include "control_file.h"
struct md_user_namespace;
struct md_fs_anchor;
struct md_control_file md_user_sysctl_new(struct md_user_namespace *,struct md_fs_anchor *);
#endif
