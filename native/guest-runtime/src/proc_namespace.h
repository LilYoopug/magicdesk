#ifndef MD_PROC_NAMESPACE_H
#define MD_PROC_NAMESPACE_H
#include "user_namespace.h"
#include <sys/stat.h>

enum md_namespace_kind { MD_NAMESPACE_USER, MD_NAMESPACE_MOUNT, MD_NAMESPACE_UTS, MD_NAMESPACE_IPC,
    MD_NAMESPACE_PID, MD_NAMESPACE_PID_CHILDREN, MD_NAMESPACE_NETWORK };
struct md_task_resources;
struct md_namespace_reference {
    enum md_namespace_kind kind;
    union {
        struct md_user_namespace *user;
        struct md_mount_namespace *mount;
        struct md_uts_namespace *uts;
        struct md_ipc_namespace *ipc;
        struct md_pid_namespace *pid;
        struct md_network_namespace *network;
    } value;
};
/* References own resources, not a pid or a proc-directory carrier. */
struct md_namespace_reference md_namespace_reference_capture(enum md_namespace_kind,
    const struct md_task_resources *, struct md_user_namespace *);
struct md_namespace_reference md_namespace_reference_copy(const struct md_namespace_reference *);
void md_namespace_reference_release(struct md_namespace_reference *);
void md_namespace_reference_stat(const struct md_namespace_reference *, struct stat *);
unsigned long md_namespace_reference_type(const struct md_namespace_reference *);
const struct md_user_namespace *md_namespace_reference_owner(const struct md_namespace_reference *);
/* Captures a related user namespace only when it is inside the caller's view.
 * The initial user namespace has no parent. Output owns its reference. */
int md_namespace_reference_related(const struct md_namespace_reference *,
    const struct md_user_namespace *caller, const struct md_pid_namespace *,
    int parent, struct md_namespace_reference *);
#endif
