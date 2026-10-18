#ifndef MD_TASK_MAPPING_H
#define MD_TASK_MAPPING_H
#include "task_call.h"
#include "task_helper.h"

/* Safe backing may be lent to the caller's table. The enclosing owner retains
 * its FD turn and loan through installation, mmap and verified retirement. */
int md_task_mapping_safe(int source);
struct md_task_mapping {
    struct md_task_call call;
    struct md_task_mapping_request request;
    enum { MD_TASK_MAPPING_IDLE, MD_TASK_MAPPING_INSTALL,
        MD_TASK_MAPPING_MAP, MD_TASK_MAPPING_DONE } stage;
    int descriptor;
    long result;
};
int md_task_mapping_begin(struct md_task_mapping *,long (*)(int,pid_t,void *,void *),
    pid_t,const struct user_pt_regs *,const struct md_interception_abi *,
    const struct md_task_mapping_request *);
int md_task_mapping_notification(const struct md_task_mapping *,const struct seccomp_notif *);
/* Same event ownership and return contract as task_call. */
int md_task_mapping_event(struct md_task_mapping *,int status);
#endif
