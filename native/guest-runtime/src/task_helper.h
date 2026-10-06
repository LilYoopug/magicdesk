#ifndef MD_TASK_HELPER_H
#define MD_TASK_HELPER_H
#include "interception.h"
#include "interception_memory.h"
#include "task_send.h"
#include "task_receive.h"
#include <sys/user.h>
#include <sys/types.h>
#include <asm/ptrace.h>
#include <linux/seccomp.h>
#include <signal.h>

struct md_task_helpers;
struct md_task_mapping_request {
    int source, protection, flags;
    uintptr_t address;
    size_t size;
    uint64_t offset;
};
enum md_task_helper_kind { MD_TASK_HELPER_MAP, MD_TASK_HELPER_CAPTURE, MD_TASK_HELPER_SEND, MD_TASK_HELPER_RECEIVE };
struct md_task_helper_request {
    enum md_task_helper_kind kind;
    struct md_task_mapping_request mapping;
    /* Copied before acceptance. Resolved in the caller's captured FS context. */
    const char *path;
    int flags;
    struct md_task_send send;
    struct md_task_receive receive;
    int source;
    /* Exact CLONE_FILES separation, before any potentially blocking IO. */
    void (*captured)(void *);
};
struct md_task_helper_result { long value; int descriptor; siginfo_t signal; struct md_received_fds received; };
/* Completion transfers descriptor ownership, including cancellation. */
typedef void (*md_task_helper_complete)(void *, struct md_task_helper_result);
struct md_task_helper_callbacks {
    long (*trace)(int, pid_t, void *, void *);
    /* Claim an early newborn stop, if already recorded by the outer loop. */
    int (*newborn)(pid_t);
};
struct md_task_helpers *md_task_helpers_new(const struct md_task_helper_callbacks *);
/* Every helper must be reaped before destruction. */
void md_task_helpers_destroy(struct md_task_helpers *);
unsigned md_task_helpers_count(const struct md_task_helpers *);
/* Borrows source on entry; accepted operations retain their own description,
 * memory owner, scratch stack and buffer lease. No caller FD is installed.
 * Completion occurs once after helper reaping or a confirmed pre-birth error.
 * The caller orders any FS/table inputs through context capture and retains
 * its continuation until completion; detach cannot resume a dead task. */
int md_task_helper_begin(struct md_task_helpers *, pid_t owner, pid_t group,
        const struct user_pt_regs *, const struct md_interception_abi *,
        struct md_interception_memory *, const struct md_interception_buffer *,
        const struct md_task_helper_request *, md_task_helper_complete, void *completion);
/* Owner terminal/exec notification must precede record reuse. */
int md_task_helper_detach(struct md_task_helpers *, pid_t owner);
/* 1 consumed, 0 belongs to the ordinary guest path, negative errno fatal. */
int md_task_helper_event(struct md_task_helpers *, pid_t, int status);
int md_task_helper_notification(struct md_task_helpers *, int listener, const struct seccomp_notif *);
#endif
