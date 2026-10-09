#ifndef MD_LAUNCH_REGISTRY_H
#define MD_LAUNCH_REGISTRY_H
#include <stdint.h>
#include <sys/types.h>

struct md_launch_info {
    uint32_t version, executor_uid, guest_uid;
    int32_t pid, descriptor;
    char program[4096], cwd[4096], label[1024];
};
struct md_launch_registration { int directory, record; char id[33]; };
int md_launch_register(struct md_launch_registration *, const char *store,
    const char *program, const char *cwd, uint32_t guest_uid);
void md_launch_unregister(struct md_launch_registration *);
/* Worker-side lookup relative to the retained launch directory, not a store
 * pathname. Returns an owned pidfd after validating the live record and owner.
 * Discovery alone does not establish ownership of an application connection. */
int md_launch_acquire(const struct md_launch_registration *, const char *id, struct md_launch_info *);
typedef int (*md_launch_visitor)(const char *, const struct md_launch_info *, void *);
int md_launch_list(const char *store, md_launch_visitor, void *);
int md_launch_stop(const char *store, const char *id);
#endif
