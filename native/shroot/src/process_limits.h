#ifndef MD_PROCESS_LIMITS_H
#define MD_PROCESS_LIMITS_H
#include "guest_identity.h"
#include <sys/resource.h>

/* Supervisor-owned task accounting. Registry references retain a zombie's
 * charge until reaping; private runtime helpers never acquire membership. */
struct md_process_member;
struct md_process_member *md_process_member_new(const struct md_identity *, const struct rlimit *);
struct md_process_member *md_process_member_retain(struct md_process_member *);
void md_process_member_release(struct md_process_member *);
int md_process_member_identity(struct md_process_member *, const struct md_identity *);
/* Reserve before native clone; transfer on birth, release on rejection/death. */
int md_process_member_fork(struct md_process_member *, const struct md_identity *,
    unsigned long flags, struct md_process_member **);
void md_process_member_forked(struct md_process_member *);
int md_process_member_exec(struct md_process_member *);
int md_process_nproc(struct md_process_member *, const struct md_identity *actor,
    const struct md_identity *target, int same_group, const struct rlimit *next, struct rlimit *old);
struct rlimit md_process_nproc_value(const struct md_process_member *);
#endif
