#ifndef MD_SPIN_POLICY_H
#define MD_SPIN_POLICY_H
#include <stdint.h>
/* Endpoint-local feedback. Four unsuccessful bounded spins park immediately
 * for the next 128 waits, then sample again. No affinity or scheduler changes. */
struct md_spin_policy { unsigned misses, cooldown; };
static inline unsigned md_spin_budget(struct md_spin_policy *p,unsigned maximum) {
    if (p->cooldown) { --p->cooldown; return 0; }
    return maximum;
}
static inline void md_spin_result(struct md_spin_policy *p,int hit) {
    if (hit) p->misses=0;
    else if (++p->misses==4) { p->misses=0; p->cooldown=128; }
}
static inline void md_spin_observed(struct md_spin_policy *p,int ready,uint64_t now,uint64_t deadline) {
    md_spin_result(p,ready && now && now<deadline);
}
#endif
