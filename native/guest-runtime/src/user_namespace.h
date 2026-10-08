#ifndef MD_USER_NAMESPACE_H
#define MD_USER_NAMESPACE_H
#include <stddef.h>
#include <stdint.h>

/* NULL is the launch's initial namespace. Stored identities stay canonical;
 * guest IDs are converted only at ABI boundaries. The supervisor serializes
 * mutations; immutable maps publish once to retained concurrent readers. */
struct md_user_namespace;
enum { MD_USER_OVERFLOW_ID=65534, MD_USER_MAP_EXTENTS=340, MD_USER_NAMESPACE_DEPTH=33 };
struct md_id_extent { uint32_t inside, outside, count; };
struct md_user_authority {
    const struct md_user_namespace *namespace;
    uint32_t uid, gid;
    uint64_t caps;
};
struct md_user_namespace *md_user_namespace_new(struct md_user_namespace *parent,
    uint32_t owner, uint32_t group, int creator_setfcap);
struct md_user_namespace *md_user_namespace_retain(struct md_user_namespace *);
void md_user_namespace_release(struct md_user_namespace *);
uint32_t md_user_namespace_into(const struct md_user_namespace *, int group, uint32_t);
uint32_t md_user_namespace_from(const struct md_user_namespace *, int group, uint32_t);
int md_user_namespace_contains(const struct md_user_namespace *ancestor, const struct md_user_namespace *);
int md_user_namespace_same(const struct md_user_namespace *, const struct md_user_namespace *);
int md_user_namespace_capable(const struct md_user_namespace *actor, uint32_t effective_uid,
    uint64_t effective_caps, const struct md_user_namespace *target, unsigned capability);
int md_user_namespace_map(struct md_user_namespace *, int group,
    const struct md_user_authority *opener, const struct md_user_authority *writer,
    const struct md_id_extent *, unsigned count);
int md_user_namespace_map_admit(const struct md_user_namespace *, int group,
    const struct md_user_authority *opener);
int md_user_namespace_setgroups(struct md_user_namespace *, int allowed);
int md_user_namespace_groups_allowed(const struct md_user_namespace *);
int md_user_namespace_may_setgroups(const struct md_user_namespace *);
const struct md_user_namespace *md_user_namespace_parent(const struct md_user_namespace *);
int md_user_namespace_extents(const struct md_user_namespace *, int group,
    struct md_id_extent *, unsigned capacity);
/* Cold custody transport: parent-first sealed policy pages. Imported owners
 * retain live read-only maps; only the creating supervisor can publish maps.
 * Export duplicates into an empty vector, import borrows its input rights. */
unsigned md_user_namespace_depth(const struct md_user_namespace *);
uint64_t md_user_namespace_inode(const struct md_user_namespace *);
uint32_t md_user_namespace_creator(const struct md_user_namespace *);
int md_user_namespace_export(const struct md_user_namespace *, int *, unsigned capacity);
int md_user_namespace_import(const int *, unsigned count, struct md_user_namespace **);
#endif
