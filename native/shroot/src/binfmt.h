#ifndef MD_BINFMT_H
#define MD_BINFMT_H
#include "binfmt_rule.h"
#include "program_files.h"
struct md_binfmt_registry;
struct md_binfmt_entry;
struct md_provider_tree;
struct md_identity;
struct md_user_namespace;
struct md_binfmt_registry *md_binfmt_registry_new(void);
void md_binfmt_registry_destroy(struct md_binfmt_registry *);
/* Filesystem-worker owned registry; controls and admitted matches retain their
 * own immutable entries. A mount in a child user namespace shadows ancestors. */
int md_binfmt_mount(struct md_binfmt_registry *,int parent,const struct md_identity *,struct md_provider_tree **);
struct md_binfmt_entry *md_binfmt_match(struct md_binfmt_registry *,const struct md_user_namespace *,
    const char *,const void *,size_t);
const struct md_binfmt_rule *md_binfmt_entry_rule(const struct md_binfmt_entry *);
const struct md_program *md_binfmt_entry_program(const struct md_binfmt_entry *);
void md_binfmt_entry_release(struct md_binfmt_entry *);
#endif
