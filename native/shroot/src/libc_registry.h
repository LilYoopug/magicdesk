#ifndef MD_LIBC_REGISTRY_H
#define MD_LIBC_REGISTRY_H
#include <stddef.h>
#include <sys/stat.h>

#define MD_LIBC_REGISTRY_LIMIT 128
#define MD_LIBC_FILE_LIMIT (32 * 1024 * 1024)
#define MD_LIBC_PREFIX "/opt/shroot/libc"
struct md_libc_manifest {
    unsigned abi;
    char family[16], version[64], recipe[65];
    char interpreter[256], libc[256], loader[256];
    char interpreter_hash[65], libc_hash[65], key[65];
};
struct md_libc_registry;
/* Native, executor-scoped immutable artifacts. NULL/absent roots select Base.
 * Successful selections retain a kernel lease until registry_close. */
int md_libc_registry_open(const char *, struct md_libc_registry **);
void md_libc_registry_close(struct md_libc_registry *);
int md_libc_registry_refresh(struct md_libc_registry *);
unsigned md_libc_registry_count(const struct md_libc_registry *);
const struct md_libc_manifest *md_libc_registry_entry(const struct md_libc_registry *, unsigned);
int md_libc_registry_claim(struct md_libc_registry *, unsigned);
int md_libc_registry_hash(struct md_libc_registry *, int, char [65]);
int md_libc_manifest_read(int directory, struct md_libc_manifest *);
int md_libc_registry_publish(const char *root, const char *candidate);
int md_libc_registry_list(const char *root);
int md_libc_registry_prune(const char *root);
#endif
