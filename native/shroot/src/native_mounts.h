#ifndef MD_NATIVE_MOUNTS_H
#define MD_NATIVE_MOUNTS_H
#include <stddef.h>

struct md_native_mounts;
/* Worker-owned snapshot of the native /proc and /dev mounts, not guest policy.
 * Returned bytes are borrowed until the next read or release. */
int md_native_mounts_read(struct md_native_mounts **, const char **, size_t *);
void md_native_mounts_release(struct md_native_mounts *);
#endif
