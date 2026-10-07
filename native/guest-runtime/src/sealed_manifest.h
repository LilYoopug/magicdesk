#ifndef MD_SEALED_MANIFEST_H
#define MD_SEALED_MANIFEST_H
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

struct md_fd_identity { uint64_t device, inode; };
static inline struct md_fd_identity md_fd_identity(const struct stat *st) {
    return (struct md_fd_identity){st->st_dev,st->st_ino};
}
static inline int md_fd_identity_same(struct md_fd_identity a, struct md_fd_identity b) {
    return a.device==b.device && a.inode==b.inode;
}
/* Immutable, bounded metadata on an authenticated private transport. Seals
 * preserve bytes/identity, not their meaning or the sender's authority. */
int md_sealed_manifest_create(const char *name, const void *, size_t, struct md_fd_identity *);
int md_sealed_manifest_read(int fd, void *, size_t capacity, size_t *size, struct md_fd_identity *);
#endif
