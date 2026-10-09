#ifndef MD_IMAGE_IO_H
#define MD_IMAGE_IO_H
#include <stdint.h>
#include <stddef.h>
/* Streaming resource bounds shared by import, layer storage and backup. */
#define MD_IMAGE_MAX_BYTES (UINT64_C(64) * 1024 * 1024 * 1024)
#define MD_IMAGE_MAX_ENTRIES UINT64_C(2000000)
int md_image_read(int, size_t, char **);
int md_image_write(int, const void *, size_t);
int md_image_hash(int, uint64_t, char [65]);
int md_image_blob(int, int, const char *, uint64_t, int *);
int md_image_snapshot(int source, int scratch, uint64_t limit, int *);
int md_image_digest_valid(const char *);
#endif
