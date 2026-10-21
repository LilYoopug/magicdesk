#ifndef MD_MAPPING_READER_H
#define MD_MAPPING_READER_H
#include <stddef.h>
#include <stdint.h>

/* Borrowed exact-mm maps/smaps description. No reopening, caching, ownership
 * transfer or access policy: each consumer decides what a mapping authorizes. */
struct md_mapping_reader { int fd; size_t cursor, size; char bytes[16384]; };
struct md_mapping_record {
    uintptr_t first, end;
    uint64_t offset, inode;
    unsigned major, minor;
    int protection, shared;
};
/* 0: EOF, 1: line, 2: truncated line, negative errno: failure. The complete
 * source line is consumed even when a pathname does not fit the output. */
int md_mapping_line(struct md_mapping_reader *, char *, size_t);
int md_mapping_parse(const char *, int truncated, struct md_mapping_record *);
/* maps only: unlike smaps, every line must be a complete mapping header. */
int md_mapping_next(struct md_mapping_reader *, struct md_mapping_record *);
#endif
