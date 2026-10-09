#ifndef MD_FILE_SNAPSHOT_H
#define MD_FILE_SNAPSHOT_H
#include <stddef.h>
struct md_inode_store;
struct md_file_snapshot { int fd; unsigned flags; };
int md_file_snapshot_flags(unsigned);
int md_file_snapshot_begin(struct md_file_snapshot *, struct md_inode_store *, unsigned);
int md_file_snapshot_append(struct md_file_snapshot *, const void *, size_t);
/* Returns a read-only/O_PATH result and releases the writable construction FD. */
int md_file_snapshot_finish(struct md_file_snapshot *);
void md_file_snapshot_close(struct md_file_snapshot *);
#endif
