#ifndef MD_FS_NATIVE_H
#define MD_FS_NATIVE_H
#include "fs_engine.h"
struct md_inode_boundary;
/* Only after logical resolution and access checks. Task-relative or virtual
 * objects keep EREMOTE/EXDEV for their existing owner. */
void md_fs_native_boundary(struct md_filesystem *, const struct md_inode_boundary *,
        const struct md_fs_request *, struct md_fs_result *, const struct md_fs_output *);
void md_fs_native_descriptor(const struct md_fs_request *, struct md_fs_result *,
        const struct md_fs_output *);
typedef ssize_t (*md_fs_directory_reader)(void *, int, void *, size_t);
void md_fs_directory_read(const struct md_fs_request *, struct md_fs_result *,
        const struct md_fs_output *, md_fs_directory_reader, void *);
#endif
