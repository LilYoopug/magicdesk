#ifndef MD_FS_MOUNTS_H
#define MD_FS_MOUNTS_H
#include "fs_engine.h"
#include "fs_location.h"

#define MD_FS_MOUNTS_MAX 16
struct md_fs_attachment { const char *source, *target; int readonly; };
/* Explicit native directories, scoped to one launch. No mount syscall, identity
 * change, source creation or persisted configuration is performed here. */
int md_fs_mounts_open(struct md_filesystem *, const struct md_fs_attachment *, unsigned count);
/* Worker-only candidate construction. Copies topology and rebases one explicit
 * root, not open descriptions, cwd or the task registry. Outputs change only on
 * success. Guest namespace publication additionally requires FD provenance. */
int md_fs_mounts_copy(struct md_filesystem *, const struct md_fs_location *root,
        struct md_mount_namespace **copy, struct md_fs_location *copied_root);
int md_fs_root_capture(struct md_filesystem *, int fd, struct md_fs_location *);
int md_fs_root_select(struct md_filesystem *, const struct md_fs_location *);
void md_fs_mounts_close(struct md_filesystem *);
int md_fs_mount_table(struct md_filesystem *, unsigned mountinfo);
int md_fs_native_mount(struct md_filesystem *, uint64_t native, uint64_t *guest);
int md_fs_base_mount(struct md_filesystem *, int shared_memory, uint64_t *guest);
/* Dispatches the composed view; the ordinary inode engine remains the backend. */
void md_fs_mounts_execute(struct md_filesystem *, const struct md_fs_request *,
        struct md_fs_result *, const struct md_fs_output *);
void md_fs_inode_execute(struct md_filesystem *, const struct md_fs_request *,
        struct md_fs_result *, const struct md_fs_output *);
#endif
