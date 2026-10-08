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
/* Rebase only a copied FS context's cwd, never existing open descriptors. The
 * destination must be an unpublished copy with the same stable mount slots. */
int md_fs_mounts_copy_cwd(struct md_mount_namespace *source, struct md_mount_namespace *copy,
        const struct md_fs_anchor *, struct md_fs_anchor **);
/* Preserve the resolved mount when capturing a freshly opened root. Without
 * provenance an ambiguous native object fails instead of choosing an alias. */
int md_fs_root_capture(struct md_filesystem *, int fd, const struct md_fs_anchor *, struct md_fs_location *);
int md_fs_root_select(struct md_filesystem *, const struct md_fs_location *);
/* Worker-only identity check, independent of cwd and textual path spelling. */
int md_fs_root_is_mount_root(struct md_filesystem *, const struct md_fs_location *);
/* Resolve the target namespace's effective root into an unpublished FS context.
 * Existing dirfds keep their old mount provenance. Worker-only. */
int md_fs_mounts_join_context(struct md_filesystem *, struct md_guest_domain *);
void md_fs_mounts_close(struct md_filesystem *);
int md_fs_mount_table(struct md_filesystem *, unsigned mountinfo, unsigned flags);
int md_fs_native_mount(struct md_filesystem *, uint64_t native, uint64_t *guest);
int md_fs_base_mount(struct md_filesystem *, int shared_memory, uint64_t *guest);
int md_fs_mount_change(struct md_filesystem *, struct md_guest_domain *, const struct md_fs_request *);
/* Dispatches the composed view; the ordinary inode engine remains the backend. */
void md_fs_mounts_execute(struct md_filesystem *, const struct md_fs_request *,
        struct md_fs_result *, const struct md_fs_output *);
void md_fs_inode_execute(struct md_filesystem *, const struct md_fs_request *,
        struct md_fs_result *, const struct md_fs_output *);
#endif
