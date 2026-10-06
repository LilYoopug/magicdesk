#ifndef MD_FS_ANCHOR_H
#define MD_FS_ANCHOR_H

/* Worker-produced path provenance, not an open-file-description mirror. Pins
 * the mount view, O_PATH identity and backing-store lifetime, not its SQLite
 * connection; the kernel owns data IO and locks. Never sent over RPC. */
struct md_fs_anchor;
struct md_fs_anchor *md_fs_anchor_retain(struct md_fs_anchor *);
void md_fs_anchor_release(struct md_fs_anchor *);
/* Borrowed O_PATH descriptor, suitable for cwd/path traversal, not data IO. */
int md_fs_anchor_fd(const struct md_fs_anchor *);
#endif
