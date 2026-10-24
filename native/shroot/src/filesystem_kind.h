#ifndef MD_FILESYSTEM_KIND_H
#define MD_FILESYSTEM_KIND_H
enum md_filesystem_kind { MD_FILESYSTEM_INODE, MD_FILESYSTEM_TMPFS, MD_FILESYSTEM_OVERLAY, MD_FILESYSTEM_RAMFS };
static inline int md_filesystem_temporary(enum md_filesystem_kind kind) {
    return kind==MD_FILESYSTEM_TMPFS || kind==MD_FILESYSTEM_RAMFS;
}
static inline const char *md_filesystem_name(enum md_filesystem_kind kind) {
    return kind==MD_FILESYSTEM_TMPFS ? "tmpfs" : kind==MD_FILESYSTEM_RAMFS ? "ramfs"
        : kind==MD_FILESYSTEM_OVERLAY ? "overlay" : "guestfs";
}
static inline unsigned md_filesystem_magic(enum md_filesystem_kind kind) {
    return kind==MD_FILESYSTEM_TMPFS ? 0x01021994U : kind==MD_FILESYSTEM_RAMFS ? 0x858458f6U
        : kind==MD_FILESYSTEM_OVERLAY ? 0x794c7630U : 0;
}
#endif
