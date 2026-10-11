#ifndef MD_FILE_METADATA_H
#define MD_FILE_METADATA_H
#include <stdint.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/stat.h>

/* Transport-neutral metadata; no guest pointers or libc-dependent padding. */
struct md_fs_info {
    uint64_t device, inode, links, rdev, mount_id;
    int64_t size, blocks;
    uint32_t mode, uid, gid, block_size;
    int64_t access_seconds, modify_seconds, change_seconds;
    uint32_t access_nanos, modify_nanos, change_nanos, reserved;
};
static inline void md_fs_stat_info(const struct stat *s, struct md_fs_info *out) {
    *out=(struct md_fs_info){.device=s->st_dev,.inode=s->st_ino,.links=s->st_nlink,
        .rdev=s->st_rdev,.size=s->st_size,.blocks=s->st_blocks,.mode=s->st_mode,
        .uid=s->st_uid,.gid=s->st_gid,.block_size=(uint32_t)s->st_blksize,
        .access_seconds=s->st_atim.tv_sec,.modify_seconds=s->st_mtim.tv_sec,
        .change_seconds=s->st_ctim.tv_sec,.access_nanos=(uint32_t)s->st_atim.tv_nsec,
        .modify_nanos=(uint32_t)s->st_mtim.tv_nsec,.change_nanos=(uint32_t)s->st_ctim.tv_nsec};
}
static inline void md_fs_info_stat(const struct md_fs_info *i, struct stat *s) {
    *s=(struct stat){.st_dev=i->device,.st_ino=i->inode,.st_nlink=i->links,
        .st_rdev=i->rdev,.st_size=i->size,.st_blocks=i->blocks,.st_mode=i->mode,
        .st_uid=i->uid,.st_gid=i->gid,.st_blksize=i->block_size,
        .st_atim={i->access_seconds,i->access_nanos},.st_mtim={i->modify_seconds,i->modify_nanos},
        .st_ctim={i->change_seconds,i->change_nanos}};
}
static inline void md_fs_info_statx(const struct md_fs_info *i, struct statx *s) {
    *s=(struct statx){.stx_mask=STATX_BASIC_STATS|(i->mount_id ? STATX_MNT_ID : 0),
        .stx_mnt_id=i->mount_id,.stx_blksize=i->block_size,.stx_nlink=(uint32_t)i->links,
        .stx_uid=i->uid,.stx_gid=i->gid,.stx_mode=(uint16_t)i->mode,.stx_ino=i->inode,
        .stx_size=i->size,.stx_blocks=i->blocks,
        .stx_atime={i->access_seconds,i->access_nanos,0},
        .stx_mtime={i->modify_seconds,i->modify_nanos,0},
        .stx_ctime={i->change_seconds,i->change_nanos,0},
        .stx_dev_major=major(i->device),.stx_dev_minor=minor(i->device),
        .stx_rdev_major=major(i->rdev),.stx_rdev_minor=minor(i->rdev)};
}
static inline void md_stat_statx(const struct stat *s, struct statx *out) {
    struct md_fs_info info;
    md_fs_stat_info(s,&info);
    md_fs_info_statx(&info,out);
}
#endif
