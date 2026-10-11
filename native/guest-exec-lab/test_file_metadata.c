#define _GNU_SOURCE
#include "file_metadata.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const struct stat original={.st_dev=makedev(511,70001),.st_ino=UINT64_C(0x123456789abcdef),
        .st_nlink=37,.st_rdev=makedev(123,456789),.st_size=INT64_C(0x123456789),
        .st_blocks=INT64_C(0xabcdef),.st_mode=S_IFCHR|06751,.st_uid=12345,.st_gid=67890,
        .st_blksize=16384,.st_atim={-123,456},.st_mtim={INT64_C(0x123456789),999999999},
        .st_ctim={789,123456789}};
    struct md_fs_info info, roundtrip;
    struct stat restored;
    md_fs_stat_info(&original,&info);
    assert(!info.mount_id && !info.reserved);
    md_fs_info_stat(&info,&restored);
    md_fs_stat_info(&restored,&roundtrip);
    assert(!memcmp(&info,&roundtrip,sizeof(info)));
    struct statx native, logical;
    md_stat_statx(&original,&native);
    md_fs_info_statx(&info,&logical);
    assert(!memcmp(&native,&logical,sizeof(native)));
    assert(native.stx_mask==STATX_BASIC_STATS && !native.stx_mnt_id);
    assert(native.stx_dev_major==511 && native.stx_dev_minor==70001);
    assert(native.stx_rdev_major==123 && native.stx_rdev_minor==456789);
    assert(native.stx_blocks==(uint64_t)original.st_blocks);
    assert(native.stx_size==(uint64_t)original.st_size && native.stx_ino==original.st_ino);
    assert(native.stx_uid==original.st_uid && native.stx_gid==original.st_gid);
    assert(native.stx_nlink==original.st_nlink && native.stx_mode==original.st_mode);
    assert(native.stx_blksize==original.st_blksize);
    assert(native.stx_atime.tv_sec==-123 && native.stx_atime.tv_nsec==456);
    assert(native.stx_mtime.tv_sec==original.st_mtim.tv_sec && native.stx_mtime.tv_nsec==999999999);
    assert(native.stx_ctime.tv_sec==789 && native.stx_ctime.tv_nsec==123456789);
    assert(!native.stx_btime.tv_sec && !native.stx_btime.tv_nsec && !native.stx_attributes_mask);
    info.mount_id=UINT64_C(0x123456789);
    md_fs_info_statx(&info,&logical);
    assert(logical.stx_mask==(STATX_BASIC_STATS|STATX_MNT_ID) && logical.stx_mnt_id==info.mount_id);
    puts("PASS file metadata: native/namespace stat and statx share complete fields");
    return 0;
}
