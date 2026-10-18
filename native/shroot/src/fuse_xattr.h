#ifndef MD_FUSE_XATTR_H
#define MD_FUSE_XATTR_H
#include "fuse_session.h"
#include "fs_operation.h"
struct md_fs_output;
int md_fuse_xattr_request(struct md_fuse_session *,const struct md_identity *,uint32_t,
    uint64_t,const struct stat *,const struct md_fs_request *,struct md_resource_wakeup *,
    struct md_fuse_request **);
void md_fuse_xattr_result(struct md_fuse_request *,const struct md_fs_request *,
    struct md_fs_result *,const struct md_fs_output *);
#endif
