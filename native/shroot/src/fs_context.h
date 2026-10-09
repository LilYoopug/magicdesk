#ifndef MD_FS_CONTEXT_H
#define MD_FS_CONTEXT_H
#include "fs_operation.h"
struct md_filesystem;
void md_fs_context_mount(struct md_filesystem *,const struct md_fs_request *,
    struct md_fs_result *,const struct md_fs_output *);
#endif
