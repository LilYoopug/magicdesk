#ifndef MD_PROC_FDINFO_H
#define MD_PROC_FDINFO_H
#include "fs_operation.h"
struct md_filesystem;
void md_fs_fdinfo(struct md_filesystem *,const struct md_fs_request *,
    struct md_fs_result *,const struct md_fs_output *);
#endif
