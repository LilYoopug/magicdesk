#ifndef MD_FS_CONTEXT_H
#define MD_FS_CONTEXT_H
#include "fs_operation.h"
struct md_filesystem;
struct md_view_mount;
int md_fs_super_reconfigure(struct md_filesystem *,const struct md_view_mount *,int readonly);
void md_fs_context_mount(struct md_filesystem *,const struct md_fs_request *,
    struct md_fs_result *,const struct md_fs_output *);
#endif
