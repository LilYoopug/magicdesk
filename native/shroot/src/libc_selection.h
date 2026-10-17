#ifndef MD_LIBC_SELECTION_H
#define MD_LIBC_SELECTION_H
struct md_filesystem;
struct md_fs_request;
struct md_fs_result;
struct md_fs_output;
void md_libc_select(struct md_filesystem *,const struct md_fs_request *,
    struct md_fs_result *,const struct md_fs_output *);
#endif
