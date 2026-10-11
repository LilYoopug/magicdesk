#ifndef MD_FS_CONTROL_H
#define MD_FS_CONTROL_H
#include "fs_operation.h"
struct md_filesystem;
struct md_mount_namespace;
struct md_view_mount;

/* Consumes carrier on every path; file and origin are borrowed. Publish only
 * after all fallible descriptor preparation has completed. */
int md_fs_control_publish(int carrier,struct md_control_file file,struct md_fs_anchor *,
    const struct md_identity *,int flags,struct md_fs_result *,const struct md_fs_output *);

typedef int (*md_fs_control_opener)(void *,int fd,int flags,const struct md_identity *,
    struct md_fs_anchor *,struct md_control_file *);
struct stat;
struct md_fs_control_source {
    void *context;
    int (*stat)(void *,int fd,struct stat *);
    md_fs_control_opener open;
    unsigned long filesystem;
};
/* Existing native carriers with provider-owned semantics (cgroup/sysfs).
 * Handles common metadata/access/open policy, returns zero for domain-specific
 * operations. The provider may return no control for directories and symlinks. */
int md_fs_control_operation(struct md_filesystem *,struct md_mount_namespace *,struct md_view_mount *,
    int fd,const struct md_fs_control_source *,const struct md_fs_request *,struct md_fs_result *,const struct md_fs_output *);
#endif
