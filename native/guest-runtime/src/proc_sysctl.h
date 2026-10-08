#ifndef MD_PROC_SYSCTL_H
#define MD_PROC_SYSCTL_H
#include "proc_file.h"
const char *md_proc_sysctl_name(enum md_proc_file_kind);
int md_proc_sysctl_access(enum md_proc_file_kind, const struct md_identity *, unsigned mode, int effective);
long md_proc_sysctl_read(const struct md_uts_namespace *, enum md_proc_file_kind,
    void *, size_t, int64_t);
long md_proc_sysctl_write(struct md_uts_namespace *, enum md_proc_file_kind,
    const struct md_identity *, const void *, size_t, int64_t *);
#endif
