#ifndef MD_NAMESPACE_INTERNAL_H
#define MD_NAMESPACE_INTERNAL_H
#include "namespace.h"
#include "fs_rpc.h"

/* Adapter-only operand, resolved to the retained image object before transport. */
enum { MD_NAMESPACE_EXECUTABLE=-3 };
struct md_namespace_operand { int descriptor; struct md_fs_task_capture capture; };
static inline struct md_namespace_operand md_namespace_descriptor(int fd) {
    return (struct md_namespace_operand){.descriptor=fd};
}

/* Paths are adapter-owned; other syscall pointers are validated when used. */
long md_namespace_request(const struct md_fs *, struct md_fs_request *, struct md_fs_response *);
long md_namespace_open_result(struct md_fs_result *, int flags);
long md_namespace_creation_mode(const struct md_fs *, unsigned);
long md_namespace_relative_mount(const struct md_fs *, int, char *);
long md_namespace_native_descriptor(int);
long md_namespace_inspect(const struct md_fs *, struct md_namespace_operand, const char *, int, unsigned, struct md_fs_response *);
long md_namespace_native_statx(const struct md_fs *, const unsigned long *);
int md_namespace_proc_borrow(const struct md_proc_path *, int *);
long md_namespace_mount(const struct md_fs *, long, const unsigned long *);
long md_namespace_xattr(const struct md_fs *, long, struct md_namespace_operand, const char *, const unsigned long *);
long md_namespace_proc_reopen(const struct md_fs *, int, int flags);
long md_namespace_path_call(const struct md_fs *, long, const unsigned long *, struct md_namespace_operand, const char *);
long md_namespace_host_call(const struct md_fs *, const char *, long, const unsigned long *,
                            unsigned, const char *);
#endif
