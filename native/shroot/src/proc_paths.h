#ifndef MD_PROC_PATHS_H
#define MD_PROC_PATHS_H
#include <stddef.h>
#include <stdint.h>

enum md_proc_kind { MD_PROC_NONE, MD_PROC_FD, MD_PROC_FDINFO, MD_PROC_CWD, MD_PROC_ROOT, MD_PROC_EXE,
                    MD_PROC_CMDLINE, MD_PROC_AUXV, MD_PROC_FOREIGN, MD_PROC_MOUNTS, MD_PROC_MOUNTINFO,
                    MD_PROC_UID_MAP, MD_PROC_GID_MAP, MD_PROC_SETGROUPS,
                    MD_PROC_HOSTNAME, MD_PROC_DOMAINNAME, MD_PROC_OSTYPE,
                    MD_PROC_OSRELEASE, MD_PROC_VERSION,
                    MD_PROC_OVERFLOWUID, MD_PROC_OVERFLOWGID,
                    MD_PROC_NS_USER, MD_PROC_NS_MOUNT, MD_PROC_NS_UTS, MD_PROC_NS_IPC,
                    MD_PROC_NS_PID, MD_PROC_NS_PID_CHILDREN, MD_PROC_NS_NETWORK, MD_PROC_NS_CGROUP,
                    MD_PROC_NS_DIRECTORY,
                    MD_PROC_PROCESS_DIRECTORY,
                    MD_PROC_STATUS, MD_PROC_STAT,
                    MD_PROC_CGROUP, MD_PROC_CGROUPS,
                    MD_PROC_NS_UNSUPPORTED,
                    MD_PROC_NET_UNPRIVILEGED_PORT, MD_PROC_NET_PING_GROUPS, MD_PROC_NET_LOCAL_PORTS };
static inline int md_proc_network_sysctl(enum md_proc_kind kind) {
    return kind>=MD_PROC_NET_UNPRIVILEGED_PORT && kind<=MD_PROC_NET_LOCAL_PORTS;
}
struct md_proc_path {
    enum md_proc_kind kind;
    size_t anchor_length;
    const char *tail;
    int ordinary_link;
    int process;
    int descriptor;
    enum md_proc_kind foreign_kind;
};
int md_host_path(const char *);
/* Classifies adapter-owned absolute strings, without resolving guest symlinks. */
struct md_proc_path md_proc_path(const char *);
struct md_proc_path md_proc_path_for(const char *, int tid, int tgid);
/* Pin thread-self to the requesting task before delegating a kernel lookup. */
int md_proc_task_path(const char *, char *, size_t);
/* An image belongs to one address space, not to the syscall transport. */
struct md_process_image {
    unsigned argc;
    uintptr_t argv[1040];
    size_t arg_lengths[1040];
    unsigned char auxv[4096];
    size_t auxv_bytes;
    char executable_object[33];
    const char *executable_path;
};
void md_proc_image_init(struct md_process_image *, unsigned argc, char *const *argv,
        const void *auxv, size_t auxv_bytes);
struct md_fs;
long md_proc_executable_open(const struct md_fs *, const char *path, int flags);
long md_proc_image_open(const struct md_fs *, enum md_proc_kind, int flags);
#endif
