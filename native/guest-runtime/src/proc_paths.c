#define _GNU_SOURCE
#include "proc_paths.h"
#include "raw.h"
#include <limits.h>

static const char *component(const char *p) {
    for (;;) {
        while (*p == '/') ++p;
        if (p[0] != '.' || (p[1] && p[1] != '/')) return p;
        ++p;
    }
}
static int word(const char **p, const char *name) {
    const char *s = component(*p);
    size_t n = md_length(name);
    if (!md_prefix(s, name) || (s[n] && s[n] != '/')) return 0;
    *p = s + n;
    return 1;
}
int md_host_path(const char *p) {
    if (*p != '/') return 0;
    if (word(&p, "dev")) return !word(&p, "shm");
    return word(&p, "proc");
}
static long number(const char **p) {
    const char *s = component(*p);
    if (*s < '0' || *s > '9') return -1;
    if (*s == '0' && s[1] >= '0' && s[1] <= '9') return -1;
    unsigned long n = 0;
    while (*s >= '0' && *s <= '9') {
        n = n * 10 + (unsigned)(*s++ - '0');
        if (n > INT_MAX) return -1;
    }
    if (*s && *s != '/') return -1;
    *p = s;
    return (long)n;
}
struct md_proc_path md_proc_path_for(const char *path,int tid,int tgid) {
    struct md_proc_path out = {.descriptor=-1};
    if (*path != '/') return out;
    const char *p = path;
    int foreign = 0;
    if (word(&p, "dev")) {
        if (word(&p, "fd")) {
            out.descriptor=(int)number(&p);
            if (out.descriptor < 0) return out;
        } else if (word(&p, "stdin")) { out.ordinary_link=1; out.descriptor=0; }
        else if (word(&p, "stdout")) { out.ordinary_link=1; out.descriptor=1; }
        else if (word(&p, "stderr")) { out.ordinary_link=1; out.descriptor=2; }
        else return out;
        out.process=tgid;
        out.kind = MD_PROC_FD;
    } else if (word(&p, "proc")) {
        if (word(&p,"cgroups")) {
            out.kind=MD_PROC_CGROUPS; out.process=tid;
            out.tail=p; out.anchor_length=(size_t)(p-path); return out;
        }
        if (word(&p,"mounts")) {
            out.kind=MD_PROC_MOUNTS; out.tail=p; out.anchor_length=(size_t)(p-path); return out;
        }
        if (word(&p,"sys")) {
            if (!word(&p,"kernel")) return out;
            if (word(&p,"hostname")) out.kind=MD_PROC_HOSTNAME;
            else if (word(&p,"domainname")) out.kind=MD_PROC_DOMAINNAME;
            else if (word(&p,"ostype")) out.kind=MD_PROC_OSTYPE;
            else if (word(&p,"osrelease")) out.kind=MD_PROC_OSRELEASE;
            else if (word(&p,"version")) out.kind=MD_PROC_VERSION;
            else if (word(&p,"overflowuid")) out.kind=MD_PROC_OVERFLOWUID;
            else if (word(&p,"overflowgid")) out.kind=MD_PROC_OVERFLOWGID;
            else return out;
            out.process=tid;
            out.tail=p; out.anchor_length=(size_t)(p-path); return out;
        }
        if (word(&p,"self")) out.process=tgid;
        else if (word(&p,"thread-self")) out.process=tid;
        else {
            long pid = number(&p);
            if (pid < 0) return out;
            foreign = pid != tgid && pid != tid;
            out.process = (int)pid;
        }
        if (word(&p, "task")) {
            /* Only the group leader's proc directory contains task/. */
            if (out.process == tid && out.process != tgid) return out;
            long selected = number(&p);
            if (selected < 0) return out;
            foreign |= selected != tid;
            out.process = (int)selected;
        }
        if (!*component(p)) { out.kind=MD_PROC_PROCESS_DIRECTORY; p=component(p); }
        else if (word(&p, "fd")) {
            out.descriptor=(int)number(&p);
            if (out.descriptor < 0) return out;
            out.kind = MD_PROC_FD;
        } else if (word(&p, "cwd")) out.kind = MD_PROC_CWD;
        else if (word(&p, "root")) out.kind = MD_PROC_ROOT;
        else if (word(&p, "exe")) out.kind = MD_PROC_EXE;
        else if (word(&p, "cmdline")) out.kind = MD_PROC_CMDLINE;
        else if (word(&p, "auxv")) out.kind = MD_PROC_AUXV;
        else if (word(&p,"status")) out.kind=MD_PROC_STATUS;
        else if (word(&p,"stat")) out.kind=MD_PROC_STAT;
        else if (word(&p,"cgroup")) out.kind=MD_PROC_CGROUP;
        else if (word(&p, "mounts")) out.kind = MD_PROC_MOUNTS;
        else if (word(&p, "mountinfo")) out.kind = MD_PROC_MOUNTINFO;
        else if (word(&p, "uid_map")) out.kind = MD_PROC_UID_MAP;
        else if (word(&p, "gid_map")) out.kind = MD_PROC_GID_MAP;
        else if (word(&p, "setgroups")) out.kind = MD_PROC_SETGROUPS;
        else if (word(&p,"ns")) {
            if (word(&p,"user")) out.kind=MD_PROC_NS_USER;
            else if (word(&p,"mnt")) out.kind=MD_PROC_NS_MOUNT;
            else if (word(&p,"uts")) out.kind=MD_PROC_NS_UTS;
            else if (word(&p,"ipc")) out.kind=MD_PROC_NS_IPC;
            else if (word(&p,"pid")) out.kind=MD_PROC_NS_PID;
            else if (word(&p,"pid_for_children")) out.kind=MD_PROC_NS_PID_CHILDREN;
            else if (word(&p,"net")) out.kind=MD_PROC_NS_NETWORK;
            else if (word(&p,"cgroup")) out.kind=MD_PROC_NS_CGROUP;
            else if (*component(p)) { out.kind=MD_PROC_NS_UNSUPPORTED; p+=md_length(p); }
            else { out.kind=MD_PROC_NS_DIRECTORY; p=component(p); }
        }
        else return out;
        if (foreign) { out.foreign_kind=out.kind; out.kind = MD_PROC_FOREIGN; }
    } else return out;
    out.anchor_length = (size_t)(p - path);
    out.tail = p;
    return out;
}
struct md_proc_path md_proc_path(const char *path) {
    return md_proc_path_for(path,(int)RAW0(gettid),(int)RAW0(getpid));
}
int md_proc_task_path(const char *path, char *out, size_t capacity) {
    const char *p=path;
    if (*p!='/' || !word(&p,"proc") || !word(&p,"thread-self"))
        return md_copy(out,capacity,path);
    char prefix[64]="/proc/";
    md_decimal(prefix+md_length(prefix),(unsigned)RAW0(gettid));
    int error=md_copy(out,capacity,prefix);
    return error ? error : md_append(out,capacity,p);
}
