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
struct md_proc_path md_proc_path(const char *path) {
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
        out.process=(int)RAW0(getpid);
        out.kind = MD_PROC_FD;
    } else if (word(&p, "proc")) {
        if (word(&p,"mounts")) {
            out.kind=MD_PROC_MOUNTS; out.tail=p; out.anchor_length=(size_t)(p-path); return out;
        }
        if (word(&p,"self")) out.process=(int)RAW0(getpid);
        else if (word(&p,"thread-self")) out.process=(int)RAW0(gettid);
        else {
            long pid = number(&p);
            if (pid < 0) return out;
            foreign = pid != RAW0(getpid) && pid != RAW0(gettid);
            out.process = (int)pid;
        }
        if (word(&p, "task")) {
            /* Only the group leader's proc directory contains task/. */
            if (out.process == RAW0(gettid) && out.process != RAW0(getpid)) return out;
            long tid = number(&p);
            if (tid < 0) return out;
            foreign |= tid != RAW0(gettid);
            out.process = (int)tid;
        }
        if (word(&p, "fd")) {
            out.descriptor=(int)number(&p);
            if (out.descriptor < 0) return out;
            out.kind = MD_PROC_FD;
        } else if (word(&p, "cwd")) out.kind = MD_PROC_CWD;
        else if (word(&p, "root")) out.kind = MD_PROC_ROOT;
        else if (word(&p, "exe")) out.kind = MD_PROC_EXE;
        else if (word(&p, "cmdline")) out.kind = MD_PROC_CMDLINE;
        else if (word(&p, "auxv")) out.kind = MD_PROC_AUXV;
        else if (word(&p, "mounts")) out.kind = MD_PROC_MOUNTS;
        else if (word(&p, "mountinfo")) out.kind = MD_PROC_MOUNTINFO;
        else return out;
        if (foreign) { out.foreign_kind=out.kind; out.kind = MD_PROC_FOREIGN; }
    } else return out;
    out.anchor_length = (size_t)(p - path);
    out.tail = p;
    return out;
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
