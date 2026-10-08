#include "proc_sysctl.h"
#include "uts_namespace.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

const char *md_proc_sysctl_name(enum md_proc_file_kind kind) {
    switch (kind) {
    case MD_PROC_FILE_HOSTNAME: return "hostname";
    case MD_PROC_FILE_DOMAINNAME: return "domainname";
    case MD_PROC_FILE_OSTYPE: return "ostype";
    case MD_PROC_FILE_OSRELEASE: return "osrelease";
    case MD_PROC_FILE_VERSION: return "version";
    case MD_PROC_FILE_OVERFLOWUID: return "overflowuid";
    case MD_PROC_FILE_OVERFLOWGID: return "overflowgid";
    default: return NULL;
    }
}
static char *field(struct utsname *names, enum md_proc_file_kind kind) {
    switch (kind) {
    case MD_PROC_FILE_HOSTNAME: return names->nodename;
    case MD_PROC_FILE_DOMAINNAME: return names->domainname;
    case MD_PROC_FILE_OSTYPE: return names->sysname;
    case MD_PROC_FILE_OSRELEASE: return names->release;
    case MD_PROC_FILE_VERSION: return names->version;
    default: return NULL;
    }
}
int md_proc_sysctl_access(enum md_proc_file_kind kind, const struct md_identity *id,
        unsigned mode, int effective) {
    if (!md_proc_sysctl_name(kind) || !id || mode&~7U) return -EINVAL;
    if (mode&X_OK) return -EACCES;
    /* Linux's UTS sysctl table uses global-root DAC, without a capability
     * override. sethostname has its separate namespace-scoped capability. */
    if ((mode&W_OK) && (kind>MD_PROC_FILE_DOMAINNAME
            || (effective ? id->uid.effective : id->uid.real))) return -EACCES;
    return 0;
}
long md_proc_sysctl_read(const struct md_uts_namespace *uts, enum md_proc_file_kind kind,
        void *out, size_t capacity, int64_t offset) {
    if (offset<0) return -EINVAL;
    struct utsname names;
    char scalar[16];
    const char *text;
    if (kind==MD_PROC_FILE_OVERFLOWUID || kind==MD_PROC_FILE_OVERFLOWGID) {
        snprintf(scalar,sizeof(scalar),"%u",MD_USER_OVERFLOW_ID);
        text=scalar;
    } else {
        if (!uts) return -EINVAL;
        md_uts_namespace_read(uts,&names);
        text=field(&names,kind);
    }
    if (!text) return -EINVAL;
    size_t length=strlen(text);
    if ((uint64_t)offset>length || !capacity) return 0;
    length-=(size_t)offset;
    if (length>capacity) length=capacity;
    if (length) memcpy(out,text+offset,length);
    if (length<capacity) ((char *)out)[length++]='\n';
    return (long)length;
}
long md_proc_sysctl_write(struct md_uts_namespace *uts, enum md_proc_file_kind kind,
        const struct md_identity *writer, const void *data, size_t size, int64_t *offset) {
    if (!uts || !offset || *offset<0) return -EINVAL;
    if (md_proc_sysctl_access(kind,writer,W_OK,1)) return -EPERM;
    if (!size) return 0;
    struct utsname names; md_uts_namespace_read(uts,&names);
    char *text=field(&names,kind);
    if ((uint64_t)*offset>strlen(text)) return (long)size;
    size_t position=(size_t)*offset;
    int64_t next;
    if (size>INT64_MAX || __builtin_add_overflow(*offset,(int64_t)size,&next)) return -EINVAL;
    for (size_t i=0;i<size && position<sizeof(names.nodename)-1;++i) {
        char c=((const char *)data)[i];
        if (!c || c=='\n') break;
        text[position++]=c;
    }
    int error=md_uts_namespace_set(uts,kind==MD_PROC_FILE_DOMAINNAME,text,position);
    if (!error) *offset=next;
    return error ? error : (long)size;
}
