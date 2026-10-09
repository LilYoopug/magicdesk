#include "identity_snapshot.h"
#include "sealed_manifest.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct snapshot {
    uint32_t version, count;
    uint64_t user_namespace;
    struct md_identity_ids uid, gid;
    uint64_t permitted, effective, inheritable, bounding, ambient;
    uint32_t securebits, no_new_privs;
    uint32_t groups[];
};
_Static_assert(sizeof(struct snapshot)==96,"credential snapshot layout");
int md_identity_snapshot_export(const struct md_identity *id) {
    if (!id) return -EINVAL;
    unsigned count=md_identity_group_count(id);
    size_t size=sizeof(struct snapshot)+count*sizeof(uint32_t);
    struct snapshot *s=calloc(1,size);
    if (!s) return -ENOMEM;
    *s=(struct snapshot){.version=1,.count=count,
        .user_namespace=md_user_namespace_inode(id->user_namespace),.uid=id->uid,.gid=id->gid,
        .permitted=id->caps.permitted,.effective=id->caps.effective,.inheritable=id->caps.inheritable,
        .bounding=id->caps.bounding,.ambient=id->caps.ambient,.securebits=id->caps.securebits,
        .no_new_privs=(unsigned)id->no_new_privs};
    if (count) memcpy(s->groups,md_identity_group_data(id),count*sizeof(uint32_t));
    struct md_fd_identity token;
    int fd=md_sealed_manifest_create("shroot-credentials",s,size,&token);
    free(s); return fd;
}
int md_identity_snapshot_import(int fd, struct md_user_namespace *owner, struct md_identity *out) {
    struct stat st;
    if (!out) return -EINVAL;
    if (fstat(fd,&st)) return -errno;
    if (st.st_size<(off_t)sizeof(struct snapshot)
            || st.st_size>(off_t)(sizeof(struct snapshot)+MD_IDENTITY_GROUPS_MAX*sizeof(uint32_t))) return -EPROTO;
    struct snapshot *s=malloc((size_t)st.st_size);
    if (!s) return -ENOMEM;
    size_t size=0; struct md_fd_identity token;
    int r=md_sealed_manifest_read(fd,s,(size_t)st.st_size,&size,&token);
    uint64_t valid=(UINT64_C(1)<<(CAP_LAST_CAP+1))-1;
    if (!r && (size<sizeof(*s) || size!=(size_t)st.st_size || s->version!=1 || s->count>MD_IDENTITY_GROUPS_MAX
            || size!=sizeof(*s)+s->count*sizeof(uint32_t)
            || s->user_namespace!=md_user_namespace_inode(owner) || s->no_new_privs>1
            || ((s->permitted|s->effective|s->inheritable|s->bounding|s->ambient)&~valid)
            || (s->securebits&~255U) || (s->effective&~s->permitted)
            || (s->ambient&~(s->permitted&s->inheritable)))) r=-EPROTO;
    if (!r && (s->uid.real==UINT32_MAX || s->uid.effective==UINT32_MAX
            || s->uid.saved==UINT32_MAX || s->uid.fs==UINT32_MAX || s->gid.real==UINT32_MAX
            || s->gid.effective==UINT32_MAX || s->gid.saved==UINT32_MAX || s->gid.fs==UINT32_MAX)) r=-EPROTO;
    struct md_identity id={0};
    if (!r) {
        id=(struct md_identity){.uid=s->uid,.gid=s->gid,
            .caps={s->permitted,s->effective,s->inheritable,s->bounding,s->ambient,s->securebits},
            .no_new_privs=(int)s->no_new_privs,.user_namespace=md_user_namespace_retain(owner)};
        r=md_identity_groups(&id,s->groups,s->count);
    }
    free(s);
    if (r) md_identity_release(&id);
    else *out=id;
    return r;
}
