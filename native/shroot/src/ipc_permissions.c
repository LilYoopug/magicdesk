#include "ipc_permissions.h"
#include <errno.h>

int md_ipc_perm_access(const struct md_user_namespace *owner, const struct md_identity *id,
        const struct ipc64_perm *p, unsigned mode) {
    if (md_identity_capable_in(id,owner,CAP_IPC_OWNER)) return 0;
    unsigned shift=id->uid.effective==p->uid || id->uid.effective==p->cuid ? 6
        : md_identity_in_group(id,p->gid) || md_identity_in_group(id,p->cgid) ? 3 : 0;
    return ((p->mode>>shift)&mode)==mode ? 0 : -EACCES;
}
int md_ipc_perm_owner(const struct md_user_namespace *owner, const struct md_identity *id,
        const struct ipc64_perm *p) {
    return id->uid.effective==p->uid || id->uid.effective==p->cuid
        || md_identity_capable_in(id,owner,CAP_SYS_ADMIN) ? 0 : -EPERM;
}
void md_ipc_perm_visible(const struct md_identity *id, struct ipc64_perm *p) {
    p->uid=md_identity_visible_id(id,0,p->uid); p->cuid=md_identity_visible_id(id,0,p->cuid);
    p->gid=md_identity_visible_id(id,1,p->gid); p->cgid=md_identity_visible_id(id,1,p->cgid);
}
int md_ipc_perm_set(const struct md_identity *id, struct ipc64_perm *p, uint32_t uid, uint32_t gid, unsigned mode) {
    uid=md_user_namespace_into(id->user_namespace,0,uid);
    gid=md_user_namespace_into(id->user_namespace,1,gid);
    if (uid==UINT32_MAX || gid==UINT32_MAX) return -EINVAL;
    p->uid=uid; p->gid=gid; p->mode=(p->mode&~0777)|(mode&0777);
    return 0;
}
