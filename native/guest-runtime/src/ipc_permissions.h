#ifndef MD_IPC_PERMISSIONS_H
#define MD_IPC_PERMISSIONS_H
#include "guest_identity.h"
#include <linux/ipc.h>
int md_ipc_perm_access(const struct md_user_namespace *, const struct md_identity *, const struct ipc64_perm *, unsigned);
int md_ipc_perm_owner(const struct md_user_namespace *, const struct md_identity *, const struct ipc64_perm *);
void md_ipc_perm_visible(const struct md_identity *, struct ipc64_perm *);
int md_ipc_perm_set(const struct md_identity *, struct ipc64_perm *, uint32_t uid, uint32_t gid, unsigned mode);
#endif
