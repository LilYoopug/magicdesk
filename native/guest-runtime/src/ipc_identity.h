#ifndef MD_IPC_IDENTITY_H
#define MD_IPC_IDENTITY_H
#include "guest_identity.h"

struct md_ipc_identity {
    int32_t pid;
    uint32_t uid, gid, group_count;
};
enum { MD_IPC_IDENTITY_MAX=sizeof(struct md_ipc_identity)+MD_IDENTITY_GROUPS_MAX*sizeof(uint32_t) };
#endif
