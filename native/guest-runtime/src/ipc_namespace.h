#ifndef MD_IPC_NAMESPACE_H
#define MD_IPC_NAMESPACE_H
#include "sysv_ipc.h"
#include "sysv_shm.h"

struct md_ipc_namespace;
struct md_ipc_namespace *md_ipc_namespace_new(const char *store, int isolated);
uint64_t md_ipc_namespace_inode(const struct md_ipc_namespace *);
const struct md_user_namespace *md_ipc_namespace_owner(const struct md_ipc_namespace *);
struct md_ipc_namespace *md_ipc_namespace_retain(struct md_ipc_namespace *);
struct md_ipc_namespace *md_ipc_namespace_copy(const struct md_ipc_namespace *, struct md_user_namespace *owner);
void md_ipc_namespace_release(struct md_ipc_namespace *);
int md_ipc_namespace_bind(struct md_ipc_namespace *, const char *store);
int md_ipc_namespace_semaphores(struct md_ipc_namespace *, struct md_ipc **);
int md_ipc_namespace_memory(struct md_ipc_namespace *, struct md_shm **);
struct md_ipc *md_ipc_namespace_active(const struct md_ipc_namespace *);
#endif
