#ifndef MD_IPC_NAMESPACE_H
#define MD_IPC_NAMESPACE_H
#include "sysv_ipc.h"
#include "sysv_shm.h"

struct md_ipc_namespace;
struct md_mqueue_view;
/* Worker-only lazy filesystem, borrowed under a retained namespace. */
struct md_mqueue_view *md_ipc_namespace_queues(struct md_ipc_namespace *,int parent);
struct md_ipc_namespace *md_ipc_namespace_new(const char *store, int isolated);
uint64_t md_ipc_namespace_inode(const struct md_ipc_namespace *);
const struct md_user_namespace *md_ipc_namespace_owner(const struct md_ipc_namespace *);
struct md_ipc_namespace *md_ipc_namespace_retain(struct md_ipc_namespace *);
struct md_ipc_namespace *md_ipc_namespace_copy(const struct md_ipc_namespace *, struct md_user_namespace *owner);
void md_ipc_namespace_release(struct md_ipc_namespace *);
int md_ipc_namespace_bind(struct md_ipc_namespace *, const char *store);
int md_ipc_namespace_semaphores(struct md_ipc_namespace *, struct md_ipc **);
int md_ipc_namespace_memory(struct md_ipc_namespace *, struct md_shm **);
/* Independent, caller-owned connection for a retained namespace. It never
 * accesses the supervisor's lazy connection or changes namespace services. */
int md_ipc_namespace_open_memory(const struct md_ipc_namespace *,struct md_shm **);
struct md_ipc *md_ipc_namespace_active(const struct md_ipc_namespace *);
#endif
