#include "ipc_namespace_internal.h"
#include <errno.h>

static void release_services(struct md_ipc_namespace *n) {
    md_ipc_close(n->semaphores);
    md_shm_close(n->memory);
}
int md_ipc_namespace_semaphores(struct md_ipc_namespace *n, struct md_ipc **out) {
    *out=NULL;
    if (!n || !n->store) return -ENOTSUP;
    n->release_services=release_services;
    int error=n->semaphores ? 0 : md_ipc_open(n->store,n->id,n->owner,&n->semaphores);
    if (!error) *out=n->semaphores;
    return error;
}
int md_ipc_namespace_memory(struct md_ipc_namespace *n, struct md_shm **out) {
    *out=NULL;
    if (!n || !n->store) return -ENOTSUP;
    n->release_services=release_services;
    int error=n->memory ? 0 : md_shm_open(n->store,n->id,n->owner,&n->memory);
    if (!error) *out=n->memory;
    return error;
}
struct md_ipc *md_ipc_namespace_active(const struct md_ipc_namespace *n) {
    return n ? n->semaphores : NULL;
}
