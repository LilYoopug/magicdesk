#define _GNU_SOURCE
#include "ipc_namespace.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

struct md_ipc_namespace {
    unsigned references;
    uint64_t id;
    char *store;
    struct md_ipc *semaphores;
    struct md_shm *memory;
    struct md_user_namespace *owner;
};
struct md_ipc_namespace *md_ipc_namespace_new(const char *store, int isolated) {
    struct md_ipc_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    n->references=1;
    if (isolated && (getrandom(&n->id,sizeof(n->id),0)!=sizeof(n->id) || !n->id)) {
        free(n); return NULL;
    }
    if (store && md_ipc_namespace_bind(n,store)) { free(n); return NULL; }
    return n;
}
int md_ipc_namespace_bind(struct md_ipc_namespace *n, const char *store) {
    if (!n || n->store || !store) return -EINVAL;
    n->store=strdup(store);
    return n->store ? 0 : -ENOMEM;
}
struct md_ipc_namespace *md_ipc_namespace_retain(struct md_ipc_namespace *n) {
    if (n) ++n->references;
    return n;
}
uint64_t md_ipc_namespace_inode(const struct md_ipc_namespace *n) { return n->id ? n->id : 1; }
const struct md_user_namespace *md_ipc_namespace_owner(const struct md_ipc_namespace *n) { return n->owner; }
struct md_ipc_namespace *md_ipc_namespace_copy(const struct md_ipc_namespace *n, struct md_user_namespace *owner) {
    struct md_ipc_namespace *copy=n ? md_ipc_namespace_new(n->store,1) : NULL;
    if (copy) copy->owner=md_user_namespace_retain(owner);
    return copy;
}
void md_ipc_namespace_release(struct md_ipc_namespace *n) {
    if (!n || --n->references) return;
    md_ipc_close(n->semaphores);
    md_shm_close(n->memory);
    md_user_namespace_release(n->owner);
    free(n->store); free(n);
}
int md_ipc_namespace_semaphores(struct md_ipc_namespace *n, struct md_ipc **out) {
    *out=NULL;
    if (!n || !n->store) return -ENOTSUP;
    int error=n->semaphores ? 0 : md_ipc_open(n->store,n->id,n->owner,&n->semaphores);
    if (!error) *out=n->semaphores;
    return error;
}
int md_ipc_namespace_memory(struct md_ipc_namespace *n, struct md_shm **out) {
    *out=NULL;
    if (!n || !n->store) return -ENOTSUP;
    int error=n->memory ? 0 : md_shm_open(n->store,n->id,n->owner,&n->memory);
    if (!error) *out=n->memory;
    return error;
}
struct md_ipc *md_ipc_namespace_active(const struct md_ipc_namespace *n) {
    return n ? n->semaphores : NULL;
}
