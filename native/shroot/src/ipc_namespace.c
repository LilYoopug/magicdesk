#define _GNU_SOURCE
#include "ipc_namespace_internal.h"
#include "mqueue_view.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

struct md_ipc_namespace *md_ipc_namespace_new(const char *store, int isolated) {
    struct md_ipc_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    atomic_init(&n->references,1);
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
    if (n) atomic_fetch_add_explicit(&n->references,1,memory_order_relaxed);
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
    if (!n || atomic_fetch_sub_explicit(&n->references,1,memory_order_acq_rel)!=1) return;
    if (n->release_services) n->release_services(n);
    md_mqueue_view_free(n->queues);
    md_user_namespace_release(n->owner);
    free(n->store); free(n);
}
struct md_mqueue_view *md_ipc_namespace_queues(struct md_ipc_namespace *n,int parent) {
    if (!n) { errno=EOPNOTSUPP; return NULL; }
    if (!n->queues && parent>=0) n->queues=md_mqueue_view_new(parent,n->owner);
    return n->queues;
}
