#ifndef MD_IPC_NAMESPACE_INTERNAL_H
#define MD_IPC_NAMESPACE_INTERNAL_H
#include "ipc_namespace.h"
#include <stdatomic.h>

struct md_ipc_namespace {
    atomic_uint references;
    uint64_t id;
    char *store;
    struct md_user_namespace *owner;
    /* Lazy services are supervisor-owned; the mount view is worker-owned.
     * Retained namespace references protect both through final retirement. */
    struct md_ipc *semaphores;
    struct md_shm *memory;
    void (*release_services)(struct md_ipc_namespace *);
    struct md_mqueue_view *queues;
};
#endif
