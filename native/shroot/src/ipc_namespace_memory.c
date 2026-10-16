#include "ipc_namespace_internal.h"
#include <errno.h>

int md_ipc_namespace_open_memory(const struct md_ipc_namespace *n,struct md_shm **out) {
    *out=NULL;
    return !n || !n->store ? -ENOTSUP : md_shm_open(n->store,n->id,n->owner,out);
}
