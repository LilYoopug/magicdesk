#ifndef MD_IPC_SCOPE_H
#define MD_IPC_SCOPE_H
#include "ipc_credentials.h"
#include <stdatomic.h>
#include <sys/types.h>

/* Internal epoch/store custody, independent of the worker's SQLite handle. */
struct md_fd_messages;
struct md_ipc_scope {
    atomic_uint refs;
    int lease, root;
    dev_t device;
    ino_t inode;
    struct md_fd_messages *local_messages;
};
void md_ipc_scope_release(struct md_ipc_scope *);
#endif
