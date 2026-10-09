#ifndef MD_IPC_STORAGE_H
#define MD_IPC_STORAGE_H
/* Ephemeral IPC metadata has an independent on-disk contract from the inode
 * store. Different runtime formats must not share locks, keys or segment IDs. */
int md_ipc_storage_open(const char *store, const char *kind);
#endif
