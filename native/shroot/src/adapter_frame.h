#ifndef MD_ADAPTER_FRAME_H
#define MD_ADAPTER_FRAME_H
#include "adapter_buffer.h"
#include "fs_buffer.h"
#include "sysv_ipc.h"
#include "sysv_shm.h"
#include "task_outgoing.h"
#include "epoll_calls.h"

/* Protocol views share capacity, never live ownership. Callers publish only
 * initialized bytes; the common allocator owns no filesystem or IPC policy. */
union md_adapter_frame {
    struct md_fs_buffer_frame filesystem;
    struct md_task_outgoing_frame outgoing;
    struct md_epoll_frame epoll;
    struct shmid64_ds shm;
    _Alignas(struct md_ipc_packet) unsigned char ipc[offsetof(struct md_ipc_packet,data)+MD_IPC_VALUE_MAX];
};
#endif
