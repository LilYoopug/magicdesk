#ifndef MD_FS_BUFFER_H
#define MD_FS_BUFFER_H
#include "fs_rpc.h"
#include "fd_receipt.h"
#include "command_image.h"
#include "fd_channel.h"
#include "received_info.h"
#include <fcntl.h>

enum md_fs_buffer_control { MD_FS_BUFFER_CALL=16, MD_FS_BUFFER_ACK, MD_FS_BUFFER_SENT,
    MD_FS_BUFFER_EXEC_PREPARE, MD_FS_BUFFER_EXEC_CANCEL,
    MD_FS_BUFFER_SNAPSHOT_BEGIN, MD_FS_BUFFER_SNAPSHOT_APPEND, MD_FS_BUFFER_SNAPSHOT_FINISH,
    MD_FS_BUFFER_RIGHTS_BEGIN, MD_FS_BUFFER_RIGHTS_READY, MD_FS_BUFFER_RIGHTS_DONE,
    MD_FS_BUFFER_CHANNEL_OBSERVED, MD_FS_BUFFER_PROC_LINK, MD_FS_BUFFER_TASK_DONE,
    MD_FS_BUFFER_TASK_RECEIVE, MD_FS_BUFFER_RECEIVED_INSPECT,
    MD_FS_BUFFER_RECEIVED_RIGHTS, MD_FS_BUFFER_RECEIVED_DROP,
    MD_FS_BUFFER_SEND_PREPARE, MD_FS_BUFFER_SEND_COMMIT,
    MD_FS_BUFFER_IPC_CAPTURE_READY, MD_FS_BUFFER_IPC_CAPTURE_SENT,
    MD_FS_BUFFER_IPC_CAPTURE_OBSERVED, MD_FS_BUFFER_IPC_RECEIVE,
    MD_FS_BUFFER_IPC_IO_PREPARE, MD_FS_BUFFER_IPC_IO_COPY, MD_FS_BUFFER_IPC_IO_SELECT };
enum { MD_FS_BUFFER_SOURCE=-2 };
enum md_fs_buffer_transfer { MD_FS_BUFFER_NO_FD, MD_FS_BUFFER_ANCHOR, MD_FS_BUFFER_ADDFD, MD_FS_BUFFER_RIGHTS,
    MD_FS_BUFFER_TASK_PATH, MD_FS_BUFFER_CALLER_OPEN };
enum { MD_FS_BUFFER_EXPORT=2, MD_FS_BUFFER_IMPORT=3, MD_FS_BUFFER_CHANNEL_CHECK=4,
    MD_FS_BUFFER_IPC_ADMIT=5, MD_FS_BUFFER_RESULT_ADMIT=6 };
/* Stateful inputs are captured according to md_fs_operation_data_inputs. */
static inline int md_fs_buffer_operation(unsigned operation) {
    switch (operation) {
    case MD_FS_OPEN: case MD_FS_REOPEN:
    case MD_FS_CREATE: case MD_FS_TEMPORARY: case MD_FS_OPEN_IMAGE: case MD_FS_OPEN_OBJECT:
    case MD_FS_GETACL: case MD_FS_XATTR_OBJECT: case MD_FS_MOUNT_TABLE:
    case MD_FS_SETACL: case MD_FS_SOCKET_BIND: case MD_FS_IPC: case MD_FS_IPC_PEER:
    case MD_FS_WATCH_CREATE: case MD_FS_WATCH_ADD: case MD_FS_WATCH_REMOVE:
    case MD_FS_WATCH_BYTES: case MD_FS_WATCH_CONTAINS:
    case MD_FS_WATCH_READ: case MD_FS_SEEKDIR: case MD_FS_GETDENTS:
    case MD_FS_PATH: case MD_FS_READLINK: case MD_FS_REALPATH:
    case MD_FS_STAT: case MD_FS_FSTAT: case MD_FS_MKDIR: case MD_FS_MKNOD:
    case MD_FS_SYMLINK: case MD_FS_LINK: case MD_FS_UNLINK: case MD_FS_RENAME:
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_ACCESS: case MD_FS_UTIMENS:
    case MD_FS_GETCAP: case MD_FS_SETCAP: case MD_FS_REMOVECAP:
    case MD_FS_REMOVEACL: case MD_FS_OBJECT_ID:
    case MD_FS_SOCKET_ADDRESS: case MD_FS_SOCKET_NAME: case MD_FS_NATIVE_MOUNT:
    case MD_FS_CHROOT: case MD_FS_UMASK: case MD_FS_STATFS: case MD_FS_WATCH_PATH: case MD_FS_TASK_PATH:
    case MD_FS_XATTR: case MD_FS_FXATTR:
    case MD_FS_MOUNT: case MD_FS_FSOPEN: case MD_FS_FSCONFIG: case MD_FS_FSMOUNT: case MD_FS_BPF:
        return 1;
    default: return 0;
    }
}
struct md_fs_buffer_input {
    int base[2];
    unsigned flags, mode, capacity, value_size;
    uint64_t resolve;
    int64_t offset;
    struct md_fs_attributes attributes;
    size_t length[2];
    char object[2][33];
    char path[2][PATH_MAX];
    size_t capture_length[2];
    unsigned capture_flags[2];
    char capture_path[2][PATH_MAX];
};
struct md_fs_buffer_frame {
    union {
        struct md_fs_buffer_input input;
        struct md_fs_response reply;
        struct md_command_recipe command;
        struct { size_t size; char data[8192]; } snapshot;
    };
    unsigned transfer;
    struct { uint64_t request; unsigned mask; int number; } export;
    char source[96];
    struct { uint64_t token; int number; unsigned mapped; } receive;
    struct { unsigned count; int index[253]; } rights;
    struct { int number; struct md_fd_channel_observation observation; } channel;
    _Alignas(struct md_fd_receipt) unsigned char receipt[
        offsetof(struct md_fd_receipt,control)+CMSG_SPACE(MD_FD_RECEIPT_MAX*sizeof(int))];
    /* Faulted and copied only for explicit value operations, not ordinary IO. */
    union {
        unsigned char value[MD_FS_OUTPUT_MAX];
        struct md_received_message received_message;
    };
};
/* Bootstrap-only FD setup; ordinary calls exchange registers and mapped bytes. */
#ifndef MD_USE_LIBC
int md_fs_buffer_accepts(const struct md_fs_request *);
long md_fs_buffer_exec_prepare(const struct md_fs_request *, struct md_command_recipe *);
void md_fs_buffer_exec_cancel(void);
/* Producer copies into mapped bytes; only the completed file enters the guest. */
long md_fs_buffer_snapshot(unsigned flags, long (*produce)(void *, void *, size_t), void *);
long md_fs_buffer_proc_link(int process, void *out, size_t capacity);
long md_fs_buffer_call(const struct md_fs_request *, struct md_fs_response *,
        int (*deliver)(void *, const void *, size_t), void *context);
long md_fs_buffer_inspect(const int *, unsigned, struct md_received_message *);
long md_fs_buffer_publish(const int *, const unsigned char *, unsigned, void *, size_t, unsigned, int *, size_t *);
#endif
#endif
