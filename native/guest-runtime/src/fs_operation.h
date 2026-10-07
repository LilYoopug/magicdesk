#ifndef MD_FS_OPERATION_H
#define MD_FS_OPERATION_H
enum { MD_FS_SOCKET_PIN=1 };
#include <stddef.h>
#include <stdint.h>
#include "file_capability.h"
#include "file_open.h"
#include "fs_anchor.h"
#include "ipc_identity.h"

enum md_fs_operation {
    MD_FS_CREATE = 1, MD_FS_OPEN, MD_FS_MKDIR, MD_FS_SYMLINK, MD_FS_READLINK,
    MD_FS_LINK, MD_FS_UNLINK, MD_FS_RENAME, MD_FS_STAT, MD_FS_FSTAT, MD_FS_PATH,
    MD_FS_GETDENTS, MD_FS_SEEKDIR, MD_FS_SOCKET_BIND, MD_FS_SOCKET_ADDRESS, MD_FS_SOCKET_NAME,
    MD_FS_REALPATH, MD_FS_TEMPORARY, MD_FS_OBJECT_ID, MD_FS_OPEN_OBJECT, MD_FS_OPEN_IMAGE,
    MD_FS_WATCH_CREATE, MD_FS_WATCH_ADD, MD_FS_WATCH_REMOVE, MD_FS_WATCH_BYTES,
    MD_FS_WATCH_CONTAINS, MD_FS_WATCH_READ, MD_FS_REOPEN,
    MD_FS_CHMOD, MD_FS_CHOWN, MD_FS_ACCESS, MD_FS_UTIMENS, MD_FS_IPC,
    MD_FS_GETCAP, MD_FS_SETCAP, MD_FS_REMOVECAP,
    MD_FS_GETACL, MD_FS_SETACL, MD_FS_REMOVEACL, MD_FS_LISTATTR,
    MD_FS_XATTR_OPEN, MD_FS_MOUNT_TABLE, MD_FS_NATIVE_MOUNT, MD_FS_MKNOD,
    MD_FS_CHROOT, MD_FS_UMASK, MD_FS_STATFS, MD_FS_WATCH_PATH,
    MD_FS_TASK_PATH, MD_FS_XATTR, MD_FS_FXATTR, MD_FS_IPC_PEER, MD_FS_LAST = MD_FS_IPC_PEER
};
enum { MD_FS_VALUE_MAX=65536, MD_FS_OUTPUT_MAX=MD_IPC_IDENTITY_MAX };
enum md_fs_xattr { MD_FS_XATTR_GET=1, MD_FS_XATTR_SET, MD_FS_XATTR_LIST, MD_FS_XATTR_REMOVE };
static inline int md_fs_operation_value(unsigned operation) {
    return operation==MD_FS_XATTR || operation==MD_FS_FXATTR
        || operation==MD_FS_GETACL || operation==MD_FS_SETACL || operation==MD_FS_IPC_PEER;
}
enum { MD_FS_STAT_MOUNT = 1 };
enum { MD_FS_REOPEN_MUTABLE=1, MD_FS_REOPEN_NATIVE=2 };
enum md_fs_task_path { MD_FS_TASK_CHDIR=1, MD_FS_TASK_TRUNCATE, MD_FS_TASK_FCHDIR };
static inline int md_fs_operation_has_origin(unsigned operation) {
    return operation==MD_FS_OPEN || operation==MD_FS_CREATE || operation==MD_FS_REOPEN
        || operation==MD_FS_OPEN_OBJECT || operation==MD_FS_OPEN_IMAGE
        || operation==MD_FS_MOUNT_TABLE || operation==MD_FS_TASK_PATH;
}
/* A path anchor is sufficient only for object identity. These inputs consume
 * a real OFD (offset, socket, queue, or payload) and must never use its anchor. */
static inline unsigned md_fs_operation_data_inputs(unsigned operation) {
    switch (operation) {
    case MD_FS_SOCKET_BIND: case MD_FS_WATCH_PATH: return 2;
    case MD_FS_FXATTR: case MD_FS_IPC_PEER: return 1;
    case MD_FS_GETDENTS: case MD_FS_SEEKDIR:
    case MD_FS_WATCH_ADD: case MD_FS_WATCH_REMOVE: case MD_FS_WATCH_BYTES:
    case MD_FS_WATCH_CONTAINS: case MD_FS_WATCH_READ: return 1;
    case MD_FS_IPC: return 3;
    default: return 0;
    }
}
struct md_fs_attributes {
    uint32_t uid, gid;
    int64_t seconds[2], nanos[2];
    unsigned char capability[MD_FILE_CAPABILITY_MAX];
    uint32_t creation_mask;
};
struct md_fs_task_capture { const char *path; unsigned flags; };
/* Paths and descriptors are borrowed. Transports resolve AT_FDCWD to a captured
 * descriptor before entering the engine. Root is explicit (-1), never the
 * namespace owner's cwd. No guest pointers enter here. */
struct md_fs_request {
    int actor, peer;
    uint32_t operation, flags, mode;
    int directory[2];
    /* Optional store-local object operand, mutually exclusive with a descriptor.
     * The filesystem owner opens/releases it; no temporary guest FD is needed. */
    const char *object[2];
    /* Adapter-only kernel path selection, captured in a private task table.
     * Transports resolve it before worker execution; never an OFD substitute. */
    struct md_fs_task_capture capture[2];
    /* Optional trusted provenance for the already captured base descriptors.
     * RPC peers cannot supply pointers or claim another task's mount view. */
    const struct md_fs_anchor *origin[2];
    const char *path[2];
    /* Transports capture these bytes before worker admission, never a guest pointer. */
    const void *value;
    uint32_t value_size;
    uint32_t capacity;
    uint64_t resolve;
    int64_t offset;
    struct md_fs_attributes attributes;
};
/* Validated, adapter-owned strings; descriptor capture remains transport-owned. */
int md_fs_request_validate(const struct md_fs_request *);
static inline int md_fs_object_id_valid(const char *id) {
    if (!id) return 0;
    for (unsigned i=0;i<32;++i)
        if (!((id[i]>='0' && id[i]<='9') || (id[i]>='a' && id[i]<='f'))) return 0;
    return !id[32];
}
struct md_fs_info {
    uint64_t device, inode, links, rdev, mount_id;
    int64_t size, blocks;
    uint32_t mode, uid, gid, block_size;
    int64_t access_seconds, modify_seconds, change_seconds;
    uint32_t access_nanos, modify_nanos, change_nanos, reserved;
};
/* Linux ARM64 statfs output. libc field names differ; the syscall ABI does not. */
struct md_fs_statfs {
    uint64_t type, block_size, blocks, free_blocks, available_blocks, files, free_files;
    int32_t fsid[2];
    uint64_t name_length, fragment_size, flags, spare[4];
};
_Static_assert(sizeof(struct md_fs_statfs)==120,"ARM64 statfs layout");
struct md_fs_result {
    int error, fd;
    unsigned host_path;
    struct md_open_completion open_completion;
    size_t size;
    int64_t position;
    struct md_fs_info info;
};
/* Caller-owned output, independent of wire framing. Directory delivery runs
 * synchronously after the read transaction and before advancing the cursor.
 * A failed publication is not permission to replay an operation. */
struct md_fs_output {
    void *data;
    size_t capacity;
    /* Watch delivery may cross event loops. The transport must complete the
     * reservation on the filesystem worker after copying or cancellation. */
    int reserve_watch;
    /* The caller holds the exact directory OFD turn until copy acknowledgement.
     * Preparing bytes does not advance the cursor; commit is an explicit seek. */
    int64_t *directory_position;
    int (*deliver)(void *, const void *, size_t);
    void *context;
    /* Optional owned path anchor from a successful file open/reopen. No origin
     * allocation occurs when omitted; caller releases a returned anchor. */
    struct md_fs_anchor **origin;
};
#endif
