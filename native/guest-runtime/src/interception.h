#ifndef MD_INTERCEPTION_H
#define MD_INTERCEPTION_H
#include <stdint.h>

#define MD_INTERCEPTION_MAGIC UINT64_C(0x4d44494e54455231)
#define MD_GUEST_MAP_IMAGE 0x4d440101
enum { MD_IMAGE_PROGRAM=0, MD_IMAGE_LOADER=1, MD_IMAGE_TAKE_PROGRAM=2, MD_IMAGE_TAKE_LOADER=3 };
#define MD_GUEST_ENTER_IMAGE 0x4d440102
#define MD_GUEST_FD_FILTER 0x4d440103
#define MD_GUEST_SHM 0x4d440104
#define MD_GUEST_SHM_FILTER 0x4d440105
#define MD_GUEST_PROC_IMAGE 0x4d440106
#define MD_GUEST_IPC 0x4d440107
#define MD_GUEST_BUFFER 0x4d440108
#define MD_GUEST_FD_CHANNEL 0x4d440109
#define MD_GUEST_TASK_HELPER 0x4d44010a
#define MD_GUEST_PROC_FILE 0x4d44010b
#define MD_GUEST_PID_FILTER 0x4d44010c
#define MD_GUEST_PID_SIGNAL_GROUP 0x4d44010d
#define MD_GUEST_PIDFD_SIGNAL 0x4d44010e
enum md_export_control { MD_EXPORT_BEGIN=1, MD_EXPORT_READY, MD_EXPORT_OBSERVED };
#define MD_EXPORT_ADMIT (-4096L)
/* Register-only control works before/inside a mapped filesystem request too. */
struct md_export_reply { long endpoint; uint64_t token; };
#define MD_WATCH_TASK_AFFINE (-INT64_C(0x4000000000000000))
#define MD_WATCH_WAIT (MD_WATCH_TASK_AFFINE + 1)
#define MD_WATCH_NATIVE (MD_WATCH_TASK_AFFINE + 2)
#define MD_IPC_WAIT (MD_WATCH_TASK_AFFINE + 3)

enum md_interception_kind {
    MD_INTERCEPT_DISPATCH = 41,
    MD_INTERCEPT_EXEC = 42,
    MD_INTERCEPT_OBSERVE = 43,
    MD_INTERCEPT_NATIVE = 44,
    MD_INTERCEPT_IDENTITY = 45,
    MD_INTERCEPT_WATCH = 46,
    MD_INTERCEPT_MEMORY = 47,
    MD_INTERCEPT_FD = 48,
    MD_INTERCEPT_CWD = 49,
    MD_INTERCEPT_CAPTURE = 50,
    MD_INTERCEPT_TASK = 51,
    MD_INTERCEPT_PROC = 52,
    MD_INTERCEPT_PROCESS = 53
};

/* Bootstrap-owned entry points, published before entering guest code. The
 * supervisor reads this descriptor at each image handshake, not linker symbols. */
struct md_interception_abi {
    uint64_t magic, size;
    uintptr_t ready, done, allocate, allocated, dispatch, export_fd, exported;
    uintptr_t export_control, store, stored, load_byte, loaded_byte;
    uintptr_t proc_open, proc_open_path;
    uintptr_t store_ids, stored_ids, raw_gate, copy_begin, copy_end;
    uintptr_t watch_gate;
    uintptr_t load_groups, loaded_groups, store_groups, stored_groups;
    uintptr_t enter;
    uintptr_t ipc_wait;
    uintptr_t fd_control;
    uintptr_t capture_gate;
    uintptr_t buffer_control;
    uintptr_t task_control, task_call, task_return, task_abort;
    uintptr_t task_collect, task_collected;
    uintptr_t buffer_admit;
};
long md_guest_buffer_admit(unsigned purpose);

int md_interception_install(int inherited);
long md_shm_dispatch(long, const unsigned long *);
long md_ipc_dispatch(long, const unsigned long *);
long md_pid_filter_install(void);
int md_interception_map_image(int fd, int loader);
int md_interception_enter_image(void *aux, unsigned count);
#endif
