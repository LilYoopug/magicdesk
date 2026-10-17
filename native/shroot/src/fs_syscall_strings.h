#ifndef MD_FS_SYSCALL_STRINGS_H
#define MD_FS_SYSCALL_STRINGS_H
#include <sys/syscall.h>

/* Two three-bit argument selectors: zero is absent, 1..6 name args[0..5].
 * This describes strings only; the executor still validates the whole call. */
static inline unsigned md_fs_syscall_strings(long number) {
    switch (number) {
    case SYS_openat: case SYS_openat2: case SYS_unlinkat: case SYS_mkdirat:
    case SYS_newfstatat: case SYS_statx: case SYS_readlinkat:
    case SYS_faccessat: case SYS_faccessat2:
    case SYS_fchmodat: case SYS_fchmodat2: case SYS_fchownat: case SYS_utimensat:
        return 2;
    case SYS_renameat: case SYS_renameat2: case SYS_linkat: return 2|(4<<3);
    case SYS_symlinkat: return 3|(1<<3);
    case SYS_statfs: case SYS_fsopen: case SYS_listxattr: case SYS_llistxattr: return 1;
    case SYS_getxattr: case SYS_lgetxattr: case SYS_setxattr: case SYS_lsetxattr:
    case SYS_removexattr: case SYS_lremovexattr: return 1|(2<<3);
    case SYS_fgetxattr: case SYS_fsetxattr: case SYS_fremovexattr: return 2<<3;
    default: return 0;
    }
}
#endif
