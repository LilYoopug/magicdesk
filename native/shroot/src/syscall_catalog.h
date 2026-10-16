#ifndef MD_SYSCALL_CATALOG_H
#define MD_SYSCALL_CATALOG_H
/* Shared by kernel interception, cooperative routing and task dispatch. */
#define MD_FILE_CALLS(X) \
    X(pipe2) X(openat) X(openat2) X(newfstatat) X(statx) X(faccessat) X(faccessat2) X(fstat) X(getdents64) X(lseek) \
    X(fsync) X(fdatasync) X(syncfs) \
    X(mkdirat) X(unlinkat) X(symlinkat) X(renameat) X(renameat2) X(linkat) \
    X(chdir) X(fchdir) X(getcwd) X(readlinkat) X(fchmodat) X(fchmodat2) X(fchownat) X(utimensat) \
    X(truncate) X(statfs) X(fstatfs) X(mknodat) X(inotify_add_watch) X(mount) X(umount2) X(pivot_root) \
    X(fsopen) X(fsconfig) X(fsmount) X(open_tree) X(move_mount) X(mount_setattr) X(bpf) \
    X(landlock_create_ruleset) X(landlock_add_rule) X(landlock_restrict_self) \
    X(setxattr) X(lsetxattr) X(getxattr) X(lgetxattr) X(listxattr) X(llistxattr) \
    X(removexattr) X(lremovexattr) X(fsetxattr) X(fremovexattr) X(fgetxattr) X(flistxattr) X(fchmod) X(fchown)
#define MD_SOCKET_CALLS(X) X(bind) X(connect) X(sendto) X(sendmsg) X(sendmmsg) \
    X(getsockname) X(getpeername) X(accept) X(accept4) X(recvfrom) X(recvmsg) \
    X(listen) X(socketpair) X(getsockopt)
#define MD_ENTRY_WORKER_CALLS(X) \
    X(newfstatat) X(fstat) X(statx) X(getdents64) X(readlinkat) \
    X(mkdirat) X(unlinkat) X(renameat) X(renameat2) X(linkat) X(symlinkat) \
    X(faccessat) X(faccessat2) X(fchmodat) X(fchmodat2) X(fchownat)
#endif
