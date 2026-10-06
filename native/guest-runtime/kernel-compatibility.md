# Kernel Compatibility

## Baseline

Shroot's minimum supported kernel is **Linux 5.15**. This is a design/support
boundary, not a claim of complete device coverage. The MagicDesk APK remains
Android 14 / API 34 and managed Desktop remains Android 15 / API 35; neither
acquires Shroot's kernel requirements. Shell tools, Termux, prepared chroot and
graphics services remain independent when guest execution is unavailable.

Admission uses actual operations under the selected executor identity, not an
Android-version inference or `uname`-only capability check. Kernel configuration,
SELinux, application filters and vendor backports affect availability. Headers
merely allow compiling an operation; they do not make it available at runtime.

The baseline includes pidfds, selective ptrace, seccomp notifications,
`openat2`, `faccessat2`, `close_range` and shared/sealed memfds. In particular,
atomic `SECCOMP_ADDFD_FLAG_SEND` is a required FD-publication primitive, available
since Linux 5.14. Separate ADDFD and reply calls are not an equivalent fallback:
cancellation between them can leave an installed descriptor without a confirmed
result. `CLOSE_RANGE_CLOEXEC` is available since 5.11. Both fit the 5.15 baseline.
See the [seccomp notification contract](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
and [close_range flags](https://man7.org/linux/man-pages/man2/close_range.2.html).

## Newer Interfaces

Every owned dependency newer than 5.15 belongs here, including optional
optimizations and experimental fixtures. Guest programs' unadapted syscalls
retain native errors; arbitrary new guest syscalls are not runtime requirements.

| Interface | First upstream kernel | Owner and purpose | Behavior without it |
| --- | --- | --- | --- |
| `PIDFD_THREAD` | 6.9 | `task_descriptor.c`, supervisor metadata capture and `guest_domain.c`: refer to the exact task, not a substituted group leader. | Try a flags-zero pidfd for that same numeric task. Non-leader tasks can be unavailable; task-affine SCM_RIGHTS is the descriptor-export alternative. Do not redirect to the leader's potentially different file table. Mapped-input fallback still needs the non-leader EINVAL case covered; see validation limits below. |
| `SECCOMP_IOCTL_NOTIF_SET_FLAGS` / `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` | 6.6 | `namespace_broker.c`: optional notification scheduling hint. | Failed ioctl leaves normal notification wakeups enabled; no permission or affinity change. |
| `fchmodat2` | 6.5; `AT_EMPTY_PATH` in 6.6 | `namespace.c` translates store metadata through the worker. `file_calls.c` also has a native direct-backend path. | Logical store metadata does not require this host syscall. Native passthrough retains ENOSYS/flag errors; no fake success or unconditional startup requirement. |
| `STATX_MNT_ID_UNIQUE` | 6.8 | `namespace_proc.c`: distinguishes globally unique mount IDs from the runtime's ordinary mount-ID namespace. | The adapter strips the UNIQUE request and asks for `STATX_MNT_ID` (5.8); returned masks do not claim UNIQUE support. |
| `PROCMAP_QUERY` | 6.11 | `test_mapping_task.c`: optional binary mapping-observation experiment. | Production `mapping_observation.c` reads a retained maps file. The fixture records unavailable ioctl access separately and verifies the text path. |
| `MFD_EXEC` | 6.3 | `test_exec_policy.c`: explicit executable-memfd policy experiment. | This experiment reports failure; production image admission does not require this flag. |
| `AT_EXECVE_CHECK` | 6.14 | Execution-policy boundary, not an enabled host dependency. | The adapter rejects unsupported execveat flags rather than treating an X_OK check as equivalent. |

Version references: [pidfd_open flags](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[Linux 6.6 seccomp ABI](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/seccomp.h),
[chmod flags](https://man7.org/linux/man-pages/man2/chmod.2.html),
[statx masks](https://man7.org/linux/man-pages/man2/statx.2.html),
[Linux 6.11 proc API](https://www.kernel.org/doc/html/v6.11/filesystems/proc.html),
[Linux 6.3 memfd ABI](https://github.com/torvalds/linux/blob/v6.3/include/uapi/linux/memfd.h),
and [Linux 6.14 exec flags](https://github.com/torvalds/linux/blob/v6.14/include/uapi/linux/fcntl.h).

## Validation Limits

Device coverage is actual UID 2000 on RM11/NX809J, Linux 6.12.23, API 36,
4 KiB pages. A real 5.15 kernel, API 34 and 16 KiB pages remain unverified.
Missing-operation injection on a newer kernel tests explicit failure/fallback,
not the scheduling, ABI or security policy of an older kernel.

The launch probe currently covers pidfds, subreaper, faccessat2, executable
mappings, ptrace and seccomp notification dispatch. It does not yet exercise
atomic ADDFD or private-helper teardown; those have separate resource fixtures.
Probe success alone is not certification of the full execution path.

`test_resources.py --case pidfd-table` is a separate 6.9+ feasibility check,
not part of the baseline suite or production adapter. Sixteen cases cover
same-group private-table getfd with ordinary/nondumpable tasks, zero to three
available result slots, shared file offset, O_PATH, helper filter death and
pipe EOF. Its fixture-owned pidfd consumes an infrastructure slot. This does
not establish descriptor publication, interruption or cancellation semantics
for production ancillary IO.

The mapped-input path currently falls back on EPERM/EACCES/ENOSYS but not
EINVAL from a non-leader pidfd on an older kernel. That is a compatibility gap,
not permission to raise the minimum to 6.9. Restricted proc-root ownership also
needs non-leader coverage without thread pidfds. Track corrective work in the
local backlog and retain the exact source-table identity throughout fallback.

The audit covers owned runtime syscall dispatch, raw/assembly calls, pidfd and
ptrace flags, seccomp ioctls, proc observation and metadata operations. Recognizing
a guest syscall is not the same as requiring the host implementation: worker-owned
chmod handles logical objects and native attachments without fchmodat2, whereas
direct passthrough preserves the host error. It does not certify arbitrary guest
libraries or replace execution on a real 5.15 device.
