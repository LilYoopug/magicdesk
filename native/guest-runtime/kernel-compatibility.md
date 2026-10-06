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

Private launch rendezvous reuses the registry's flags-zero pidfd, proc-descriptor
identity and file locks, plus Unix seqpacket/SO_PEERCRED and nonblocking IO. It
adds no newer-kernel primitive or shared-startup requirement. Discovery failure
does not grant an alternative identity or enable application FD framing.
Candidate message routing uses a fixed header, `SO_COOKIE`, descriptor-free
`recvmsg(MSG_PEEK | MSG_DONTWAIT)` and a `getrandom` nonce. Scope retention shares
existing flock leases. These operations also fit the baseline; no new pidfd
flags, socket diagnostics or per-IO capability probe is required.

## Newer Interfaces

Every owned dependency newer than 5.15 belongs here, including optional
optimizations and experimental fixtures. Guest programs' unadapted syscalls
retain native errors; arbitrary new guest syscalls are not runtime requirements.

| Interface | First upstream kernel | Owner and purpose | Behavior without it |
| --- | --- | --- | --- |
| `PIDFD_THREAD` | 6.9 | `task_descriptor.c` owns descriptor capture; `task_lifetime.c` owns exact-thread liveness for restricted proc roots. | Try flags zero for the same task. A non-leader rejected with EINVAL is reported as ENOTSUP and uses task-affine SCM_RIGHTS export. Liveness retains `/proc/<tid>/stat` instead: a flags-zero pidfd observes group death, not exact-thread death. Never substitute the leader's file table. |
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

The launch probe covers pidfds, subreaper, faccessat2, executable mappings,
ptrace, seccomp notification dispatch and atomic ADDFD through the production
mapped-buffer installation. It acquires a mapped lease and completes a production
private-table helper: clone, inherited-FD removal, channel publication, exact-task
proc capture, descriptor export and full helper reaping. Only then does the probe
release its lease and report readiness. These guest-only checks do not initialize
the filesystem worker or affect independent shell services.

`test_resources.py --case kernel-baseline` masks PIDFD_THREAD with EINVAL and
executes the resource model plus production private-thread proc capture and
mapped descriptor/data/import workflows. Exact-task handle cases include
ordinary/nondumpable tasks, independent non-leader file tables, retained handle
copies and dead-task observation after reaping. The resource model checks
restricted proc roots belonging to live non-leaders and copies of those roots.
Fallback proc handles are opened once and inspected on demand, not periodically.

The same suite injects missing pidfd, faccessat2, seccomp, close_range, private
clone and ADDFD operations. ADDFD also covers EINVAL and EACCES. Each rejected
guest probe must leave an independent shell usable. Probe success alone is not
certification of the full execution path.

`test_resources.py --case pidfd-table` is a separate 6.9+ feasibility check,
not part of the baseline suite or production adapter. Sixteen cases cover
same-group private-table getfd with ordinary/nondumpable tasks, zero to three
available result slots, shared file offset, O_PATH, helper filter death and
pipe EOF. Its fixture-owned pidfd consumes an infrastructure slot. This does
not establish descriptor publication, interruption or cancellation semantics
for production ancillary IO.

The audit covers owned runtime syscall dispatch, raw/assembly calls, pidfd and
ptrace flags, seccomp ioctls, proc observation and metadata operations. Recognizing
a guest syscall is not the same as requiring the host implementation: worker-owned
chmod handles logical objects and native attachments without fchmodat2, whereas
direct passthrough preserves the host error. It does not certify arbitrary guest
libraries or replace execution on a real 5.15 device.

`test_resources.py --case fd-messages` includes an optional exact Unix-socket
diagnostic probe. The request and inode/cookie validation are already present in
[Linux 5.15](https://github.com/torvalds/linux/blob/v5.15/net/unix/diag.c#L243-L305),
but the tested shell policy returns EACCES. This probe is not a runtime dependency;
denial remains unknown liveness, never permission to discard provenance. The
separate queued-pipe lifetime candidate uses baseline pipe/socket and poll/epoll
operations and does not depend on socket diagnostics.
