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
Creation-time ancillary-format selection uses the existing IPC metadata gate,
SQLite transaction and cookie binding. It adds no kernel primitive or probe;
ordinary read/write remain kernel-owned.

Shared mount policy uses memfd size seals plus `F_SEAL_FUTURE_WRITE`, present in
the [Linux 5.15 seal ABI](https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/fcntl.h#L29-L41),
and lock-free ARM64 shared-memory flag loads/stores. Publication is lazy and
explicit: unavailable memfd/sealing returns an error while retaining local
policy. It adds no shared-startup requirement and never substitutes a stale copy
for the requested live policy. `--case mount-policy` checks rejected memfd,
mapping and sealing operations, including a native seccomp-injected seal denial.
Portable attachment graphs use the same baseline memfd interface with immutable
`F_SEAL_WRITE` manifests, O_PATH directory rights and CLOEXEC duplication. They
add no newer-kernel requirement or startup probe. Graph publication/import fails
explicitly if those operations are unavailable; no pathname-reopening fallback
substitutes for retained directory identity.
Portable backing custody uses the same sealed-manifest primitive and transfers
existing root/lower directory descriptions through SCM_RIGHTS. CLOEXEC duplication
and queued rights preserve their existing flock leases; import never relocks
them. These semantics fit the 5.15 baseline and add no startup requirement.
`--case inode-custody` covers malformed/partial imports, allocation/FD exhaustion,
sender exit, receiver death, queued-right discard, exclusive-lock preservation
and bounded transfer of all 512 rights. Native FD/in-flight quotas remain errors.
Message-origin parcels compose these same descriptors and seals with the existing
message-route contract. Per-worker graph interning and FD-table publication add
no kernel primitive. `--case origin-transfer` checks mixed/copy/alias views,
route/store rejection, allocation rollback, exact descriptor balance and queued
transfer after an independent exec sender exits.
Self-contained `ipc_capsule` custody uses those same baseline primitives plus
SO_COOKIE, getrandom, flock and renameat. Its HMAC is userspace Mbed TLS, not a
kernel crypto API. Single-packet queue trees use MSG_PEEK without SO_PEEK_OFF;
native descriptor, in-flight and Unix graph-depth limits remain errors.
`--case origin-transfer` covers independent sender exit, fresh receiving owner,
repeated/concurrent peeks, authentication rejection, partial FD limits and final
queue/epoch/backing release. It adds no post-5.15 dependency.

The `ipc_origins` service uses the same capsule primitives and existing eventfd
worker queue. It adds no kernel interface, private listener or live-source RPC.
`--case ipc-origins` covers exact captured sockets after slot reuse, worker
cancellation/join, bounded admission, allocation/in-flight quota failures,
source exit before receiver creation and receiver exit with untaken custody.
Actual data capture uses baseline `recvmsg(MSG_PEEK | MSG_CMSG_CLOEXEC)`
and `fstat` through the shared bounded ancillary parser; incomplete custody
never becomes success.

Captured-send helpers use existing atomic ADDFD_SEND (Linux 5.14) only for their
private import channel and application socket. The same bounded SCM_RIGHTS
queue imports 0..253 rights, including O_PATH, which ADDFD rejects with EBADF.
Closing the import channel before socket admission preserves the 254-slot bound
for 253 outgoing rights. No pidfd-getfd or post-5.15 primitive is needed.
`--case fd-observation` covers protected/full callers, zero/one helper slot,
exact/partial import capacity, receive/close/send filters, SIGPIPE, clone
rejection and cancellation before/after import and native send.
The native control-memory fault check confirms MSG_CTRUNC rather than EFAULT;
incomplete private import fails before send and reaping closes the imported prefix.
The outgoing guest sender composes these helpers with worker preparation
and the same mapped-buffer controls. `--case ipc-ancillary` checks actual guest
sendmsg/sendmmsg/sendto, explicit credentials, mixed headers, captured pathname
anchors, binary abstract addresses, protected/full tables, 253 rights, source exit
before import, blocked-send cancellation and shared-table slot replacement. It adds no
kernel interface or capability requirement beyond the existing helper path.
Native anchors use O_PATH, SCM_RIGHTS and task-local proc FD aliases; they require
one extra private slot, never an extra application right. The import channel
occupies the original application socket number so final ADDFD_SETFD preserves
FD-specific filters without overwriting imported rights. A shell SELinux policy
may forbid fixture socket-file creation; retained native-path rejection and
cleanup are checked separately from successful virtual/abstract delivery.
The optional `--native-anchor` helper fixture verifies successful native-path
delivery under the Termux app UID, including protected callers and 253 O_PATH/mixed
rights; it does not bypass the production executor or prove shell permission.
Imported origin custody and annotated-vector return reuse the existing shared
kernel receipt, SCM_RIGHTS and destination-table ordering. They require no new
syscall, flag or startup capability. Protected terminal-receiver, truncation and
peek checks run in `--case ipc-origins`; `--case ipc-ancillary` exercises the
native application-control-memory publication with the actual guest adapter,
including imported capsule origins. Message expansion adds no kernel primitive.
Capsule queues count against native per-UID in-flight rights; an export helper
with a reduced RLIMIT_NOFILE can fail with ETOOMANYREFS despite free slots.
The actual guest checks keep this explicit, without raising limits or replay.
`fd_table_observation` uses task-captured proc-FD directory iteration, `lseek`,
`getdents64` and the existing `PTRACE_EVENT_EXIT` stop. It observes the table before
`exit_files`, not after reaping. These interfaces and ordering are present in
5.15 ([proc iteration](https://github.com/torvalds/linux/blob/v5.15/fs/proc/fd.c),
[exit ordering](https://github.com/torvalds/linux/blob/v5.15/kernel/exit.c)).
Denied capture/iteration remains an explicit guest-operation failure, not an
empty receipt or a shared-service prerequisite. `--case fd-observation` covers
the device policy, production private-table capture and cancellation, partial
control faults, protected/shared-table receivers, quotas and fatal exit. The
typed capture request reuses the same helper lifecycle, clone flags, private
channel and atomic ADDFD_SEND; it adds no kernel primitive or startup probe.
This is an alternative observation fixture, not the guest annotated-return path.
Production annotated return uses the existing mapped kernel receipt and
SCM_RIGHTS, including O_PATH, without proc-table capture or ADDFD_SETFD. Filtered
input capture reuses table-owned channels and atomic ADDFD_SEND only for channel
admission. The exact gettid notification gate still evaluates application
filters. None of these operations adds a post-5.15 dependency.
Filtered socket waits use ppoll, epoll and the existing ptrace signal-mask and
syscall-register interfaces. Native WAITALL/batch jobs use pthreads, eventfd and
a supervisor-local signal with an ARM64 syscall-entry cancellation gate. These
are baseline interfaces; no newer pidfd, io_uring or kernel page-fault mediation
is required. `--case ipc-ancillary` compares signal restart, socket timeouts,
SIGPIPE, Unix/TCP peeks, large messages and batch completion under UID 2000.
Explicit source-vector export uses the same private-table clone, close_range,
atomic ADDFD_SEND and authenticated SCM_RIGHTS channel, without pidfd_getfd or
new proc operations. Its 254-input bound allows a socket plus 253 data rights;
export splits into existing 253-right packets. `--case fd-observation` checks
protected callers, source-table replacement, quotas, filter denial and partial
export cancellation. It adds no post-5.15 requirement or startup probe.

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
