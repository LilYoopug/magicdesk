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

Guest Landlock filesystem ABI 1 is implemented by `landlock_policy`, the task
resource owners and the filesystem worker; it does not require the host's
`CONFIG_SECURITY_LANDLOCK` or become a shared-startup prerequisite. Its syscall
numbers and filesystem rights predate the 5.15 baseline. Newer ABI rights are
rejected, not advertised as enforced. Native host queries retain the kernel's
own result. `landlock_guest` and `test_arch_runtime.py` distinguish that query
from actual guest permission checks. The same ABI 1 assertions run under UID
1000 in a reference Linux 6.18 QEMU VM; that reference does not raise Shroot's
minimum. See [filesystem restrictions](../../docs/shroot.md#filesystem-restrictions)
for provider limits and the difference from native security confinement.

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
Native `/proc/self/mountinfo` snapshots use its baseline namespace-generation
`poll(POLLPRI)` notification, with a zero timeout for observation, not a wait.
The namespace owner retains the source descriptor and invalidates cached native
entries on change or observation failure. Changes during construction prevent
reuse; guest mounts and namespace-relative IDs are generated per request.
`test_native_mounts` covers reuse, invalidation, interrupted/failed observation,
changes during reading and descriptor release, plus a real kernel-source read.
It is included in `test_resources.py --case stores`; no newer kernel primitive
or startup probe is required.
Portable attachment graphs use the same baseline memfd interface with immutable
`F_SEAL_WRITE` manifests, O_PATH directory rights and CLOEXEC duplication. They
add no newer-kernel requirement or startup probe. Graph publication/import fails
explicitly if those operations are unavailable; no pathname-reopening fallback
substitutes for retained directory identity.
Live graph publication adds nonblocking Unix seqpacket queues and the existing
bounded SCM_RIGHTS bundles. Mounted-origin lifetime uses one `O_TMPFILE` carrier
per exported graph and independent `F_OFD_SETLK` byte-range leases, all available
within the 5.15 baseline. Retirement and normal unmount acquire exclusive leases
without waiting; imported origins refresh their generation under a shared lease.
These operations run only on explicit graph publication/transfer or mount changes.
Failure does not change the selected identity or require them for other services.
Base-root relocation uses that same userspace graph, O_PATH custody and origin
leases. Guest pivot_root does not issue a privileged host mount/pivot syscall or
add a kernel capability requirement.
Guest UTS and SysV IPC namespaces also use supervisor-owned resources, not host
namespace privileges. Their clone/unshare adapters remove only the implemented
namespace flags before the ordinary kernel transition and commit on its exact
success event. UTS argument copies reuse the mapped-buffer transport; IPC uses
the existing store locks, getrandom identities and owner leases. These add no
post-5.15 dependency. Guest CLONE_NEWUSER and typed proc map writes follow the
5.15 UID/GID mapping and CAP_SETFCAP rules without requiring host CONFIG_USER_NS.
UTS sysctl files use the same lazy descriptor-selector mechanism as map files.
Offline IPv4 sysctls use the shared typed-control transport and retained mount
anchors; numeric values and permissions are launch-owned state, not host sysctl
writes. They add no post-5.15 interface. Foreign proc executable selection reuses
the existing process-image inspection, worker preparation and anonymous-image
custody; it does not add a kernel exec or proc-FD capability requirement.
Local typed SCM_RIGHTS custody adds a pipe EOF to the existing worker event loop;
it needs no newer kernel API, polling loop or additional worker thread.
Guest PID namespaces likewise use retained userspace identities, not native
CLONE_NEWPID authority. `pid_namespace` and the supervisor use baseline clone,
wait4/waitid, flags-zero pidfd_open/pidfd_send_signal, ptrace birth/exec/exit
events and PR_SET_CHILD_SUBREAPER (since 3.4) for PID 1 orphan adoption. A denied
subreaper admission fails that child namespace explicitly. Signal disposition
observation reads native proc status on demand. Logical proc mounts reuse
O_PATH/native directory cookies and typed snapshots; their creation does not
issue a host mount. No PIDFD_THREAD, PIDFD_SIGNAL_THREAD or newer pidfd ioctl is
required. `--case mount-namespace`, stock Bubblewrap/GDB and Chromium's automatic
user/PID route cover these paths under actual UID 2000; the APK's other services
do not acquire these prerequisites.
Shared clone-TID publication uses the existing ptrace birth stop and task-affine
memory adapter. Proc-root capture and live fdinfo use retained O_PATH/proc
descriptions and that same private-table helper. None adds a post-5.15 runtime
requirement; `test_thread_identity_runtime.py` and `test_proc_root_runtime.py`
cover ordinary/protected tasks, PID namespaces and debugger ownership.
Noexec mapping policy uses the existing seccomp/ptrace observation and
CLONE_VM ownership, not MFD_NOEXEC_SEAL or a host mount. MREMAP_DONTUNMAP is
within the baseline (5.7 for anonymous private mappings, 5.13 for additional
mapping types); rejected native mappings keep their kernel errors.
Focused tests cover execution admission, mmap/mprotect, remap, fork and failed
metadata allocation. This adds no requirement for newer memfd execution flags.
Private-memory preparation uses retained smaps/mem/pagemap descriptions, ordinary
private file mappings and pagemap's present/swap/file/soft-dirty bits, all within 5.15.
Candidate admission reads bit 55 from its untouched mapping: both populated and
absent entries include the VMA's soft-dirty flag, as implemented in
[Linux 5.15 pagemap](https://github.com/torvalds/linux/blob/v5.15/fs/proc/task_mmu.c).
This avoids a second smaps walk without requiring PROCMAP_QUERY or soft-dirty
tracking to be enabled. An unreadable entry remains a preparation failure.
It neither reads PFNs nor requires CAP_SYS_ADMIN. Proc access is captured before
nondumpable state and cannot be reused for a forked address space. Missing
access, unknown VMA flags and unsupported mapping types fail preparation without
replacing the original mapping. The kernel retains COW, truncation and DONTNEED
semantics. `test_resources.py --case private-memory` covers the memory owner and
native/guest preparation under UID 2000, including retained access after
PR_SET_DUMPABLE=0, supervisor source capture, exact child-mm ownership and partial
proc-capture FD exhaustion. Direct source capture uses the existing task-descriptor
adapter, falling back to the existing private-table SCM_RIGHTS capture. Denied
capture leaves native mmap intact without reopening a source by pathname or
changing dumpability. The namespace
worker's acknowledged pause uses existing eventfds and pthread synchronization,
with no newer kernel dependency. The replacement transaction uses baseline mmap/munmap and
fixed mremap, retaining the original VMA separately through commit or rollback.
A failed fixed move does not prove that its destination remains mapped; see
[Linux 5.15 mremap](https://github.com/torvalds/linux/blob/v5.15/mm/mremap.c).
Focused checks cover cancellation, destructive-destination failures, failed
restoration/cleanup and lost syscall observation. Automatic repair additionally
uses baseline PTRACE_INTERRUPT, wait4 and original CONT/SYSCALL/SINGLESTEP
continuations to quiesce launch-owned writers. Existing group stops stay stopped;
real events and rusage return to the normal dispatcher. Pending syscall/debugger
interrupts retain their original event owner across nested barriers. The helper and worker
barriers add no post-5.15 dependency. A `vfork` parent remains kernel-blocked
until the baseline PTRACE_EVENT_VFORK_DONE stop; child exit/exec and concurrent
JIT compilation exercise this ordering without waiting for another interrupt.
Concurrent ordinary/protected JIT writers
with namespace IO and stock SteamOS Plasma QML exercise the integrated path.
The opt-in `test_jit_memory.c` experiment uses ordinary mmap/mprotect,
`MREMAP_FIXED`, memfds and fork; these fit the baseline. Its optional
userfaultfd probe separately tests full kernel-fault handling and
`UFFD_USER_MODE_ONLY` (since 5.11), without requiring either for production
Shroot or the private-view prototype. Available user-mode faults do not imply
permission to service kernel accesses to missing pages. The experiment does not
use newer userfaultfd move/poison ioctls or change SELinux/sysctl policy.
Anonymous ELF custody uses baseline `F_GET_SEALS`, CLOEXEC duplication, pread
and backed mappings. It does not require `MFD_EXEC` or `MFD_NOEXEC_SEAL`.
`test_anonymous_exec.py` checks ordinary/sealed images and process-image lifetime;
firmware execution-policy rejection remains an error, not an implicit elevation.
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
O_PATH capture can retain the stopped private helper's object through
`/proc/<tid>/fd/<n>` with O_PATH, available in 5.15. Restricted proc access falls
back to SCM_RIGHTS; nofollow and stateful descriptions retain exact transfer.
`--case fd-observation` checks regular/directory/nofollow objects, protected
callers, filters, full tables, cancellation, name replacement and `/dev/full`
custody. `test_device_bind.py` checks device binding separately from the native
data-access denial. No post-5.15 primitive or privilege change is required.
This is an alternative observation fixture, not the guest annotated-return path.
Production annotated return uses the existing mapped kernel receipt and
SCM_RIGHTS, including O_PATH, without proc-table capture or ADDFD_SETFD. Filtered
input capture reuses table-owned channels and atomic ADDFD_SEND only for channel
admission. The exact gettid notification gate still evaluates application
filters. Mapped export-channel admission, direct ADDFD results and private-helper
admissions use the same gettid mechanism rather than depending on application
prctl policy. A protected PID-namespace fixture denies prctl and verifies cold
metadata export, a returned mount-table FD and bidirectional native-peer
credentials. Unix PID snapshots use the existing logical process identities and
SCM transport; no kernel PID namespace or newer credential API is required.
None of these operations adds a post-5.15 dependency.
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

Offline network namespaces, private devpts views and permissive cgroups require
no post-5.15 interface or host namespace/cgroup privilege. Their owners use the
existing resource transactions, socketpair/SCM_RIGHTS, native PTY ioctls and
mapped control-file transport. Native terminal permission denials remain errors.
Anonymous-pipe metadata carriers use O_TMPFILE and OFD locks, also within the
baseline; no reader/writer endpoint is retained. `--case mount-namespace`,
`--case origin-transfer`, `test_descriptor_metadata.py`, stock sandbox-enabled
Chromium and `test_glycin_runtime.py` cover these paths under shell identity.
Native statx may return mount ID zero for anonymous objects; the adapter retains
that result instead of treating it as a failed mount lookup.

Opt-in routed networking uses the Linux 5.15 NETLINK_ROUTE wire contract in
`network_route`, retained namespace/interface/endpoint owners in `network_model`
and `network_endpoint`, and the existing baseline capture/cancellable IO path
in `network_io`. Its native sockets, accept4, eventfd and SCM_RIGHTS introduce
no post-5.15 dependency or privileged Android network operation. Unsupported
protocols return explicit errors. `test_network_{model,route,endpoint}.c`,
`test_routed_network.py` and `probe_docker_runtime.py --profile routed
--exercise-ports` cover mutation rollback, namespace moves, TCP/UDP, independent
port observation, outbound DNS/HTTP and cleanup under actual UID 2000.

Namespace-handle bind mounts use retained typed providers, baseline sealed
memfd carriers, O_PATH and descriptor duplication. They do not call host mount
or setns and introduce no post-5.15 dependency. Carrier reads are never reopened
through proc: the retained description supplies the descriptor, as for anonymous
ELF images. `--case mount-namespace` covers path/FD aliases, owner exit, recursive
bind, copy-cycle prevention, authority and repeated lazy retirement.

Logical `CLONE_NEWCGROUP`, namespace handles/ioctls and `setns` use the same
resource transactions and control-file carriers. Captured hierarchy roots and
user-namespace authority follow the Linux 5.15 contract; no host cgroup namespace
or newer syscall is required. `--case mount-namespace` covers relative proc paths,
mounted proc, clone/unshare/setns, retained handles, removed roots, owner checks
and `fsopen` capture under UID 2000.

Logical cgroup-device BPF uses the userspace ABI available before 5.15, sealed
memfd carriers and the existing control-FD delivery/ownership contract. It never
calls host bpf or requires CAP_BPF, native cgroup hooks, BTF or a newer kernel.
`cgroup_program`, `namespace_bpf` and `fs_bpf` own this permissive bookkeeping;
unsupported commands/features fail explicitly rather than falling through to
Android. `test_cgroup_bpf.py` covers program/attachment lifetime, protected exec,
SCM_RIGHTS, readonly policy, failed FD publication, invalid attributes and exact
warmed descriptor cleanup under UID 2000.

The descriptor mount API (`fsopen`, `fsconfig`, `fsmount`, `move_mount`,
`mount_setattr`) follows
the Linux 5.15 userspace contract through `fs_context`, `mount_source` and the
existing mount graph. It does not issue these privileged syscalls on the host.
Context carriers use sealed memfds; mount FDs use O_PATH and the common retained
origin/ADDFD/SCM_RIGHTS delivery mechanisms. No newer kernel interface is needed.
`test_mount_api.py` covers stock util-linux callers under UID 2000, and the
transient-store fixture covers detached graph custody and exact FD retirement.
Attribute changes use the existing single-writer policy, including recursive
preflight and locked-policy rejection; no host mount_setattr call is required.

`sysfs_view` retains the existing logical network owner and exposes its loopback
state through typed control files, O_PATH provenance and a private native name
tree. Legacy mount and fsopen share this provider; no host sysfs mount or
post-5.15 API is used. `test_sysfs.py` covers namespace authority and capture,
live netlink updates, retained/bound files, cgroup nesting, unsupported mutations,
stock util-linux mounting and repeated detached retirement under UID 2000.

`mqueue_view` implements a limited IPC-owned directory provider through the same
mount APIs, without CONFIG_POSIX_MQUEUE or a host mount. POSIX message calls
explicitly return ENOSYS; their absence must not fall through to Android queues
on kernels which enable them. No post-5.15 API is required. `test_mqueue_mount.py`
checks both mount APIs, IPC capture and authority, bind/copy/readonly behavior
and unsupported operations. The resource-owner fixture checks final namespace
release, private-tree removal and exact native FD baseline over 40 iterations.

## Newer Interfaces

Every owned dependency newer than 5.15 belongs here, including optional
optimizations and experimental fixtures. Guest programs' unadapted syscalls
retain native errors; arbitrary new guest syscalls are not runtime requirements.

| Interface | First upstream kernel | Owner and purpose | Behavior without it |
| --- | --- | --- | --- |
| `PIDFD_THREAD` | 6.9 | `task_descriptor.c` owns descriptor capture; `task_lifetime.c` owns exact-thread liveness for restricted proc roots. | Try flags zero for the same task. A non-leader rejected with EINVAL is reported as ENOTSUP and uses task-affine SCM_RIGHTS export. Liveness retains `/proc/<tid>/stat` instead: a flags-zero pidfd observes group death, not exact-thread death. Never substitute the leader's file table. |
| `SECCOMP_IOCTL_NOTIF_SET_FLAGS` / `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` | 6.6 | `namespace_broker.c`: optional notification scheduling hint. | Failed ioctl leaves normal notification wakeups enabled; no permission or affinity change. |
| `fchmodat2` | 6.5; `AT_EMPTY_PATH` in 6.6 | `namespace.c` translates store metadata through the worker. `file_calls.c` also has a native direct-backend path. | Logical store metadata does not require this host syscall. Native passthrough retains ENOSYS/flag errors; no fake success or unconditional startup requirement. |
| `SO_PEERPIDFD` | 6.5 | `test_proc_root_guest.py`: optional coverage of native peer-pidfd fields in logical fdinfo. | ENOPROTOOPT/EINVAL/ENOSYS skips only this optional acquisition; baseline pidfd_open and fdinfo assertions still run. This is not a runtime prerequisite. |
| `STATX_MNT_ID_UNIQUE` | 6.8 | `namespace_proc.c`: distinguishes globally unique mount IDs from the runtime's ordinary mount-ID namespace. | The adapter strips the UNIQUE request and asks for `STATX_MNT_ID` (5.8); returned masks do not claim UNIQUE support. |
| `PROCMAP_QUERY` | 6.11 | `test_mapping_task.c`: optional binary mapping-observation experiment. | Production `mapping_observation.c` reads a retained maps file. The fixture records unavailable ioctl access separately and verifies the text path. |
| `MFD_EXEC` | 6.3 | `test_exec_policy.c`: explicit executable-memfd policy experiment. | This experiment reports failure; production image admission does not require this flag. |
| `AT_EXECVE_CHECK` | 6.14 | Execution-policy boundary, not an enabled host dependency. | The adapter rejects unsupported execveat flags rather than treating an X_OK check as equivalent. |

Version references: [pidfd_open flags](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[Linux 6.6 seccomp ABI](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/seccomp.h),
[Linux 6.5 socket options](https://github.com/torvalds/linux/blob/v6.5/include/uapi/asm-generic/socket.h),
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
