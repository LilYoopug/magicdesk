# Kernel Compatibility

## Baseline

Shroot's minimum supported kernel is **Linux 5.15**. This is a design/support
boundary, not a claim of complete device coverage. The MagicDesk APK remains
Android 14 / API 34 and managed Desktop remains Android 15 / API 35; neither
acquires Shroot's kernel requirements. Shell tools, Termux, prepared chroot and
graphics services remain independent when guest execution is unavailable.

Native-leaf storage uses baseline openat/fstat/fchmod, user xattrs, proc FD magic
links and fsync. `inode_native.c` uses the retained proc alias for O_PATH metadata,
not fchmodat2/AT_EMPTY_PATH. `inode_publication.c` uses renameat2 with
RENAME_NOREPLACE and a shared lock-free 32-bit atomic hint; unsupported native
filesystem operations return their errors. These primitives add no post-5.15
dependency or shared startup probe. Store admission tests O_TMPFILE and user
xattrs before enabling eligible native creation; denial keeps the catalogue
allocator. Mixed directory enumeration uses getdents64 and bounded OFD cookies,
with persistent mappings for large filesystem cookies. None requires a newer
kernel. `test_native_leaf`, `test_publication` and the stores
runner cover UID-2000 operations, process interruption, error propagation and
portable backup/restore; they do not establish physical power-cut durability.

The optional gamepad bus uses baseline Unix stream/datagram socketpairs,
eventfd, poll/epoll, SCM credentials and the existing typed descriptor transport.
Evdev/joydev/uinput and udev discovery are guest providers; no native uinput
permission, input-driver module, device-node creation or global kernel uevent
subscription is required. The exported input ioctls predate 5.15. Unsupported
device classes fail explicitly. `test_input_devices`, `test_input_uinput`,
`fs_dispatch --input` and the guest/SDL fixtures cover these boundaries.

The namespace-local nftables adapter implements a supported subset of the
[Linux 5.15 nfnetlink ABI](https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/netfilter/nfnetlink.h)
over the existing Unix datagram carrier. Generation, tables/chains/rules/sets and
atomic batches require neither host NETLINK_NETFILTER permission nor CONFIG_NF_TABLES.
`network_flow` and `network_forward` apply IPv4 TCP/UDP flow filtering and NAT
using ordinary sockets, epoll, eventfd and nonblocking IO, all predating 5.15.
Unsupported expressions fail before publication; direct-flow revocation returns
`EBUSY`, and native backing ports are not kernel-firewall isolated.
`test_network_nft`, `probe_nft_runtime.py`, `probe_nft_traffic.py` and the stock
Podman/Docker fixtures cover protocol, atomicity, traffic and cleanup. No
post-5.15 host primitive or new shared-startup requirement is added.
Verdict maps, rule/base-chain logical counters, revision-zero xt TCP/UDP and
DNAT/SNAT adapters, bridge hairpin control, netlink credential snapshots and
IPv4 IP_PKTINFO use baseline userspace wire formats
and existing socket/relay owners. They introduce no newer host dependency.

Cooperative-entry spin timing optionally uses the arm64
[`__kernel_clock_gettime@LINUX_2.6.39` vDSO ABI](https://man7.org/linux/man-pages/man7/vdso.7.html).
`vdso.c` resolves its versioned export from the kernel's `AT_SYSINFO_EHDR`;
`cooperative_entry.c` falls back to the existing clock syscall when unavailable
or unsuccessful. Both predate 5.15. `test_vdso` covers bounded symbol/version
lookup, absent/unsupported layouts and a live monotonic-clock comparison;
cooperative runtime/libc fixtures cover execution, cancellation and filter
fallback. This optional optimization adds no shared-service prerequisite.

Admission uses actual operations under the selected executor identity, not an
Android-version inference or `uname`-only capability check. Kernel configuration,
SELinux, application filters and vendor backports affect availability. Headers
merely allow compiling an operation; they do not make it available at runtime.

`process_limits` implements launch-local `RLIMIT_NPROC` accounting using the
existing clone/identity/exit events, task-affine ABI copies and typed proc files.
Its user-namespace accounting follows Linux 5.15 semantics and introduces no new
host syscall, kernel feature or shared-startup probe. `test_nproc.py` covers
native and PID-scoped guest views, protected copies, quota/reaping and seccomp.
Native real-time scheduling and other host resource ceilings remain authoritative;
the packaged RTKit fixture records scheduler `EPERM` rather than masking it.

Launch cancellation uses baseline `timerfd_create(CLOCK_MONOTONIC)` and
`timerfd_settime` in the supervisor's existing poll loop. The descriptor is lazy
for unbounded launches; admission errors fail that launch, never shared services.
`test_resources.py --case launch-cancel` covers idle/busy, dumpable/protected
groups, ignored TERM, exact reaping and the distinction from cleanup failure.

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
`openat2`, `faccessat2`, `close_range` and shared/sealed memfds. The native read
provider uses `openat2(RESOLVE_NO_SYMLINKS, O_PATH|O_NOFOLLOW)` to pin admitted
task-independent paths. A missing or denied operation retains task-affine
dispatch; self aliases and private proc views do not use this optimization.
These flags predate the 5.15 baseline. In particular,
atomic `SECCOMP_ADDFD_FLAG_SEND` is a required FD-publication primitive, available
since Linux 5.14. Separate ADDFD and reply calls are not an equivalent fallback:
cancellation between them can leave an installed descriptor without a confirmed
result. `CLOSE_RANGE_CLOEXEC` is available since 5.11. Both fit the 5.15 baseline.
See the [seccomp notification contract](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
and [close_range flags](https://man7.org/linux/man-pages/man2/close_range.2.html).

Optional `cooperative_entry.c` / `namespace_broker.c` communication uses the
existing shared memfd, ordinary shared `FUTEX_WAIT`/`FUTEX_WAKE`, monotonic clock,
checked process-memory copying and notification wake gate. It adds no post-5.15
kernel primitive. Runtime admission failure selects the caller-owned SVC
continuation; installed application filters do not acquire an unfiltered direct
route. Kernel-carried `openat`/`fsopen` records retire at exact notification
admission; new-file creation reuses the existing publication protocol.
Existing regular-file plans, including writable/append/truncate opens, retain
one engine-owned O_PATH pin and use
a native guest `openat` through `/proc/SUPERVISOR/fd/PIN`, with exact-PC admission
in Shroot's filter. `close` and FD flags use the same file-table owner and native
result journal. Stop recovery uses existing GET/SETREGSET on AArch64; cancellation
preflight uses zero-count `FUTEX_WAKE_PRIVATE`. None requires a post-5.15 kernel
operation. Denied native reopens return their real errno; unsupported providers
decline before a data-open effect, not after it. A 64-boundary instruction-stop
fixture checks actual open/close/flag results under shell UID 2000. Deferred
FIFO completion uses the existing `ppoll`, ptrace interruption/restart and
owned-child reaping, not a new cancellation syscall or polling timer.
`test_cooperative_runtime.py` covers admission, exhausted pools, signals,
fork/exec, protected pointers, namespace changes, signal-handler memory
abandonment, argument/IP filter policy and TSYNC revocation. The isolated musl
integration additionally checks real libc threads, cancellation and exec,
cwd/dirfd replacement, FIFO signals/restarts and exact FD retirement.
The version-4 libc boundary adds only a bounded userspace offer-table lookup and
a fixed opaque handle. Runtime progress/feedback reuse the existing channel;
there is no new allocation syscall, loader dependency or kernel capability.

Ready open results may reuse a ptrace-stopped syscall through the existing fstat
notification route without changing application registers or its return PC.
The owner is `supervisor.c`, with `namespace_broker.c`
and `fd_install.c` retaining FD custody. This uses the
[5.15 post-TRACE seccomp recheck](https://github.com/torvalds/linux/blob/v5.15/kernel/seccomp.c),
NT_ARM_SYSTEM_CALL and syscall-exit observation, not a newer notification flag.
The broker matches the complete original call context, including ARM64's
preserved orig_x0, before normal fstat decoding. Confirmed replies avoid another
register read at the retained syscall-exit stop. Interrupted notification delivery
retains the completed result and uses the existing shielded task-affine gate;
protected inputs, application filters and debuggers keep their existing route.
`test_resources.py --case fs-buffer` covers these branches, masks, CLOEXEC,
mutation signals, preserved registers/NZCV, file-table pressure and group termination.
`--case fs-dispatch` also checks both carriers' exact argument matching, rejected
replay, confirmed results and FD cleanup.

Direct worker FD replies use the same baseline ADDFD_SEND primitive. Cancellation
can report ENOENT, or ESRCH after the receiver discards an already queued ADDFD;
the latter is accepted as cancellation only after ID_VALID confirms expiry.
`notification_result.c` retains the result; `namespace_broker.c` prevents another
execution during supervisor handoff, including kernel restarts without a delivered
signal. Nonblocking metadata recovery in `supervisor.c` uses baseline ptrace
register/signal-mask access and GET_SYSCALL_INFO (5.3), not WAIT_KILLABLE_RECV
(5.19). It rechecks the original SVC through kernel seccomp before completing
the read and restoring the real signal. `--case fs-buffer` compares native and
guest shared-memory creation under frequent signals, with and without SA_RESTART,
protected callers, preserved registers/NZCV and masks, application ERRNO/TRAP
filters, and concurrent SIGSTOP/SIGCONT cycles. ARM64's temporary x7 marker at
syscall stops is never copied back into the application context.

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
Guest `MS_NOSYMFOLLOW` and `MOUNT_ATTR_NOSYMFOLLOW` use the common mount policy and
component walker, not a host mount. Their semantics and the distinct
`ST_NOSYMFOLLOW` statfs bit exist in the
[Linux 5.15 ABI](https://github.com/torvalds/linux/blob/v5.15/include/linux/statfs.h).
`test_mount_api.py` covers detached tmpfs, native attachments, proc links, bind
aliases, remount and namespace copies; `--case mount-policy` also checks a bare
inode root with no attachments. Ordinary data IO needs no additional interception.
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
Their internal notification model uses baseline eventfd, epoll, atomic references
and a source mutex; it requires no kernel change above 5.15. Independent opens
own generation cursors and lazy wake descriptors. The virtual-interest collector
is connected to selected guest epoll queues. Native `epoll_pwait2`
(Linux 5.11) shares the direct wait policy; unsupported or denied native calls
retain their kernel error. No notification thread or periodic sampling is added.
Weak descriptor authorities use lazy eventfd notifications and userspace mutexes
within the same baseline. Subscriptions borrow a strong reference only while
accessing the provider; final release publishes expiry before destruction.
`control-event` covers acquisition/retirement races and failed admission;
`ofd-order` covers table and queued-transfer custody. No native epoll nesting,
kernel OFD reference-count inspection or newer syscall is required for this
internal lifetime mechanism.
Epoll creation custody and optional native-export reservations reuse the
existing file-table terminal observation, SCM_RIGHTS and userspace atomics.
They add no post-5.15 dependency, retained native epoll duplicate or kernel
nesting level. `control-event` requires zero interception of ordinary control
and wait calls (creation alone is observed); `ofd-order` covers export rollback
and activation races, and `ipc-origins` covers independent receiver custody.
Selector construction and staged epoll activation add no kernel API. The cold
remote-admission fixture uses baseline ptrace register/signal-mask access and
seccomp TSYNC, preserving the application's filter decision. It compares native
interrupt/restart behavior under dumpable and protected tasks; production
cross-owner admission also has guest coverage with protected foreign readers.
The common task-call executor also uses baseline `PTRACE_GET_SYSCALL_INFO` and
`NT_ARM_SYSTEM_CALL` to restore syscall entry/seccomp/exit boundaries without
repeating side effects. Restart-code exits use the kernel-restarted entry to
recover the private original argument, then rearm baseline PTRACE_INTERRUPT when
restoring the exit. This preserves restart processing without a pending real
signal. Native UID-2000 fixtures cover both dumpable and protected tasks,
signal-induced and synthetic-interrupt restarts, and IP-scoped TRACE filters.
The bootstrap's classic seccomp program can encode an ordinary close's low-int
FD in TRACE's 16-bit data, read through baseline PTRACE_GETEVENTMSG. Large and
negative descriptors retain full capture. Ordinary close skips an entry register
read but retains actual syscall-exit observation and table ownership. Scalar
filesystem receipts use the existing stopped-task result publication, with no
new seccomp flag, ioctl or post-5.15 dependency.
Production proc/watch selector installation uses this task-affine owner through
the mapped adapter frame, without guest FDs or ptrace writes to application
memory. Its payload uses reserved control capacity in the same mapping so IO
pool exhaustion cannot create a table-turn dependency cycle.
Guest selector/proc, Chromium sandbox, private-memory and native-wait fixtures
exercise that path. Single-task admission can fall back from denied seccomp
TSYNC to baseline PR_SET_SECCOMP, only after excluding siblings and private
helpers. Native fixtures cover that application-filtered path at all supported
continuation boundaries. The inventory/admission modules add no kernel API.
Mixed-queue native waiting preserves the caller's signalfd and temporary
signal-mask context when the caller exclusively owns its file table. This uses
the existing ptrace syscall boundary and exact native descriptor, not a new
kernel operation or a guest FD. Guest tests cover pending/process signals,
virtual wakeups, simultaneous ready events/signals, equal event data and filtered
cross-owner queue activation.
Shared-table waits use the same caller context with an atomic ADDFD_SEND loan
of the captured queue. Loan retirement reuses baseline close/close_range and the
common short-call/quiescence owner. Regression coverage includes exact-number
reuse, close_range, fork/unshare while waiting, retained CLOEXEC, denied close,
policy-rejected retirement and terminal cleanup through a surviving owner. No new kernel API, nested epoll
or post-5.15 dependency is introduced.
PTRACE_SETSIGMASK clears pending kernel saved-mask restoration,
so it cannot be used blindly at an interrupted epoll/ppoll exit. This semantic
requirement is part of the 5.15 baseline, not a reason to raise the minimum.
Named-FIFO readiness uses baseline epoll, shared read-only mappings and the
existing rendezvous generation file. Poll/select native waits reuse that
task-affine ptrace boundary even for shared file tables; provider helpers never
wait on the application's ordinary descriptors. Channel rejoining uses existing
O_PATH pins, flock leases and authenticated origin parcels. These paths add no
post-5.15 requirement. `test_fifo_runtime.py` covers initial hangup suppression,
signalfd, temporary masks/EINTR and transfer across sender exit and receiver exec;
`fs-buffer` covers contiguous mapped loans and terminal cleanup.
The live inventory fixture combines those baseline operations with CLONE_FILES
and fork, covering distinct thread groups over shared/copied tables and rollback
after one group's application filter denies seccomp. Quiescence loans retain
existing ptrace event/rusage and resume ownership without another kernel API.
Logical IPv4 sysctls, including forwarding policy, use the shared typed-control transport and retained mount
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
Nested debugger waits use baseline ppoll, PTRACE_INTERRUPT and ptrace register/
signal-mask operations. Kernel-owned syscall restart is shared with socket IO;
there is no new kernel requirement or permanent helper. Native-versus-guest
wait4/waitid signal tests and stock strace's 41-thread SIGINT detach cover it.
Mounted proc visibility policies use the Linux 5.15 `hidepid`/`gid`/`subset`
semantics in `procfs_view`, without host mount authority or newer syscalls.
Live peer inspection uses `/proc/PID/io`'s READ_FSCREDS check, including native
dumpability and LSM policy. Missing `/proc/self/io` (CONFIG_TASK_IO_ACCOUNTING)
rejects a restricted proc mount with EOPNOTSUPP; permission/resource failures
remain explicit. Guest credentials and capabilities never elevate native file
access. `test_proc_policy.py` checks credentials, groups, protected/live/zombie
tasks, retained FDs, bind/copy and both mount APIs under shell.
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
worker's acknowledged pause uses its pipe-backed queue signals and pthread synchronization,
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

The `ipc_origins` service uses the same capsule primitives and existing pipe-backed
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
filters. Mapped export-channel admission, task-affine ADDFD results and private-helper
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

Managed netlink control also implements the baseline nlctrl family catalogue,
strict route query validation, kernel-peer connect, policy-rule queries and
SO_PASSCRED/NETLINK_PKTINFO reply metadata. These are userspace protocol owners;
they do not open privileged host netlink sockets or require newer kernel APIs.
`--case mount-namespace` and `--case ofd-order` cover validation, duplication,
ancillary metadata, membership and unsupported operations. Default systemd boot
and the Podman probe exercise stock NetworkManager and netavark clients.

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
Tmpfs read-only reconfiguration uses baseline `F_SETLEASE/F_RDLCK` under the
existing store gate to detect native writers and shared writable mappings.
`inode_super.c` releases each probe lease before policy publication; native
unsupported/permission errors fail the requested reconfiguration only. Lease
break signals target the worker TID through baseline `F_SETOWN_EX`, with scoped
blocking and pending-signal preservation. Policy lives in the retained store,
not a new per-write syscall adapter. `test_mount_api.py` and the native
transient-store fixture cover writers, unlinked files, mappings, aliases,
cross-process snapshots and release. This does not require a post-5.15 kernel.
Native-leaf tmpfs writer discovery uses this same lease probe before unlink or
overwrite; a busy leaf is promoted so an unlinked writer still blocks read-only
remount until its description/mapping is released. Persistent-store mutation
does not acquire this tmpfs-only probe.

Protected proc final-link capture uses caller-side O_PATH|O_NOFOLLOW and the
existing exact-description transport. The filesystem walker verifies the captured
link and retains its original mount policy; it never changes dumpability or
requires pidfd_getfd permission. `test_proc_policy.py` covers protected metadata,
reopening, directory reads and no-follow link identity. Signal delivery after
guest ptrace uses the existing GETSIGINFO/SETSIGINFO primitives and target PID
view; `test_thread_identity_runtime.py --debuggers` covers libc's set-ID signal
handshake across debugger/target namespace boundaries.

`open_tree` and `STATX_ATTR_MOUNT_ROOT` use the same logical mount identity and
detached-origin lifetime; neither requires host mount privilege. Mounted proc
directories retain PID selection and typed UTS controls. `test_mount_api.py`
and `--case mount-namespace` cover these paths under shell identity.

Live mount-table descriptors use optional AF_UNIX out-of-band readiness
(`CONFIG_AF_UNIX_OOB`, upstream 5.15). `fs_mount_table.c` falls back to a regular
typed descriptor when the host rejects OOB: table reads remain supported, but
epoll registration may fail. PRI readiness is not a complete procfs ERR/poll
contract; typed UTS sysctl poll notification remains unsupported.

`terminal_calls.c` first tries native termios2 on the original task/FD. Firmware
EACCES or ENOTTY falls back to legacy termios for representable standard baud
rates only; arbitrary BOTHER rates return EOPNOTSUPP when native termios2 is
unavailable. `test_terminal_attributes.py` checks both ABI and terminal identity.

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
| `SECCOMP_IOCTL_NOTIF_SET_FLAGS` / `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` | 6.6 | `namespace_broker.c`: optional notification scheduling hint. | Failed ioctl leaves normal notification wakeups enabled; no permission or affinity change. Success does not guarantee CPU co-location: the scheduler still owns placement, and not every FD-install completion uses this hint. |
| `fchmodat2` | 6.5; `AT_EMPTY_PATH` in 6.6 | `namespace.c` translates store metadata through the worker. `file_calls.c` also has a native direct-backend path. | Logical store metadata does not require this host syscall. Native passthrough retains ENOSYS/flag errors; no fake success or unconditional startup requirement. |
| `SO_PEERPIDFD` | 6.5 | `test_proc_root_guest.py`: optional coverage of native peer-pidfd fields in logical fdinfo. | ENOPROTOOPT/EINVAL/ENOSYS skips only this optional acquisition; baseline pidfd_open and fdinfo assertions still run. This is not a runtime prerequisite. |
| `SO_PASSPIDFD` / `SCM_PIDFD` | 6.5 | `socket_control.h`, `ipc_io_host.c`, `task_receive.c` and `socket_ancillary.c`: receive, custody, CLOEXEC publication and cleanup of kernel-generated pidfds. An authenticated brokered sender carries its original flags-zero pidfd (baseline 5.3), never substitutes the broker's PIDFD. `ipc-ancillary` compares native/guest scalar, batch, peek, truncation, filtered receives and exact sender identity; `test_systemd.py` covers notify and FD-store restart. | The socket option retains native ENOPROTOOPT/EINVAL when unavailable; no synthetic support or startup requirement. The optional pidfd fixture reports that absence; ordinary credential and rights tests still run. Negative pidfd payloads remain errno values, not owned descriptors. |
| `PIDFD_GET_*_NAMESPACE` | 6.11 | `pid_calls.c`, `supervisor.c` and `namespace_proc.c`: guest pidfds return retained logical namespace handles through the common FD-publication path. `--case mount-namespace` and systemd directory setup cover the ABI. | No host namespace ioctl is required for managed pidfds. Time namespaces remain EOPNOTSUPP; unowned native pidfds retain native errors. |
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

The separate [cooperative-entry fixture](../guest-exec-lab/cooperative-entry.md)
uses shared anonymous mmap, classic shared FUTEX_WAIT/FUTEX_WAKE, Unix
SOCK_SEQPACKET and SCM_RIGHTS with the existing receiver's close-on-exec handling.
It introduces no post-5.15 dependency and does not participate in runtime
admission. Its bounded-spin mode is a userspace experiment, not a requirement
for ordinary Shroot or a substitute for application seccomp admission.

Its optional private-engine FD experiments use baseline `clone(CLONE_FILES)`
without CLONE_VM for the guest, and a pthread executor with
`unshare(CLONE_FILES)`. Flags-zero `pidfd_open` (5.3) and `pidfd_getfd` (5.6)
copy from the engine/thread-group leader into its same-process helper's private
table. They do not require PIDFD_THREAD or permission to export from a protected
guest process. The explicit `test-pidfd` fixture checks shared open-file offsets,
sockets, pipes, CLOEXEC and exact death retirement under shell UID 2000. A denied
probe fails that optional experiment; SCM_RIGHTS remains a separate control,
not an untested implicit fallback. `/proc/thread-self/fd` inventories the helper
table, whereas engine backing paths deliberately refer to the leader's table.
The ordinary-file `/proc/self/fd` reopen control creates a fresh open description
and is not a generic substitute for FD transfer. None changes runtime admission.

The same fixture's optional readonly open plans use baseline `O_PATH` pins and
proc FD links. The helper control opens through `/proc/self/fd`; the direct guest
control uses `/proc/<engine-pid>/fd`. The latter requires actual host permission
to access that engine's proc descriptor, and the guest's own seccomp policy must
permit the native open. It is not a way to bypass those policies. Deterministic
replacement/unlink and denied-open checks cover object pinning and cancellation
without publishing an origin or leaking pins. Readonly plans add no post-5.15
interface; creation still uses the separately probed pidfd control. These lab
checks do not make the mechanism a production capability or prove admission for
every sandbox.

The follow-up single-pin and queued-completion controls use the same interfaces.
Native guest close reports its actual result through a bounded shared-memory
queue; classic futex waits handle backpressure and explicit draining. Tests
cover a full queue, index wraparound, denied close and controlled guest death.
The optional bounded read window is userspace engine admission, not a new kernel
requirement. Arbitrary death between a native operation and completion posting,
concurrent FD users and production filter admission remain integration work.
