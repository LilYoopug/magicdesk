# Guest Syscall Interception

One native supervisor owns each explicitly launched guest tree. It uses seccomp
TRACE stops for adaptation and USER_NOTIF for descriptor metadata, selected path
operations, selected watch reads and the image-entry protocol. It never attaches to Android tasks.
The guest retains the selected real UID; neither the supervisor nor the filesystem
service changes SELinux policy or acquires root.

## Execution And State

The bootstrap publishes a private, size-checked ABI containing its gate addresses
at an explicit readiness stop. The supervisor reads it before resuming the guest;
exec republishes the same immutable bundle's ABI. No generated address header,
Java class name or environment-variable switch selects an implementation.
The dispatch gate receives policy in x9 and moves it to the C argument register
in userspace. It does not rely on changing x7 at an ARM64 syscall stop: the
[kernel restores that register](https://github.com/torvalds/linux/blob/v5.15/arch/arm64/kernel/ptrace.c#L1694-L1726)
after the stop. Notification cancellation, ordinary
seccomp entry and debugger syscall stepping share this entry contract.
Before task-affine admission, a signal-delivery stop retires an unexecuted
notification if it wins the race with the requested ptrace interruption.
The kernel retains EINTR and SA_RESTART semantics; a restarted call is a fresh
notification. The later interrupt cannot reuse the signal handler's registers
to execute the retired request. Adapter-owned, already-shielded operations
retain their existing completion and cancellation ownership.

`command_image` owns ELF/shebang inspection and returns retained program/loader
descriptors plus a pointer-free recipe. `command` assembles argv in its caller's
address space. Namespace reexec performs all image preparation on the filesystem
worker under the captured identity, root, cwd and mount view. Descriptor exec
captures the actual input OFD, including protected callers; no private image FD
is installed into the old guest table during preparation. The supervisor retains
both completed images while the guest constructs argv and enters real kernel exec.
The new bootstrap takes each lease with ADDFD_SEND
after kernel file-table separation, validates the load segments and maps them
without reopening filenames or reparsing the command. Failed exec or task loss
releases the leases; nonleader exec transfers them to the resulting task identity.
Queued cancellation and task death also retire in-progress worker resources,
without leaving temporary image FDs in a surviving CLONE_FILES peer.
The native-root laboratory path retains its inherited-image handoff.
The opened program's object ID and canonical dentry path are captured
in the opening transaction and passed through the bootstrap handoff; descriptor
exec obtains identity from the retained FD. Bootstrap does not issue a second
object lookup. Namespace image admission and logical credential publication remain
separate from this handoff.
Same-thread descriptor aliases and the current executable are captured before
worker admission. Unresolved proc magic links are rejected rather than resolved
against a supervisor descriptor or the native bootstrap image.

Data IO, common memory operations, futexes, clocks and signals pass directly to
the kernel. `MD_DOMAIN_KERNEL_CALLS` and `MD_DOMAIN_KERNEL_ARGUMENTS` describe
additional calls requiring no adaptation or observation in any guest domain.
The domain checker and seccomp filter consume these same definitions. Argument
predicates compare the full 64-bit value; other commands retain the dispatcher.
`MD_DOMAIN_FD_CALLS` and `MD_DOMAIN_FD_ARGUMENTS` separately select short native
descriptor mutations whose origins need ordered observation. Their fcntl command
is normalized to the kernel's 32-bit argument. Close, dup/dup3, close_range and
F_SETFD/F_DUPFD/F_DUPFD_CLOEXEC complete in the kernel; the supervisor publishes
metadata at the syscall-exit event. These capabilities remain available after
the admitted proc-root restriction, with application filters still in force.
Application filters still evaluate kernel-fast-path calls. Logical credentials,
root changes, filter installation and dumpability changes retain their observers.
Watch descriptors install bounded FD-class read selectors lazily; reads in
unselected classes stay native. Kernel-object identity distinguishes watch
readers from ordinary descriptors sharing a class. Selected reads retain their
original signal context while the worker waits for records; protected readers
use task-affine copying and a native readiness wait. Filter installation ownership is separate from
address-space and descriptor ownership; see [filesystem watches](watches.md).
Adapted calls run on guarded scratch stacks leased by `interception_memory`, the
address-space owner. CLONE_VM shares it; fork copies private scratch-stack mapping
metadata without sharing stack leases; exec replaces it. Completed calls return
their lease. Thread records are reused
without a fixed thread-count ceiling. Stack leases and ordering records are reused.
Origin-bearing opens and RPC exchanges allocate their own retained state; ordinary
data IO does not allocate runtime bookkeeping.

The same address-space owner retains shared adapter buffers. Namespace
bootstrap obtains a size-sealed memfd through ADDFD_SEND, maps it and closes the
setup FD before entering the guest image. Setup occurs once per fresh exec, not
per call; its file table is private after kernel exec. Fork retains the shared
allocator and inherited mapping, preventing overlapping leases between parent
and child. Exec creates an independent pool; outstanding workers retain old
storage until completion. The pool has 32 page-rounded response slots, allocated
only for namespace execution, not direct-rootfs launches.
`adapter_buffer` owns the lease controls, while `adapter_frame` defines the
filesystem, SysV packet and shared-memory metadata views. Filesystem requests
clear only their bounded header, not the entire payload capacity. SysV calls
return their slot before blocking; their inotify watcher remains supervisor-owned.

All guest filesystem operations, including opens/reopens and root changes, use this
transport before admission when their inputs can be captured. An immutable BRK gate
leases a slot, submits the request and releases it after the adapter copies the
result. No temporary guest FD, socket, mmap or pool allocation is needed per
call. Each admitted request owns one host allocation, a pinned output slot and a
captured filesystem context. Requests copy both validated paths, scalar fields
and attributes before submission; getcwd needs no pathname allocation. Input
capture acquires the file-table turn before the CLONE_FS turn, retaining the
admitted resource owner and each cwd/explicit-dirfd anchor. Unannotated explicit
inputs use `task_descriptor` to duplicate the real kernel description. Socket,
ACL-payload, directory-seek and watch inputs always capture that description, even when a path
annotation exists: an O_PATH anchor has neither its offset nor queue state.
Close/reuse or registry
replacement after capture cannot retarget the request. Captured reads release
both short turns before worker execution. Root replacement retains the ordered
filesystem mutation through worker publication, then releases it before returning
to the guest. SQLite runs only in the worker.
Slot pressure, context admission and completion use event-driven waits, ended by
completion or launch cancellation, not the RPC connection timeout. Queued
cancellation releases the request immediately; submitted cancellation detaches
the caller while the worker retains the buffer. Kernel inspection denial selects
table-owned export, using the same captured context and ordered input admission.
Unknown cwd still requires task-local capture. Invalid descriptors retain EBADF. Mutations never fall
back to RPC after execution. A pure O_PATH lookup can explicitly select rights
transfer when no stable reopen source exists, before publishing any descriptor.
Transport framing is checked separately from
the common typed request and result contracts.

For O_PATH results the worker transfers a retained source FD and origin to the
receiving task's supervisor record. The adapter reopens `/proc/PID/fd/N` through
the existing capture gate, preserving O_DIRECTORY and caller-selected CLOEXEC.
The file-table turn covers native installation and origin publication, not the
worker operation. Syscall completion or terminal observation publishes an
installed result without an adapter acknowledgement. Release or task loss closes
only the provider reference; no private service FD is left in the guest table.
For O_NOFOLLOW, directories use `/proc/PID/fd/N/.`; inode-backed objects use their
immutable physical basename below a retained objects directory. The provider
checks device/inode identity, not a logical path that copy-up or rename can change.
Store/source leases retain that name through delivery. The adapter passes the
actual flag to the kernel; fcntl is not emulated. Other native non-directory and
anonymous nofollow sources return the retained result through SCM_RIGHTS on the
table-owned channel, without repeating the filesystem lookup.

Mapped creation, temporary-file, ACL/xattr, mount-table and prepared-image results
use atomic ADDFD_SEND for their data FD. The provider retains the original open
description until release. The destination table turn orders kernel delivery and
allocation-free origin publication; it does not cover worker execution or guest
data IO. A cancelled notification installs nothing, while a successful ioctl
publishes even if the receiving task dies immediately. Delivery consumes only the
result slot and does not add a guest service FD.
Mapped watch reads use the same engine reservation as RPC. The supervisor offers
the shared reply, then queues commit/rejection on the filesystem worker after the
adapter acknowledges its copy. No file-table or filesystem turn is held while
waiting. Cancellation before offering restores records; after offering it retires
possibly delivered records. The request retains its buffer, input description and
context until worker completion, independently of task lifetime.
Mapped directory reads prepare records without advancing their OFD. The same
acknowledgement commits its next cookie or leaves its old position unchanged.
`ofd_order` retains only active descriptions, matching aliases with native
self-kcmp; a denied comparison is an explicit error, never a guessed identity.
Broker, mapped and RPC directory read/seek operations share those turns. Ordinary
synchronous reads allocate no entry when no asynchronous read is active.
Independent opens remain independent even for the same inode. Queued operations
retain their captured FD, not its possibly reused guest number. Cancellation
before offering leaves the cursor untouched; after offering it commits the
possibly copied batch. The worker holds no SQLite or file-table lock over user
copying. Guest operations bypassing the adapter and OFDs shared between separate
launch owners are outside this ordering contract.
Deferred FIFO opens run in a cancellable supervisor child after the worker has
prepared their resources. Its separate kernel file table owns pin/control FDs;
only the completed endpoint reaches the guest. No worker or resource turn spans
peer rendezvous. The existing SIGCHLD loop owns reaping, including cancelled
operations. Ordinary opens create no child. The guest build contains no
filesystem RPC-client fallback; native host clients retain their RPC contract.
Proc-image snapshots share this worker lifecycle. Task-local copying fills the
mapped slot; captured chunks build a worker-owned file. Only the completed
read-only/O_PATH result is delivered. Rejected copying and terminal loss retire
construction without a guest cleanup syscall. Kernel umask reads also stay on
the worker, retaining live kernel semantics rather than a shadow fs_struct mask.
Read-only and O_PATH snapshots publish retained origins with their result FD;
later metadata does not require another guest slot. Path metadata and statfs
likewise keep their temporary objects on the worker. Watch registration captures
the queue OFD and resolves the target in the same authenticated view. Opening a
current-thread proc-FD alias captures that descriptor directly; native reopening
uses the captured object, not a second lookup of the guest FD number.
Metadata/readlink/suffix operations borrow the same original input. Foreign
executable readlink uses the shared response mapping and existing process-access
checks, without a guest-side file or read syscall.
Mknod of regular files/FIFOs also keeps construction descriptors on the worker.
Task-affine chdir/truncate lease a worker-owned target; the caller executes the
final syscall without installing that descriptor. Kernel filesystem state and
caller RLIMIT_FSIZE/SIGXFSZ remain native. The lease closes on completion or death.
Xattr targets and ACL values stay worker-owned. Bounded mapped bytes carry up to
64 KiB; input is copied before admission and output is copied by the originating
task. No guest payload FD or scratch target FD is needed. FD-style xattr calls
capture the actual description, including its O_PATH restriction; path calls
use the retained cwd/dirfd origin. Native host RPC uses the same engine contract.
Slot reuse clears its header prefix only; unused value pages are not touched by
ordinary calls. Shared bytes do not contain ownership metadata or trusted pointers.
Inherited shared bytes are not isolation between mutually hostile guest processes.

`fd_channel` owns both receive queues of a seqpacket pair in the supervisor.
A file table acquires its CLOEXEC endpoint lazily via atomic ADDFD_SEND when
protected input export or a result-rights transfer needs it.
Sparse descriptor metadata follows its aliases
through dup, close/range, fork, unshare and exec. The file-table turn covers
export, not worker execution. Each message is bound to its retained channel,
request token, expected vector length and kernel SCM_CREDENTIALS process identity.
The supervisor closes malformed, duplicate and cancelled rights; final channel
release also drops any queued descriptions. It never mirrors application OFDs
between requests. Caller-owned input leases let the channel dispatch accepted
vectors independently of the filesystem service; cancellation does not discard
another owner's message. Dispatch allocates no bookkeeping and invokes no callbacks.
Ambiguous terminal mutation of an infrastructure slot requires
task-local F_GETFD/SO_COOKIE observation under its table turn. Matching socket
identity repairs the entry; closed/replaced slots lose only their annotation.
Denied or cancelled observation leaves it uncertain, without admitting another
possibly orphaned slot. Ordinary transfers do not perform these extra checks.
This costs one infrastructure FD per newly admitted table, not one per request.
Cold admission may fail with EMFILE; native SCM_RIGHTS quotas and application
seccomp denial still apply. Shared guest memory and process credentials do not
establish hostile-thread or arbitrary application message provenance.

Protected metadata uses those same input leases with register-only control. It
does not acquire a filesystem mapping slot, including when invoked inside an
adapter continuation. The table turn covers source capture and original-site
replay; terminal cancellation releases the lease, not a guessed guest FD.
Restricted `/proc/self/fd` directory opens borrow the verified original proc-root
FD under that turn and execute a fixed bootstrap pathname after admission. The
kernel result belongs directly to the application. There is no temporary proc
root or result FD to export/close, and no second read of an application pathname
after it has been validated.

`fd_return` orders result publication by destination table and channel; the
channel turn also covers independent tables inherited through fork. One packet
is offered at a time. `fd_delivery` prepares origins against a borrowed receipt
in the existing shared request mapping, without a per-call memfd, mapping or
guest scratch FD. Kernel recvmsg writes that receipt. Completion or exact task
termination publishes installed origins before releasing the table turn. The
supervisor drains unreceived rights through its retained copy of the guest
endpoint before releasing the channel turn. No cleanup syscall is injected into
a dying task, and no installed caller FD is closed as transport cleanup.
An admitted channel needs only the result slot. Cold admission needs one extra
infrastructure slot; receive truncation at EMFILE releases queued rights rather
than retrying the lookup. Application recvmsg restrictions still apply.

Regular-file seeks use a supervisor fast path after the original syscall's
seccomp admission and domain checks. A task-affine duplicated FD retains the
actual open-file description throughout inspection and seek; no FD-number
cache or namespace metadata RPC is involved. Shared positions and descriptor
reuse retain kernel semantics. When remote descriptor access is unavailable, the
adapter holds the file-table turn through native fstat and a non-directory seek.
This needs no data-OFD mirror, transport FD or namespace metadata lookup.
Directory seeks enter the namespace engine through mapped requests when the
real description can be captured; no preliminary path anchor substitutes for
its shared kernel position. Enumeration retains a separate delivery contract.

`namespace_broker.c` handles ordinary openat/newfstatat/fstat/getdents64 notifications in the
namespace worker, alongside adapter RPC. The worker alone owns SQLite and the
sealed-image catalogue; `fs_engine.c` also dispatches shared-buffer requests. Eligible notifications
copy paths page by page, retain exact-task descriptors and validate notification
IDs before execution and result publication. Successful opens use atomic ADDFD
plus response. The optional kernel synchronous-wakeup hint changes scheduling
only; unsupported kernels retain normal notification delivery.
Directory reads use the engine's deferred-position contract. Their existing
file-table/OFD turn spans output copying, notification reply and cursor commit.
An invalid notification, rejected kernel reply or failed/partial copy cannot
consume records; only a successful accepted reply advances the retained OFD.

Pidfds are owned by task lifetime, borrowed during request preparation and retired
on exit or exec. No file-number, cwd, path or metadata cache is involved. Published
supervisor state excludes restricted domains and adapter continuations from the
ordinary path. A shared-root restriction revokes every CLONE_FS member before
its caller resumes, including members not returning through a ptrace stop.
ADDFD rejects O_PATH. Eligible adapter requests use retained proc reopening;
uncaptured inputs and nofollow sources without a stable backing use SCM_RIGHTS. Mutating opens and directory
seeks retain the task-affine adapter and its no-replay contract.
Filesystem transports order descriptor capture and publication with native
table mutations. RPC control uses an immutable bootstrap BRK entry point,
not a new syscall subject to an application's seccomp syscall allowlist.
Only a ready supervised task uses it. FD payload delivery has a retained kernel
recvmsg receipt, so receiver death does not require a guest acknowledgement.
Native adapter chdir/fchdir and a dedicated bootstrap O_PATH capture entry point
also have completion observation. The gate captures `.`, a current-thread proc
FD alias or a retained worker result. Cwd capture orders both independently shared CLONE_FS and CLONE_FILES
owners, acquiring the file-table turn first; descriptor capture needs only that
table. The gate validates its entry address, syscall, flags and origin selector.
The adapter supplies `.` or the original parsed proc alias without rewriting
it into a canonical spelling; the kernel still validates the actual path. Like
internal RPC receipts, this is trusted adapter coordination, not isolation from
a malicious guest modifying its own memory. Kernel permissions and application
seccomp filters remain in force.
On its first O_PATH capture a task acquires terminal-event observation, retained
across clone/exec separately from nested debugger options. At the exact capture
return gate the supervisor publishes the terminal openat result before releasing
the file-table turn. A killed call may retain either ABI spelling of AT_FDCWD;
neither is an installed FD. Unrecognized terminal state remains unknown. This
adds one option update on first capture and an exit event for participating
tasks, not additional per-IO stops or cleanup injection into a dying task.
See [publication ordering](process-resources.md#publication-ordering) for lifetime
rules and the remaining inherited/native/general-SCM_RIGHTS boundaries.
Directory reads validate and enumerate through one namespace operation without a
preliminary metadata RPC. A reusable 64 KiB worker buffer bounds output independently
of the RPC frame, with no per-read allocation. The engine's synchronous output callback runs after
the read transaction, before advancing the actual open-file-description cursor.
Denied remote output can delegate only when no bytes or cursor position changed;
partial copies fail without automatic replay. Cancellation before publication
leaves the cursor unchanged. Cancellation after publication/advance may have an
uncertain outcome, like a lost RPC reply. Restricted domains retain their native
descriptor-read policy, and application seccomp filters still apply.

`magicdesk-guest --statistics --store STORE -- PROGRAM` enables aggregate
syscall/ptrace/stop counters, broker handling/delegation counts, engine operation
times, SQLite costs and CPU usage, printed once on completion. Namespace-worker
CPU is a subset of supervisor process CPU, not an additional cost. Collection and clock
sampling are opt-in; there are no per-call logs. Engine counters cover direct,
mapped and RPC execution; transport selection does not hide filesystem work.
Operation times include kernel
waiting and descheduling; nested filesystem/SQLite totals must not be added as
independent CPU costs. Detailed `--diagnostics` is a separate mode; neither is
enabled for ordinary launches or comparative timing runs.

Internal sendmsg/recvmsg at the immutable raw-syscall gate go directly to the
kernel. These calls are already unconditional native operations in every guest
domain; the domain policy and gate share the explicit list. External calls still
enter their adapters. This removes redundant supervisor stops, not application
filter evaluation: ERRNO, TRAP and KILL also apply to the internal transport.
Internal fstat at the same gate reads native descriptor metadata directly; it
does not request logical inode or set-ID metadata. Application fstat retains the
namespace and image-catalogue path.

The guest owns SIGSYS, signal masks and alternate stacks. Native clone and signal
return retain their register/extension ABI. Application filters are not removed:
ERRNO, TRAP and KILL retain kernel precedence over runtime TRACE/USER_NOTIF.
Register changes and same-site replay are rechecked by the kernel. Cancellation,
group stops, concurrent TSYNC and non-leader exec have dedicated fixtures.

## Guest Kernel Interfaces

Nested guest debugging uses the [debugger contract](debugging.md). The supervisor
retains physical ptrace ownership; GDB requests do not replace syscall mediation.
Native descriptor completion publishes origins before delivering the inferior's
syscall-exit stop; internal adapter calls are not additional guest debugger events.

Native `/proc` and `/dev` descriptors remain task-affine when the operation needs
no guest inode authority. SELinux can allow local metadata access but reject
descriptor transfer to another process. An ordinary notification that cannot
borrow the descriptor delegates to the existing task adapter. A failed protected
SCM_RIGHTS export returns an error and releases received descriptors; truncated
ancillary data is not a supervisor assertion or permission to bypass a guest domain.

`guest_domain` owns the distinction between an unsupported guest interface and
permission to access a host resource. Kernel audit has no guest implementation:
AF_NETLINK/NETLINK_AUDIT creation returns EPROTONOSUPPORT before a kernel socket
is created. The rule is independent of executable name, distribution, virtual
root and actual root. It applies at the existing socket syscall stop, including
raw SVC and nondumpable tasks, without additional ptrace stops or allocations.
Other socket protocols retain their existing kernel/domain checks.

No host denial is converted to success, no audit record is discarded after
claiming delivery, and Android's global audit service is not reconfigured.
Stock [shadow account tools](https://github.com/shadow-maint/shadow/blob/4.17.4/lib/audit_help.c)
already accept an unavailable audit protocol. Software requiring audit must treat
it as unsupported. Application seccomp ERRNO/TRAP/KILL still precedes runtime
TRACE handling, including this interface rule.

The guest has no key-management provider. `add_key`, `request_key` and `keyctl`
return ENOSYS in the initial seccomp policy, including raw SVC, protected callers,
fork/exec and nested namespaces. They never enter Android's key service or claim
successful keyring creation. Applications may choose their existing no-key-service
path; applications requiring keys receive an explicit unavailable interface.
Later application ERRNO and higher-priority TRAP/KILL policies remain effective.
There is no syscall-specific supervisor work or persistent keyring allocation.

## Protected Metadata

The supervisor first attempts kernel remote-memory/descriptor access. A
nondumpable task can deny that access; the runtime never makes it dumpable to
proceed. The task-affine fallback exports a retained descriptor through SCM_RIGHTS,
uses notification ADDFD and resumes a bounded copy at the original call site.
Instruction-only copy faults return EFAULT. Notification IDs are checked when
replying; cancellation invalidates pending work rather than authorizing a replay.

Filesystem service authorization remains based on the real executor UID, not
the browser's seccomp domain. Same-site filtering alone is not a complete
authorization boundary for every broker request or in-process syscall gate.

## Image Admission And Logical Credentials

`--admit-elf /absolute/guest/path` explicitly selects one ordinary ELF for a
launch-local sealed snapshot and logical set-ID metadata. The filesystem service
owns the catalogue: path lookup, object reopening, hardlinks and FD metadata agree
on that admitted object. It does not chmod or replace the stored source.

Initial launch and exec use the same admission contract. The supervisor tracks
logical IDs, irreversible drops and no_new_privs, publishes auxv/AT_SECURE, and
applies the corresponding nondumpable state before loader entry. Real kernel
credentials remain those of the executor. Ordinary stored files retain their
logical ownership/mode without acquiring automatic set-ID admission; actual
set-ID backing executables remain rejected.

`--user` and OCI User share `guest_accounts` resolution and `guest_identity` with
image admission. Each task retains real/effective/saved/filesystem UID/GID and
immutable supplementary groups across fork and exec. Raw set-ID calls remain
thread-local; libc may broadcast them. `getgroups/setgroups` use checked copies,
with task-affine bounded batches for nondumpable/protected memory. An incomplete
input does not commit a new group list. Initial no_new_privs is inherited from
the executor and can only increase. Filesystem requests use the same identities
through `task_registry`, together with their filesystem-root snapshot; this is
guest DAC and path selection, not seccomp-domain confinement.

The proc-root model handles the restricted self/fd or fdinfo roots used by the
tested helper, with CLONE_FS ownership and irreversible narrowing. Ordinary
inode-backed guest chroot uses the same resource owner and the filesystem engine;
its limits are in [process resources](process-resources.md#guest-roots).
Neither chroot mechanism creates a mount namespace. Guest `CLONE_NEWNS` separately
copies the worker-owned mount view and FS context before publication; it does
not create a host kernel namespace or change the selected Android identity.

Stock Debian Chromium passes three fresh-profile headless JavaScript/DOM runs
and PNG production with its normal helper and no sandbox-disabling flags. Tests
observe installed application filters and require process completion. This is
application execution, not security equivalence to a native Linux sandbox.
Interpreter/library admission, mapped-code protection, complete descriptor/root
confinement and domain-authenticated filesystem authorization are not established.

## Lifetimes And Availability

The runner owns the guardian; the guardian owns the supervisor and its descendants.
The supervisor's namespace worker is joined after tracee cleanup. Signalfd, pidfds,
eventfds and child/ptrace events drive
completion and cancellation. There is no ordinary launch deadline; an explicit
test deadline fails and cancels the owned tree. Supervisors close unrelated
inherited FDs while the application retains caller-supplied descriptors.
See [process lifetime](process-lifetime.md).

The lazy guest probe executes under this supervisor and tests the actual kernel
operations in the selected shell/root domain. Denial fails that guest launch;
it does not disable Android tools, PRoot, chroot, graphics or Desktop. The APK
does not load these native executables into ART or probe them during startup.
Current device coverage is UID 2000, NX809J, Android 16, Linux 6.12.23, 4 KiB pages.
Other kernels, page sizes and actual UID 0 require separate device verification.
