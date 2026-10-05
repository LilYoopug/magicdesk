# Process Resources

`task_resources` owns independently shared guest state in the supervisor.
Its lifecycle follows successful kernel process/resource transitions, not
Android Activities, named environments or launcher configuration.

| Resource | Clone sharing | Unshare | Exec |
| --- | --- | --- | --- |
| Filesystem context | `CLONE_FS` | `CLONE_FS` | Retained |
| Mount view | Shared independently of `CLONE_FS` | Namespace creation unsupported | Retained |
| Descriptor-origin annotations | `CLONE_FILES` | `CLONE_FILES`, `CLOSE_RANGE_UNSHARE` | Detach; remove close-on-exec entries |
| Semaphore undo | `CLONE_SYSVSEM` | `CLONE_SYSVSEM` | Retained |

The kernel owns cwd, umask, descriptor tables and open-file descriptions.
The filesystem context owns guest root selection, optional cwd provenance and the admitted proc-root
restriction. `task_registry` pins that context alongside each task's identity;
registry references do not count as task owners. Both filesystem request
transports use `md_fs_context` to capture identity, filesystem owner, root, cwd
origin, mount view and descriptor-origin table in one authenticated registry
snapshot. The file-table handle remains live; it is not a frozen copy of its
entries. A missing task mount view fails explicitly; the worker's initial view
is not a fallback for another task.
See [namespace execution](namespace-execution.md) for the launch filesystem and
[interception](interception.md) for restricted domains.

## Request Context

The namespace notification broker and task-affine RPC service retain the same
request context from admission through execution and delivery cleanup. It binds
the task and authenticated peer once; dispatch cannot substitute either identity
or resolve a replacement task record. Direct notifications capture it before
duplicating input descriptors; RPC captures it after packet validation and before
dispatch, including watch reads. Delegation releases the direct context; the
task-affine request authenticates independently.

Registry replacement, task exit and resource-owner release do not invalidate an
admitted request. Guest chroot publishes into its captured filesystem owner,
not a fresh lookup of the task ID. Real-ID access checks use a local credential
value without changing the captured identity. Execution borrows the retained
view/root and restores the worker's previous context on both success and failure.

Context storage belongs to the existing operation or peer pool, and retaining
resources adds no per-request heap allocation or RPC. References survive reply,
watch acknowledgement and client-release phases, and are released on completion,
failure, timeout or worker shutdown. The filesystem worker/store must outlive
them. Synchronous internal engine callers use a scoped context through
`md_fs_execute`.

Retained authentication is not cancellation rollback. Input-descriptor capture
and result publication use the file-table ordering described below; a failed
reply does not undo committed IO.

## Mount Views

`mount_namespace` owns the attachment tree, retained native objects and native
mount-ID mapping. Tasks, registry entries and in-flight snapshots hold independent
references. Fork and threads retain the same view, regardless of CLONE_FS;
unsharing cwd/root or semaphore undo does not split it. Nonleader exec transfers
the executing task's reference with its other resources. Final release closes
retained descriptors outside the registry lock.

The filesystem worker builds the initial view before acknowledging readiness,
and remains the sole executor of path resolution and object registration. The
supervisor only manages references; it never reads the mutable object cache.
Registry snapshots stay valid after task replacement or removal. Dispatch selects
that snapshot's mount view and restores its previous borrowed context on failure
as well as success. A root from another view is rejected as stale.

An empty view allocates only its owner, not attachment arrays or object indexes;
requests without attachments retain the direct inode-engine path. Ordinary
requests acquire references without heap allocation, extra RPC or syscall stops.
`md_fs_mounts_copy` constructs an unpublished candidate on the filesystem worker.
It copies source/covered O_PATH references, parent relationships and per-mount
policy, then explicitly rebases the selected root. Inode roots retain their
backend identity; native roots receive a location in the new tree. A location
from the original native tree is stale in the copy. Neither registry publication
nor the original context changes on failure, and partial candidates release all
acquired descriptors.

Mount IDs identify instances, not attachment indexes. Root, shared-memory,
attachment and admitted native mounts use one allocator per owner process; IDs
are not reused, and exhaustion fails explicitly. statx and mount-table publication
use the same mapping. Copies have distinct IDs and independent lazy native-ID
maps. The object cache is not copied: only the selected native root is registered,
so copy cost depends on mount count, not the number of previously opened files.
Only O_PATH references are retained; FIFO reader/writer counts and flock/OFD-lock
lifetime remain with application descriptions.

Candidate construction is not guest CLONE_NEWNS. Publishing a replacement view
requires task descriptor/cwd provenance through every kernel lifetime transition.
Guest namespace creation still fails explicitly.

## Path Origins

The filesystem engine accepts optional `md_fs_anchor` origins for its captured
base descriptors. Each anchor retains the exact mount view, mount and an O_PATH
reference. It borrows the worker's backing store, which must outlive the anchor.
Successful open/reopen operations can return an owned anchor when explicitly
requested. Other calls allocate no anchor; RPC clients cannot serialize pointers
or claim a view. The transport must obtain provenance from trusted task resources.

Relative paths, relative symlinks and `..` follow the origin's tree and policy,
even when the task selects a copied tree. Absolute paths and absolute symlinks
start at the task's current root. `RESOLVE_IN_ROOT` instead keeps the captured
base as the resolution root. `RESOLVE_NO_XDEV` checks mount/view changes,
including an absolute symlink resetting traversal. Link and rename cannot join
different mount instances. stat metadata and reopen retain the origin's mount ID
and readonly policy rather than inferring them from the current view.

Anchors neither retain readable/writable descriptions nor replace the input FD
for data operations. Directory offsets, FIFO peers and flock/OFD-lock release
remain kernel-owned. Anchor-capture failure closes the result FD and any pending
FIFO rendezvous descriptor. It does not undo earlier filesystem mutations or
authorize a retry.

The caller must associate each anchor with the correct captured descriptor.
Device/inode validation rejects a mismatched object; it cannot distinguish two
opens of the same inode through different mounts. An O_PATH pin alone is not an
open-file-description identity. There is no mirror of ordinary data descriptions;
read/write stays native and close is observed at its kernel completion.

Cross-view relative IO works, but path/image-path publication for an origin in
another tree returns ENOENT instead of inventing a current-root path. Changing
the task root through such an origin is unsupported.

Native object IDs identify `(mount, device, inode)` within their retained view.
The walker or a trusted origin selects the mount, so aliases can retain distinct
IDs and readonly policy even after unlink. Image opening and root capture use
the resolved mount rather than inferring it from the backing inode. Root capture
requires a directory in the selected view and rejects mismatched or stale origins.
An unannotated descriptor fails with ENOTSUP when cached identities or uncached
source lookup reveal multiple mounts; a unique cached match retains the existing
fast path. The cache is not a replacement for complete descriptor provenance,
and public admission of duplicated/overlapping native sources remains disabled.

## Descriptor And Cwd Annotations

`fd_origins` is a sparse metadata table keyed by guest FD number. It retains
anchors and descriptor flags, never readable/writable descriptions or offsets.
The owner follows CLONE_FILES independently of both CLONE_FS and mount-view
ownership. A fork without CLONE_FILES copies annotations; shared owners see one
table. Registry and in-flight request pins keep it alive without counting as
task owners. An absent entry means unknown provenance, not EBADF.

The owner is small; buckets and entries are allocated only for explicit
annotations. A prepared update reserves memory and retains its origin before a
kernel mutation. Publication after success needs no allocation; cancellation
leaves the old entry intact. Replacing a destination with an unknown origin
clears its previous annotation. Range closure, close-on-exec marking and exec
cleanup operate on existing entries without per-FD allocation. Locks cover only
metadata; removed anchors are released outside them.

The filesystem context similarly retains an optional cwd anchor. CLONE_FS
shares it, an independent context copies the reference, and exec retains it.
Root selection and cwd are independent: changing the root does not move cwd,
and cwd provenance alone does not activate the scoped-root adapter. The special
proc-root chdir clears ordinary cwd provenance.

Filesystem opens from the direct broker and task-affine service publish their
origins automatically. Native dup/dup3, F_DUPFD/F_DUPFD_CLOEXEC, F_SETFD, close
and close_range update annotations from their actual kernel results. Fork,
unshare and exec use the same ordered ownership transition. The seccomp filter
and restricted-domain policy share the descriptor-operation list; observation
does not remove native descriptor capabilities after a proc-root restriction.

This does not yet cover cwd changes, inherited/native descriptors or general
application SCM_RIGHTS transfers. An unconfirmed native mutation at task death
forgets any known affected destination instead of claiming rollback or retaining
a potentially stale origin. An automatically assigned dup result is then unknown.
Complete provenance, including those terminal cases, is required before copied
guest namespaces can be published.

### Publication Ordering

The file-table owner provides an intrusive queue for short descriptor capture
and publication operations. The supervisor and filesystem worker admit records
through the same synchronized queue, while each record retains one event-loop
owner. Mutexes cover metadata changes, never kernel calls or event waits.
CLONE_FILES peers share the queue, while an independent table copy starts with
an empty queue. Every accepted request pins its table through completion,
including after the last task releases ownership.

A zero-initialized caller-owned record is queued or immediately ready, then
explicitly started. Completion follows the exact kernel result and its metadata
publication, and signals the newly ready successor's retained eventfd token.
No successor pointer crosses event-loop ownership. The token duplicates the
nonblocking eventfd once per event loop, not per request; loop shutdown or FD
reuse cannot redirect a later wake. A saturated eventfd already has a wake pending.
Cancelling a queued or ready record removes it; cancelling a running record
only records intent. It continues to own its turn until the kernel operation
is confirmed complete. Cancellation or a timeout does not prove that a descriptor
was never installed. Requests perform no queue allocation, callbacks or blocking
waits, and unrelated file tables can progress independently.

Both filesystem transports and the observed native mutations use this ordering.
A blocking receive or FIFO rendezvous waits outside the queue; only its short
descriptor capture/publication phase belongs inside it. A cancelled queued
notification is validated again before use. Unordered native producers and
readers of live FD numbers do not gain a kernel barrier from the metadata mutex
or this queue's existence. Close and replacement can release a native description
with blocking cleanup; complete peer-dependent progress for such native resources
is not established by the short-operation fixtures.

### Kernel Publication Boundaries

`ADDFD_FLAG_SEND` makes FD installation and the notification response atomic
against cancellation. It does not keep the receiver stopped until subsequent
supervisor metadata writes. A CLONE_FILES peer can replace that slot even when
installation and response are separated. Replacement with another open
description of the same inode is not detected by device/inode validation.

A split ADDFD followed by a cancelled notification can leave an installed FD
while the caller receives EINTR. A failed SEND is therefore not proof that no
descriptor was installed, and rollback cannot blindly close a reusable FD number.
SCM_RIGHTS similarly installs received FDs before an application acknowledgement;
the acknowledgement is not a shared-table publication barrier.

The direct broker prepares the annotation before atomic ADDFD_SEND, publishes
the returned FD number, then releases its table turn. An observed shared-table
mutation cannot overtake that publication. Failed atomic delivery discards the
prepared annotation, not a guessed descriptor number. O_PATH still requires the
task-affine transport, since notification ADDFD rejects it.

Task-affine RPC captures input origins under a short send turn. A launch-local
exchange ID binds them to the authenticated actor and exact table; wire values
are not pointers. The worker retains the exchange independently of its initiating
task. Metadata-only replies need no receiving table turn. FD replies first send
a sealed-size shared receipt, then a separate payload-FD parcel. The receiver
waits for readiness outside the table turn and executes nonblocking recvmsg
inside it. The kernel writes the installed FD numbers into the retained receipt.
Normal completion or the receiving task's terminal event publishes those numbers
before releasing the turn; no post-receive guest ACK is needed. Truncated delivery
publishes exactly the installed prefix before client-side error cleanup.

Only FD-producing RPC exchanges allocate a receipt mapping. Updates are prepared
before delivery, and publication itself is allocation-free. Transport readiness,
peer lifetime and syscall completion remain distinct from cancellation intent.
The shared mapping is a lifetime mechanism, not protection against a malicious
guest modifying its own memory. General application SCM_RIGHTS is not covered.
See the kernel's [userspace notification contract](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html#userspace-notification).

## Guest Roots

`chroot` selects a directory through the existing composed filesystem
walker, checks search permission and guest CAP_SYS_CHROOT, and changes the
calling task's filesystem context only after success. Shared CLONE_FS owners
observe that change; fork or successful `unshare(CLONE_FS)` gives an independent
context. Exec retains it, including for nondumpable processes. Registry locks
cover snapshots/publication, never filesystem IO.

Absolute paths and absolute symlinks start at the selected root; `..` stops
there. `md_fs_location` identifies the root by mount and backend object, not a
pathname prefix. Inode-store roots and directories inside native attachments
share this contract, including rename and retained-descriptor lifetime. Cwd
and existing descriptors are not moved or revoked: relative access through a
retained directory outside the new root remains possible, as with Linux chroot.
getcwd returns ENOENT when the directory has no path within the selected root.
Mount-table snapshots omit attachments outside it and retain visible parent/child
mount IDs. Native roots preserve their attachment's readonly policy and the
kernel's permission checks; guest CAP_SYS_CHROOT grants no Android authority.

The syscall adapter receives task-local root selection, including when CLONE_VM
peers have independently unshared filesystem contexts. It has no mutable global
current-root cache. Ordinary launches need no additional RPC, SQL query or
per-request allocation. Only scoped-root adapter calls materialize a local
filesystem configuration.

Arbitrary native/proc roots outside explicit attachments return ENOTSUP.
Native-directory pathname traversal through inherited `/proc` or `/dev`
descriptors also remains unsupported after guest chroot. The separately admitted
`/proc/self/fd` and `fdinfo` restriction retains its irreversible policy. These
explicit limits are not successful mount or namespace emulation.

Copying a descriptor table does not copy open-file descriptions: offsets remain
shared, while close-on-exec flags and descriptor closure become independent.
There is no supervisor mirror of every open-file description. Reads and writes
remain native; short table mutations have ordered completion observation.

## Resource Changes

`unshare` prepares candidate guest-owned resources before resuming the kernel
call. The syscall-exit observer commits them only if the kernel succeeds.
Failure, cancellation or task death releases the candidate; no partial guest
change is published. The kernel validates `CLONE_VM`, `CLONE_SIGHAND` and
`CLONE_THREAD` constraints. Unsupported namespace flags fail before changing
any resource, including when combined with otherwise supported flags.

An unshared filesystem context copies retained root descriptors only when
there are other owners. A sole owner needs no copy. Semaphore undo starts empty
when split; leaving the old undo group applies its adjustments only when the
last owner leaves. Ordinary fork starts an independent empty undo group.

Fork ownership is published from the kernel's birth event before either
participant resumes guest execution. Nonleader exec transfers the executing
thread's resources to its resulting process identity; teardown of the replaced
leader must not release the executing thread's owners. Kernel exec detaches
shared descriptor tables, but not shared filesystem context or semaphore undo.
Exec prepares its detached annotation owner before the kernel call. The confirmed
exec event commits that owner and removes close-on-exec entries before transferring
the executing nonleader's resources. Failed exec does not change the owner.
Fork copies annotations at its actual birth event and releases the turn before
waiting for vfork completion. `close_range` with CLOSE_RANGE_UNSHARE uses the same
prepare/commit/rollback transaction as `unshare(CLONE_FILES)`, then applies its
range operation only after kernel success. Ordinary close_range, close and
descriptor-flag calls use their actual results without emulating native data IO.

## Boundaries

Concurrent named environments and launch-local attachments are not Linux
namespaces. `CLONE_NEWNS`, `CLONE_NEWUSER`, `CLONE_NEWIPC`, `CLONE_NEWUTS`,
`CLONE_NEWPID`, `CLONE_NEWNET`, cgroup/time namespaces and `setns` are not
implemented. Their creation is not reported as successful. General guest
mount mutation and user-namespace mappings require
their own resource and authority contracts.

This resource model does not establish security isolation from Android, other
launches or peer guest processes. Programs retain the executor's host authority;
successful browser execution is not proof of complete sandbox equivalence.

## Verification

With `MAGICDESK_GUEST_FIXTURES=ON`, `test_task_resources` checks independent
ownership, transaction rollback, retained-root copies and descriptor leaks.
Its `test_fd_origins` cases cover descriptor replacement, unknown origins,
close-on-exec flags, ranges, cwd/root independence, all CLONE_FS/CLONE_FILES
combinations and lifetime past task/registry removal. Allocation-failure injection
checks each preparation step and allocation-free publication; concurrent readers
check coherent origin/flag pairs. An annotated pipe must still reach EOF.
Ordering checks cover shared versus copied queues, middle/tail cancellation,
running cancellation awaiting completion, successor handoff, request reuse and
table lifetime after all task owners exit, with allocation failure enabled.
Three independent event loops exercise 3000 publications and concurrent
cancellation; saturated wake descriptors and owner-loop teardown retain correct
handoff. Exchange tests check actor/table binding, owner loss, malformed receipts,
preparation failure and allocation-free publication.
`resource_guest` compares native Linux and Shroot cwd/umask/FD semantics,
failed-unshare rollback, close_range splitting/marking and exec inheritance. Guest-only cases check proc-root
sharing, native descriptor mutation after proc-root restriction, 32-bit fcntl
command semantics and semaphore-undo splitting, final-owner cleanup and exec retention.
Pipe acknowledgements order observations; an alarm is only a failure bound.

`fd_handoff` exercises native kernel publication under the selected executor,
not Shroot emulation. A real CLONE_FILES peer replaces a slot with another open
description of the same inode before a split notification reply and before an
SCM_RIGHTS receiver acknowledgement. The atomic-delivery case permits receiver
replacement before later metadata work. Signal cancellation checks the installed
FD left by split delivery and the untouched destination after cancelled atomic
delivery. O_PATH rejection and descriptor cleanup are checked separately.
Positive cases feed a competing dup3 notification into the file-table queue
for atomic ADDFD_SEND and SCM_RIGHTS delivery. They verify physical descriptor
identity before allowing replacement and publish the exact source/replacement
origins in order. The fixture's acknowledgement follows the actual dup3 result;
production publication follows its syscall-exit event, not notification SEND
success. These cases do not establish complete mutation interception in Shroot.
Receipt cases let a real CLONE_FILES receiver exit immediately after recvmsg,
without an ACK or sending FD numbers. The survivor observes the terminal event
and publishes from retained kernel output: no delivery, one/two FDs and truncated
delivery. Kernel flags, shared file position, origins and leaks are checked.
Socket acknowledgements establish ordering without sleep or scheduler races;
alarms and parent-death termination bound fixture failure. `test_resources.py`
runs this alongside the model and intercepted guest checks.

`root_guest` runs the same checks with inode-backed and attached-native roots:
nested roots, absolute symlinks, root-clamped traversal,
unchanged inherited descriptors, failed-change rollback, CLONE_FS with and
without CLONE_VM, unshare and exec in ordinary/nondumpable tasks. Model checks
add root rename, enumeration, authenticated task snapshots, mount-table filtering,
nested readonly/writable attachments and retained covered-directory descriptors.
They also alternate two task mount views on one worker, check independent readonly
policy and mount-table output, retain snapshots past registry teardown, and check
coherent identity/root/mount publication under concurrent readers and writers.
Request-context checks retain authentication and roots across registry replacement
and teardown, reject actor/peer substitution, preserve captured credentials across
real/effective access checks, and commit chroot only to the captured filesystem
owner. `test_rpc` replaces the authenticated task record immediately before
dispatch: the first creation retains its original owner, the next sees the new
owner, and an unknown actor cannot create a file. Both retained mount views keep
their original readonly policy after task and registry teardown.
`test_mount_copy` checks distinct IDs, explicit native/inode root rebasing,
independent readonly policy, moved covered directories and source-view teardown.
RLIMIT_NOFILE exhaustion at every descriptor-acquisition step checks rollback
without leaks or changed outputs. A populated source cache does not grow copy
cost; pipe EOF and flock/OFD-lock release remain observable with both views alive.
`test_fs_anchor` checks old origins against copied trees with different policy,
absolute/relative links, nested parent traversal, openat2 constraints, cross-view
link/rename rejection and root restoration. It also checks inode/native mount IDs,
reopen, FD-number reuse with another inode, rename, source-view teardown, completed
FIFO identity/EOF, flock/OFD-lock release and EMFILE capture cleanup. These are
engine checks, not guest namespace-creation tests.
`test_mount_alias` constructs a candidate view with one source at writable and
readonly targets. It checks both opening orders, distinct stable object IDs,
image identity, retained opens after unlink, ambiguous unannotated descriptors,
root capture and copied-root policy. It also checks invalid origins and descriptor
cleanup. This internal fixture does not enable duplicated-source launch admission.
`test_root_userspace.py` exercises stock Debian/Alpine chroot with each
distribution's dynamic loader, shell and nested exec in disposable inode-backed
and attached-native directories.

`test_resources.py BUILD --compare-installed` stages a disposable store under
the selected shell UID and compares the same static metadata/spawn fixtures
against the installed runtime. Uninstrumented samples alternate execution order;
opt-in counters are separate runs. Reports preserve both timings and operation
counts without treating scheduler variation as a throughput guarantee.
