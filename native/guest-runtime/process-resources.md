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
transports capture identity, root, cwd origin, mount view and descriptor-origin
table in one authenticated registry snapshot. The file-table handle remains live;
it is not a frozen copy of its entries. A missing task mount view fails explicitly; the worker's
initial view is not a fallback for another task.
See [namespace execution](namespace-execution.md) for the launch filesystem and
[interception](interception.md) for restricted domains.

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
open-file-description identity. There is no mirror of ordinary data descriptions
or new interception of close/read/write.

Cross-view relative IO works, but path/image-path publication for an origin in
another tree returns ENOENT instead of inventing a current-root path. Changing
the task root through such an origin is unsupported. Native object-ID requests
still reject conflicting aliases of one backing inode within a view; the object
cache is not a replacement for explicit origin tracking. These limits remain
separate from the working engine traversal contract.

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

These are owner/lifetime contracts, not automatic guest-FD tracking. Guest opens,
dup/fcntl/close, received SCM_RIGHTS and cwd changes do not yet populate these
annotations. Initial inherited descriptors, FD-number reuse, concurrent kernel
mutations by CLONE_FILES peers and transfer provenance need transport integration
before copied guest namespaces can be published. The metadata lock does not
order kernel syscalls or prove which description occupies a live FD number.

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
There is no supervisor mirror of every descriptor or new interception of
ordinary close/read/write operations.

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
The confirmed exec event detaches the corresponding annotation owner and removes
close-on-exec entries after any nonleader resource transfer. Failed exec does
not change that owner. `close_range` with CLOSE_RANGE_UNSHARE uses the same
prepare/commit/rollback transaction as `unshare(CLONE_FILES)`, then applies its
range operation only after kernel success. Ordinary close_range, close and
descriptor-flag syscalls retain their existing interception policy; complete
annotation maintenance is not enabled.

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
`resource_guest` compares native Linux and Shroot cwd/umask/FD semantics,
failed-unshare rollback, close_range splitting/marking and exec inheritance. Guest-only cases check proc-root
sharing and semaphore-undo splitting, final-owner cleanup and exec retention.
Pipe acknowledgements order observations; an alarm is only a failure bound.

`root_guest` runs the same checks with inode-backed and attached-native roots:
nested roots, absolute symlinks, root-clamped traversal,
unchanged inherited descriptors, failed-change rollback, CLONE_FS with and
without CLONE_VM, unshare and exec in ordinary/nondumpable tasks. Model checks
add root rename, enumeration, authenticated task snapshots, mount-table filtering,
nested readonly/writable attachments and retained covered-directory descriptors.
They also alternate two task mount views on one worker, check independent readonly
policy and mount-table output, retain snapshots past registry teardown, and check
coherent identity/root/mount publication under concurrent readers and writers.
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
`test_root_userspace.py` exercises stock Debian/Alpine chroot with each
distribution's dynamic loader, shell and nested exec in disposable inode-backed
and attached-native directories.

`test_resources.py BUILD --compare-installed` stages a disposable store under
the selected shell UID and compares the same static metadata/spawn fixtures
against the installed runtime. Uninstrumented samples alternate execution order;
opt-in counters are separate runs. Reports preserve both timings and operation
counts without treating scheduler variation as a throughput guarantee.
