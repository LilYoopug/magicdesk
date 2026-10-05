# Process Resources

`task_resources` owns independently shared guest state in the supervisor.
Its lifecycle follows successful kernel process/resource transitions, not
Android Activities, named environments or launcher configuration.

| Resource | Clone sharing | Unshare | Exec |
| --- | --- | --- | --- |
| Filesystem context | `CLONE_FS` | `CLONE_FS` | Retained |
| Mount view | Shared independently of `CLONE_FS` | Namespace creation unsupported | Retained |
| Descriptor table | `CLONE_FILES` | `CLONE_FILES` | Kernel detaches it |
| Semaphore undo | `CLONE_SYSVSEM` | `CLONE_SYSVSEM` | Retained |

The kernel owns cwd, umask, descriptor tables and open-file descriptions.
The filesystem context owns guest root selection and the admitted proc-root
restriction. `task_registry` pins that context alongside each task's identity;
registry references do not count as CLONE_FS owners. Both filesystem request
transports capture identity, root and the retained mount view in one authenticated
registry snapshot. A missing task mount view fails explicitly; the worker's
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

Candidate construction is not guest CLONE_NEWNS. Existing descriptors and cwd
need their own origin contract before a candidate can replace a task's view.
An old descriptor must not be reassigned by looking up its inode or current path
in the new tree. Exact description comparison does not solve lifetime ownership:
retaining a readable/writable comparison FD would keep FIFO peers and file locks
alive. Guest namespace creation still fails explicitly.

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
`resource_guest` compares native Linux and Shroot cwd/umask/FD semantics,
failed-unshare rollback and exec inheritance. Guest-only cases check proc-root
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
`test_root_userspace.py` exercises stock Debian/Alpine chroot with each
distribution's dynamic loader, shell and nested exec in disposable inode-backed
and attached-native directories.

`test_resources.py BUILD --compare-installed` stages a disposable store under
the selected shell UID and compares the same static metadata/spawn fixtures
against the installed runtime. Uninstrumented samples alternate execution order;
opt-in counters are separate runs. Reports preserve both timings and operation
counts without treating scheduler variation as a throughput guarantee.
