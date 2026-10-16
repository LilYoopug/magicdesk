# Namespace Providers

[Native architecture](README.md) | [Resource model](process-resources.md)

UTS, IPC, PID/proc, logical filesystems, terminals and permissive cgroups. These userspace contracts do not grant host kernel namespace authority.

- [UTS And IPC Ownership](#uts-and-ipc-ownership)
- [PID and Proc Views](#pid-and-proc-views)
- [Logical Filesystems](#logical-filesystems)
- [Limited Mqueue Mounts](#limited-mqueue-mounts)
- [Private Terminal Views](#private-terminal-views)
- [Permissive Cgroups](#permissive-cgroups)

## UTS And IPC Ownership

`uts_namespace` owns the guest hostname and domain name. `--hostname` initializes
that owner once; fork and exec retain it. `uname`, `sethostname` and
`setdomainname` use the same owner, including nondumpable callers through the
shared adapter-buffer lease. Mutations require CAP_SYS_ADMIN in the owner's user
namespace. Android's hostname and domain name are not modified. The hostname,
domainname, ostype, osrelease and version proc sysctls use typed control files.
Each IO selects the caller's current UTS owner, including an FD inherited before
unshare. Sysctl DAC uses canonical global IDs; namespace CAP_SYS_ADMIN does not
override that check. Hostname/domainname support partial reads and strict string
writes; the other fields are read-only.
The same sysctl provider exposes the read-only UID/GID overflow values used by
namespace consumers; it does not read Android's global sysctl as guest policy.

UTS providers retain a `control_event` generation source with an independent
cursor for each open. Dup references share consumption; namespace copies share
the notification sources while retaining distinct names. Reading does not
acknowledge a change: provider readiness does, following
[Linux proc_sys_poll](https://github.com/torvalds/linux/blob/v5.15/fs/proc/proc_sysctl.c#L580-L625).
Wake eventfds are allocated only when observed. Publication, acknowledgement
and subscriber retirement use one source lock; pending generations coalesce
without per-event allocation. Sysctl placements and unopened provider prototypes
have no carrier FD. Concurrent captures of one open publish a single sealed
carrier, while independent opens retain different carrier identities.

`control_epoll` is a typed open-description authority and virtual-interest
collector used by selected guest queues. Existing file tables, duplication, copied/shared tables and queued
local message vectors retain that same authority; it has no parallel alias
registry and retains no duplicate of the application's native epoll descriptor.
Its constructor allocates metadata only. The first successful virtual ADD
publishes its wake transport, whose descriptor remains stable through an empty
interest set until final authority release. Failed cold admission releases the
unpublished transport. The owner keys registrations by
retained open-description identity plus registering FD. Native kernel epoll
registrations and application event data remain untouched, including equal data
values. Virtual events are collected into a separate result slice through a
bounded ready queue. Level, edge and one-shot interests share provider readiness;
exclusive and wake-lock requests return an explicit unsupported error.
The enclosing descriptor custodian supplies confirmed OFD retirement, including
aliases and queued transfers. Registration references alone cannot determine it.
Cross-owner admission installs the selected queue's filters before activating
virtual interests. Exclusive-table mixed epoll and selected FIFO poll/select
reuse the task-affine native-wait owner, including signal delivery and cancellation;
the provider helper observes only virtual wake descriptors. Poll vectors borrow
contiguous slots from the existing mapped-buffer pool, while the file-table turn
ends before blocking. Native-only processes retain ordinary waits, including
`epoll_pwait2`, without supervisor stops. Shared-table epoll still uses its captured
host collector; it does not yet have equivalent caller-context signal coverage.
An interrupted caller-context wait collects already-ready virtual events before
returning EINTR. Collected events are delivered once; if none exist, signal
delivery retains the kernel-owned temporary mask without a ptrace mask rewrite.
The [FIFO contract](fifos.md) covers initial hangup suppression and transfer.

`ipc_namespace` independently owns lazy SysV semaphore/message and shared-memory
authorities. The initial namespace is store-scoped across launches; NEWIPC has a
fresh identity with separate keys and object lookup. Namespace destruction
retires its unremoved objects. A forked task shares the selected namespace;
NEWIPC and CLONE_SYSVSEM cannot be combined in clone. Unshare separates undo
ownership and releases old adjustments against the old authority.

Shared-memory mappings retain the authority that admitted them, independently of
the task's current IPC namespace. Unshare does not detach those mappings. Fork,
partial unmap, shmdt and address-space retirement account against each mapping's
original authority. Fork and exit batch database updates per authority, not per
mapping. No mapping copy or extra data path is introduced.

Namespace candidates are prepared before clone/unshare executes. A confirmed
kernel birth/exit event publishes them; failure retires only the candidates.
UTS and IPC owners retain their user-namespace authority. Internal identities
and IPC metadata use canonical IDs; ABI reads translate them into the caller's
view. `CLONE_NEWUSER` prepares a nested owner with immutable UID/GID maps,
irreversible setgroups denial and scoped capabilities. UID/GID map files retain
their target and opening credentials; write validates synchronously, including
parent authority and CAP_SETFCAP for mapping parent UID zero. Stat, ownership,
ACL, SysV and Unix peer/message credential boundaries translate canonical IDs.
Inherited mounts retain placement and readonly locks in a less privileged owner.

Proc control files share descriptor ownership, offsets, copying and cancellation
through `proc_file`. Their lazy selector is armed only in tables receiving those
objects. Local SCM_RIGHTS custody retains the same live object, including a
nondumpable receiver; queue discard releases it through worker-owned pipe EOF
observation. Cross-supervisor control-file transfer returns EXDEV, and an
unframed native peer is rejected before transfer. Ordinary filesystem origins
continue to use portable capsules that survive their publishing supervisor.
Exporting a graph does not prevent its owner from subsequently adding local
typed mounts. Such a change publishes an explicit unavailable revision:
foreign views return `EOPNOTSUPP` rather than traverse stale topology or a
provider's physical carrier. Local operations continue. Removing those providers
and publishing a complete portable graph restores foreign synchronization with
the same surviving mount identities. This is an explicit transport limitation,
not cross-supervisor support for private providers.
Selector collisions and the pre-sandbox all-FD selector preserve the original
syscall owner: ordinary `lseek`, `getdents64` and `fstatfs` return to the filesystem
adapter rather than bypassing directory cursors or mount metadata. Native data
IO remains native when no typed provider owns it.

User, mount, PID, UTS, IPC, network and cgroup namespace descriptors retain typed resource ownership,
not a process number or an Android proc-directory handle. Stat/statfs, readlink,
dup/reopen, `NS_GET_NSTYPE`, `NS_GET_OWNER_UID`, `NS_GET_USERNS` and `NS_GET_PARENT`
use that identity. Related user namespaces must lie within the caller's user
namespace; the initial user namespace has no parent. Related-FD publication
uses the same ordered descriptor installation as ordinary proc control files.
Local SCM_RIGHTS keeps namespace owners alive after the creating task exits.
The namespace directory enumerates the implemented user/mount/UTS/IPC/pid/pid_for_children/net/cgroup entries,
independently of the host's CONFIG_USER_NS. Directory positions belong to a
retained open description; dup/fork share it and rejected output copying does
not advance it. A directory whose process has exited returns ENOENT, while
already opened namespace handles remain usable.
Namespace files support path and descriptor bind mounts through the same mount
engine. `control_file` supplies the typed namespace reference and placement;
the supervisor captures proc sources without installing a temporary guest FD.
Mounts retain unplaced providers, while opened files retain their exact mount
origin. Stat/statfs, related-namespace ioctls, proc-FD reopening and `setns`
preserve authority after owner exit, move or lazy detach. Recursive binds retain
providers; ordinary unmount rejects live opens. A namespace copy omits mounted
mount-namespace files and their descendants. Binding a reference to the same or
an older mount namespace returns EINVAL, preventing reference cycles. Cross-
supervisor graph export rejects these live providers rather than flattening them
into native carrier files. Other control-file kinds are not implicitly mountable.
Process directories retain native entries and add exactly one UID map, GID map
and setgroups entry, with inode identities matching the corresponding proc files.
Enumeration builds a bounded lazy snapshot on that open description; ordinary
file IO and directory opens that are never enumerated do not allocate it.
Unmanaged host-process directories retain native handling.

`setns` selects these namespace kinds under the caller's file-table and FS
turns. User entry requires a single-threaded process with an unshared FS context;
reentry cannot replenish capabilities. Namespace-scoped authority is checked
before preparing a candidate. Mount entry resolves the selected namespace's
effective root and cwd on the filesystem worker, then publishes both with the
selected view. Failure discards the candidate. Old dirfds retain their original
view. IPC entry separates SEM_UNDO and releases adjustments against the old
authority. Pidfd-based multi-namespace entry is not implemented.

## PID and Proc Views

`pid_namespace` owns nested number spaces and process/thread identities.
The executor's native view is represented by NULL: ordinary launches allocate
no PID identity or PID-specific syscall filter. First namespace use installs a
thread-group filter through the existing adapter; inherited filters do not
change an ancestor's native PID view.

Clone reserves numbers before the kernel transition and publishes them at the
confirmed birth event without allocating. Failed clone retires its reservation.
For shared-memory clone, the stopped newborn publishes both parent- and child-TID
fields before either task returns to guest code. The parent remains event-parked
until publication or newborn death; it cannot rewrite a field after the kernel
has cleared it on child exit. Protected memory uses the existing task-affine
store adapter. Nonshared parent output stays with the parent. The same birth
boundary precedes guest-debugger notification.
Each task retains its TID identity, its TGID identity and the namespace selected
for future children. Unshare/setns only changes the last of these; the caller
does not move into its children's namespace. Entry is limited to the current
namespace and descendants, with user-namespace authority checks.

The kernel still owns process lifetime, process groups, sessions, signal queues
and child wait events. ABI translation covers PID/TID/PPID, parent-TID output,
wait4/waitid, signals, process groups, sessions, affinity/scheduling and selected
process-addressed operations. PID 1 uses an owned native child-subreaper to adopt
orphans. The guest-visible subreaper setting is independent of that requirement.
Admission fails explicitly if the required native operation is denied. The last
live thread of PID 1 closes the namespace and terminates its descendants;
another child cannot silently recreate PID 1 in that namespace.

Init signal policy preserves caught and blocked signals while ignoring ordinary
default-action signals. Same-namespace SIGKILL/SIGSTOP cannot terminate init;
an ancestor can. Group delivery runs in the actual sender, preserving kernel
credentials and pending-signal behavior. Wait/signal output maps sender numbers
and known guest UIDs; arbitrary SI_QUEUE payloads are not reinterpreted as host
identities. Protected output uses the existing task-affine memory access.

`task_registry` owns live and retired task records. Exit releases filesystem,
file-table and namespace execution resources, retaining only credentials, PID
identity and cgroup membership in the existing record. Retired records cannot
authenticate new worker requests. Proc observation distinguishes a retired guest
from an external native process, including without a virtual PID namespace;
native fast paths must not substitute Android credentials or cgroups.
Retirement and reaping allocate no objects. A separate intrusive retired list
avoids scanning live tasks during collection. PID-number ownership itself does
not retain credentials or filesystem resources.

Reaping removes lookup visibility independently of open pidfds.
Automatically reaped children are collected only when no pending native wait
result still needs translation. Collection is lifecycle-triggered, not polling.
Debugger notifications retain their own visible number and do not reap a child's
real-parent result.
Typed pidfds retain the process object through dup, fork and local SCM_RIGHTS;
they add no duplicate host descriptor. Signal checks and execution share the
file-table turn, so close/reuse cannot replace the checked target. Kernel
pidfd wait/poll semantics remain native. Nonleader exec retains the TGID and
publishes the former visible TID to the guest debugger before retiring it.

Unix connection and explicit-message credentials capture immutable TGID-number
snapshots using the same PID owner. They translate into the receiver's namespace
without consulting a potentially reused native PID. Unrelated namespaces see
zero; the native view keeps the actual PID. Native endpoints retain kernel
UID/GID checks. Tests cover connection/message snapshots after reaping and native
PID reuse, a threaded sender, inherited connections, and an external shell peer
with a nondumpable guest whose filter denies prctl.

A logical `proc` mount retains its selected PID namespace alongside mount
identity and policy. The filesystem walker resolves numeric process/thread
components, self and thread-self in that view. Enumeration filters native
entries and repacks names without assuming equal numeric widths. Native
directory cookies and the shared OFD turn retain seek and rejected-copy behavior.
The proc provider owns immutable `hidepid`, canonical exception GID and `subset`
options. Both mount APIs create it; bind and mount-namespace copies retain it.
`hidepid=1` keeps directory metadata but denies another process's contents;
`2` hides those directories, while `4` always requires inspection permission,
including for the exception group. `subset=pid` omits non-task root entries.
Traversal, directory reads and descriptor operations share the same policy.
Inspection captures only group identity, credentials and retirement state from
the registry, without allocations or unrelated resource pins. It checks fs IDs,
namespace-scoped CAP_SYS_PTRACE and effective capability coverage. Unprivileged
live peers also pass the native proc IO READ_FSCREDS check; retired guest tasks
use their retained credentials without reusing a dead native PID. Unknown host
processes do not acquire guest credentials. Policy-free proc views skip these
checks, and native file-data IO is unchanged. Filesystem-option remounts fail
explicitly; per-mount bind flags retain their separate contract.
Status/stat use typed per-open snapshots with guest IDs, credentials and debugger
relationships; seeking to zero refreshes the snapshot. A zombie remains visible
until wait consumes it. Namespace handles retain their owners after task exit;
opening pid_for_children before its first child returns ENOENT.
Zombie cgroup v2 observations retain the last membership and mark a removed
group with ` (deleted)`; v1 reports the hierarchy root. Exited members do not
populate `cgroup.procs` or prevent removal. Already-open membership files retain
the same provider independently of the task record.

Foreign `/proc/PID/root` access captures the selected task's retained root and
mount view after the process-access check. Traversal uses that root with the
caller's credentials; no temporary root FD enters the guest table. Opened roots
survive target exit and retain their view rather than resolving a reused PID.
Status/stat snapshots also apply to supervised processes in the implicit proc
provider, without requiring an explicit proc mount.

Foreign FD/cwd metadata and readlink use the same process-access policy. Native
magic-link capture retains the selected object across worker execution; socket
metadata is read from that FD rather than by replaying a reusable proc spelling.
Typed proc descriptors keep their logical provider metadata. Foreign executable
stat retains the guest image description for worker resolution, not the Android
bootstrap or a temporary descriptor installed in the caller.
Typed metadata uses the common `md_fs_info` representation. Providers with a
retained filesystem origin add its mount ID and mount-root attribute without
restatting their inert carrier or resolving a path. This applies to ordinary and
O_PATH descriptions, including dup and local SCM_RIGHTS transfer.

`O_NOATIME` on typed proc/control files is checked against the guest inode owner
or logical CAP_FOWNER, not the owner of an inert native descriptor. Open, reopen,
and F_SETFL retain that check; F_GETFL exposes the logical flags. Process
directories in explicit proc mounts use the same guest identity. Native attached
files retain native access checks. No additional ownership lookup is performed
for ordinary opens without O_NOATIME. `test_proc_policy.py` covers own/foreign
processes, inherited descriptors, mounted proc, and flag changes; this also
permits procps-ng versions that request O_NOATIME for ordinary process scans.

Current-process `fdinfo` captures the actual proc file in a private-table helper,
not a copy of the described application FD. Seeking to zero refreshes native
position, flags and close/reuse state. PID fields translate through the selected
logical proc namespace; a host without CONFIG_PID_NS can still supply logical
NSpid from the runtime's retained identities. Unknown native fields are preserved.
The typed read-only provider shares offsets across dup and preserves positional
reads. Foreign-process fdinfo remains explicitly unsupported.

Explicit mounts override the initial root's implicit proc/dev providers. Bind
source resolution can retain those providers through old-root descriptors after
pivot_root; unrelated directory aliases remain ordinary guest dentries. Nested
Bubblewrap can therefore construct a new root with `--proc /proc` and
`--dev-bind /dev /dev`, without borrowing host mount authority. `/dev` uses the
selected native devices and their real permissions, not a private device manager.
Guest device-node creation requires logical CAP_MKNOD and stores type/rdev in
the inode provider without native mknod. Supported character numbers use explicit
native endpoints; unknown numbers remain metadata-only and return ENXIO on data
open. Native attached directories reject device creation with EPERM.
The origin retains the logical carrier separately from endpoint identity, so
fstat, chmod/chown, reopen and transferred descriptors use guest metadata.
Callers may bind an existing native device onto a regular placeholder, including
through a retained proc-FD target. Native rdev, IO and access checks are preserved;
nodev rejects new opens without invalidating already-open descriptions.

## Logical Filesystems

Logical tmpfs uses a private transient inode store, not Android's kernel tmpfs.
It supports mode/uid/gid, ordinary file operations, shared native mappings,
namespace copies, bind policy and retained detached descriptors. Backing files
consume the store's disk space. `size`, `nr_blocks` and `nr_inodes` accept validated
numeric requests, including binary suffixes and percentages for size, under a
permissive allocation policy. They do not impose quotas or alter statfs capacity.
Writes, truncation and shared mappings retain native IO and backing-space errors.
Atime flags in legacy and descriptor mount APIs are compatibility hints: timestamps
follow the backing filesystem, not a new per-mount IO observer. Memory accounting
and strict timestamp policy are not provided. Nosuid, nodev and noexec are per-mount policies, independently retained
by aliases and frozen by less-privileged namespace copies.
Existing-name creation errors precede readonly rejection: mkdir on an existing
directory returns EEXIST, and a read-only O_CREAT open can select an existing
file without gaining write authority.

Bind operands can be exact retained files or directories, including proc-FD
aliases. Their mount provenance survives detach/rebind; selecting a regular
file does not substitute its parent directory. Named readlink on a non-link
returns EINVAL, including bind roots; empty-path descriptor readlink retains
ENOENT. A mount-root path is reconstructed from its covered dentry, independently
of ambiguous hardlink names in the backing store. Native proc/dev sources use the
task-local capture path. `mount_propagation` owns weak namespace-family
membership and retained peer/master ancestry. `fs_mount_propagation` prepares
attach/detach/move changes across peers and downstream slaves before publishing
them through the common topology stream transaction. Private changes do not
propagate upstream; unbindable mounts reject bind cloning. Namespace copies
retain or downgrade relationships according to user-namespace authority.
Local mountinfo resolves live masters through family membership. Foreign graph
snapshots still need complete master retirement after the last peer disappears.
Bind dispatch ignores unrelated mount flags rather than interpreting them as a
second propagation/remount operation; bind policy derives from the source.
New filesystem mounts discard `MS_REC` at the syscall boundary; recursive
semantics remain specific to bind and propagation operations.

Overlay builds an unpublished merged metadata index bottom-to-top.
Regular-file bodies retain source custody without copying. Names, hardlinks,
directory precedence and user/trusted whiteout/opaque markers select the merged
tree. Directory attributes come from the highest layer rather than a union of
attributes; overlay control xattrs are hidden through the merged view without
modifying lower bodies. Lower trees must remain unchanged while mounted.
Without an upper layer the resulting store is read-only and rejects writable
remounts. A writable mount reserves disjoint upper/work directories in the same
inode filesystem and retains them for the view's lifetime, including detached
FDs. The view and upper use a single SQLite transaction: name changes, copy-up
metadata, whiteout/opaque publication and rollback are not separate journals.
The upper namespace shares promoted regular-file bodies; old lower descriptors
retain their original contents. Channel identities preserve FIFO/socket traffic
through copy-up and remount. Lower/merged directory rename returns EXDEV;
pure-upper directories can be renamed. Upper namespace observers receive
committed create/delete events. External mutation of the lower or upper while
mounted is not a supported synchronization mechanism. An overlay view as the
upper filesystem is rejected; ordinary and transient inode stores are supported.
Mounting credentials are retained with the view and checked alongside current
caller permissions, including ACLs, metadata changes and upper sticky directories.
Custody transfer and worker reconnection preserve this snapshot and its namespace.
Denied publication rolls back merged/upper metadata together. Data IO through
already admitted native descriptors retains its existing kernel behavior.

Noexec admission applies to each executable, script interpreter and ELF loader,
including descriptor-based execution and mount aliases. X_OK on regular files
observes the same policy; directory traversal remains permitted. File-backed
mmap captures live mount policy under the file-table turn. PROT_EXEC is rejected
on a noexec mount, while a non-executable mapping retains its missing VM_MAYEXEC
permission independently of FD closure or later remount. Mprotect cannot restore
that permission. An earlier mapping from an executable mount keeps its original
rights, matching the kernel's per-VMA policy rather than a retroactive remount.

The address-space owner records only noexec intervals. Split/replacement, unmap,
remap and fork share its existing resource turn; successful kernel results
publish preallocated metadata. Failed calls preserve the old intervals. Ordinary
read/write and non-replacing anonymous mmap remain native, with no policy record.
File mmap is observed for live mount policy; executable mprotect and destructive
mapping calls enter the supervisor, but unrelated calls need no syscall-exit
observation. Adapter mappings use their admitted source through the existing raw
gate. If a task loses an unobserved noexec mapping result, surviving CLONE_VM
users receive EIO for subsequent executable mprotect rather than permission
based on an assumed rollback. A fresh exec owns a fresh address space.

## Limited Mqueue Mounts

`mqueue_view` is a lazy, worker-owned filesystem held by the task's IPC namespace.
Legacy mount and fsopen check CAP_SYS_ADMIN in that namespace's user owner;
fsopen captures it before later unshare/setns. Repeated mounts of the same IPC
owner share root inode identity and logical mode/ownership. Different IPC owners
have distinct instances. Mount copies, bind aliases and retained directory
descriptors keep the whole IPC namespace alive after the task leaves it.

The supported surface is directory enumeration, stat/statfs, chmod/chown,
mountinfo and ordinary readonly mount policy. POSIX queue creation and message
delivery are not implemented: all six mq syscalls report ENOSYS, regardless of
the host kernel's mqueue configuration. File creation through the mount reports
EOPNOTSUPP; no regular file or Android queue substitutes for a guest queue.
Cross-supervisor export is rejected. The initial namespace's mount metadata is
launch-local, not a shared POSIX queue service across independent launches.

The IPC namespace's atomic lifetime is independent of its lazy SysV services.
The shared task registry publishes retained IPC snapshots; services retain their
supervisor-side implementation and release callback. Mounting does not open a
SysV database. Final namespace release removes the private directory and its
native descriptors. Focused checks cover both mount APIs, namespace authority,
retained/copy/bind behavior and exact native FD cleanup.

## Private Terminal Views

`devpts_view` owns each mounted devpts directory and its logical uid/gid/mode
policy. Only terminals allocated through that instance's ptmx are resolved or
listed. Bind aliases and copied mount views retain the instance. Kernel slave
identity, not just its number, guards against index reuse. Closed terminals
disappear from directory results; the view retains no master/slave data FD.

Data, termios, readiness, EOF and terminal sessions remain kernel operations.
A slave open that may acquire a controlling terminal returns a deferred O_PATH
pin. The opening guest task completes the open through the existing captured
path and descriptor-publication turn; the filesystem worker cannot acquire the
terminal on its behalf. PID namespace terminal group/session ioctls translate
through the common PID owner; native permission errors are preserved.

This is a private name/membership view over native PTYs, not a kernel devpts
mount or a separate index allocator. It does not hide already inherited terminal
descriptions or explicit native `/dev` attachments. TIOCGPTPEER-created slave
descriptors currently retain native metadata rather than mounted-view
provenance. Cross-supervisor mount export fails explicitly for private devpts.

## Permissive Cgroups

`cgroup` owns a launch-local world with a cgroup2 hierarchy and a cgroup v1
`devices` hierarchy. Tasks retain membership independently of mount views;
fork inherits it, exec preserves it, exit removes live membership. Proc cgroup
paths use the reader's cgroup namespace; control-file PID lists use the caller's
PID namespace. Mounting the same hierarchy again retains its existing state.

`md_cgroup_namespace` separately retains a captured root for each hierarchy and
its creating user namespace. `CLONE_NEWCGROUP` snapshots the caller's membership;
`setns` changes the view without moving any member. Proc handles, namespace
ioctls, dup/fork/reopen and owner permissions use the common typed namespace
contract. A retained handle outlives its creating task. `/proc/PID/cgroup` paths
are relative to the reader's current namespace, including `/..` for members
outside its root. Existing mounts retain their roots; new mounts select the
captured group. `fsopen` retains the opener's cgroup namespace through later
configuration and descriptor transfer. Mounting requires CAP_SYS_ADMIN in that
namespace's owning user namespace. Removed roots cannot be mounted again.

`fs_cgroup` supplies directory operations and typed `control_file` objects.
The shared proc-control transport owns descriptor identity, IO ordering,
dup/fork/SCM_RIGHTS, shared offsets and reopen behavior. Live readonly mount
policy is enforced even through an already opened control. No cgroup data-file
daemon or periodic task scan is involved. Removal rejects populated groups and
releases backing directory descriptors; retired logical metadata remains until
the launch world is released, allowing open controls to return ENODEV.

The v2 hierarchy advertises pids. Subtree control enables child pids files,
respects the no-internal-process rule and refuses disabling a controller still
enabled below. Removed controls invalidate retained FDs even after re-enabling.
`pids.max` retains a nonnegative integer or max; `pids.current` counts live threads
recursively on read; `pids.events` reports max 0. These values are permissive
compatibility state, not enforced limits. Fork/exit retain the existing membership
bookkeeping without a second counter or periodic scan. CPU/memory/IO limits and
freezing remain unavailable. The v1
devices list is always `a *:* rwm`; all-device allowance is accepted, restrictive
rules are rejected. Unsupported controller enabling, freezes and release agents
return EOPNOTSUPP. This interface never accesses Android's cgroup hierarchy or
provides a resource/security boundary. Administrative delegation and
independent-supervisor hierarchy transfer are not implemented.

`cgroup_program` owns launch-local logical BPF program IDs, descriptors and
cgroup2 device attachments. `namespace_bpf` captures the bounded syscall ABI;
`fs_bpf` executes through the existing filesystem worker and typed control-FD
transport. Loading, lookup by ID, information queries, multi-attach, detach and
direct/effective queries share the cgroup owner. Descriptor and attachment
references independently retain a program; the registry is weak, so closing
the final FD after detach removes its ID. Removing a group releases its
attachments. Retained targets respect live readonly mount policy.

Admission accepts at most 4096 forward-only instructions from a limited
arithmetic/branch subset, with device-context field reads for CGROUP_DEVICE.
CGROUP_SKB accepts the same arithmetic subset without packet access, but
network attachment returns EOPNOTSUPP. Loading is separate from attaching;
neither action installs a host BPF program. Maps, helpers, loops, JIT/BTF
exports, pinning, replacement and other attachment types are unavailable.
Unavailable bpf commands return EINVAL, as for Linux command feature probes;
unsupported operations within recognized commands fail explicitly.

Device attachments are bookkeeping in the **permissive** provider, not an
executed predicate or enforced device restriction. Native Android access
denials remain unchanged. No per-IO accounting, host BPF capability, background
worker or runtime dependency is added. Programs and attachment arrays are
allocated only when requested, with limits of 4096 live programs per launch
and 64 direct attachments per group.
