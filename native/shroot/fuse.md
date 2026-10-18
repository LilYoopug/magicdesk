# Guest FUSE

Shroot provides FUSE as a native guest filesystem adapter. A stock guest daemon
opens `/dev/fuse`, negotiates the Linux wire protocol and serves ordinary guest
mounts. Android's real FUSE device and kernel mount permission are not used.
The selected executor identity, namespace owner, DAC, Landlock and mount policy
remain authoritative. This adds no persistent store format or APK dependency.

## Ownership

- `fuse_device` owns the typed character device and daemon IO. Final device
  closure aborts pending operations instead of leaving a sleeping worker.
- `fuse_transport` owns bounded requests, unique IDs, replies, cancellation and
  notification delivery. Completion callbacks run outside the connection lock.
  Invalidation handlers run under that lock to serialize context teardown;
  they only update view state and never call back into the transport.
- `fuse_session` owns INIT negotiation, credentials and advertised capabilities.
- `fuse_view` owns node IDs/generations, names, attributes and mount operations.
  Carrier names do not consume one retained host FD per node.
- `fuse_file` owns each open handle, IO and release. `fuse_image` prepares sealed
  private images for mmap and executable admission.
- `watch_source` supplies bounded provider events to the existing `inode_watch`
  owner. No listener, event descriptor or event record is allocated until a
  guest watches that provider. Native and journal-backed watches retain their
  existing paths.
- `fs_continuation` and the existing filesystem worker own suspended operations.
  Captured operands remain valid across daemon waits. Mutations are not replayed
  after partial completion, and no store transaction or FD-table turn spans a
  guest daemon wait.

Namespace clones and bind mounts retain the provider. Lazy unmount removes its
placement but preserves open descriptions. Last-anchor release schedules mount
collection on the filesystem event loop; ordinary workloads need no periodic
collection. The provider closes only when its remaining owners are gone.

## Protocol and Policy

The offered protocol ceiling is 7.31; negotiation accepts compatible older
daemons down to minor 12. Unsupported capabilities are not advertised. Request
queues are bounded at 256 requests and 8 MiB; a packet cannot exceed 1 MiB.
File IO is chunked at 16 KiB. Queue saturation returns an explicit error.

Regular-file `read`, `pread` and their vectored forms retain one OFD turn across
transport pages. A full packet is not a short syscall result: the adapter keeps
copying until the requested count, EOF, a short daemon reply or an error. Only
confirmed bytes advance the cursor; positional reads leave it unchanged. A
signal or copy failure after a delivered prefix returns that prefix instead of
restarting the syscall. Devices and directory records keep their separate packet
semantics; ordinary native-backed files never enter this path. Suspected EOF is
checked against fresh daemon attributes rather than a stale cached size, while
`FOPEN_DIRECT_IO` leaves EOF to the daemon.

The adapter implements lookup/attributes, regular files/directories/symlinks,
creation, rename, links, removal, xattrs, data IO, directory iteration, truncate,
sync and statfs. Daemon errors propagate. Mounts enforce owner/allow_other and
default_permissions, and are always nodev/nosuid. Private executable mappings
and execution still enforce noexec; guest FUSE cannot create a host set-ID path.
INVAL_INODE, INVAL_ENTRY and DELETE notifications invalidate relevant state.
Positive names and attributes honor the daemon's independent protocol TTLs.
Names are indexed by parent/name; per-node links retain path and open-description
identity through rename/unlink. Deadlines start at request submission, and a
reply crossing a mutation or invalidation cannot renew a stale lease. Zero or
malformed TTLs do not enable caching. No timer thread or persistent index is used.

Cached metadata never caches an authorization decision: every access uses the
current credentials, mount policy and daemon connection state. Mutation checks,
append size queries and executable/private-image validation still fetch fresh
attributes. Ordinary reads still reach the daemon; no content cache is added.

## Append and Notifications

Append uses current OFD flags, including changes made by `F_SETFL`, and a fresh
daemon size query. Writes, descriptor truncation and truncating opens share a
lazy per-inode queue across independently opened descriptions. An accepted
operation retains its inode turn until the daemon replies, even if its original
guest task exits. The descriptor owner's turn and cursor likewise survive an
abandoned write; a later operation cannot overtake its effects. Partial writes
advance only by accepted bytes. Positional append follows Linux's `O_APPEND`
behavior without changing the OFD cursor. No global filesystem lock spans a
daemon wait, and unrelated files continue independently.

Inotify reports successful guest operations, not attempted requests: create,
open, copied file/directory reads, write, attributes, close, unlink and paired rename events.
Open descriptions retain their dentry through rename/unlink; inode watches
survive unlink until final descriptor closure. `IN_EXCL_UNLINK`, one-shot masks,
duplicate-watch handling, queue overflow and provider teardown are covered.
`O_PATH` retains that lifetime without manufacturing open/close events. Invalidation alone is not a
mutation event; a daemon's DELETE notification is. Changes to a daemon's backing
files outside the FUSE mount cannot be inferred without protocol notification.

Each listener queues at most 16,384 provider records and reports overflow rather
than growing indefinitely. Object-indexed interests filter masks and unlinked
names before queue allocation; unrelated provider traffic cannot fill the queue.
Unmount notification is retained separately so even
an overflowing queue eventually retires its watches. Provider event storage is
ephemeral and does not change format 17 or create persistent journal traffic.

## Mapping Limits

MAP_PRIVATE and executable images use sealed snapshots, not a coherent Linux
page cache. Preparation checks attributes again after copying; detected changes
fail with EAGAIN. A new mapping revalidates metadata and the invalidation epoch.
Cancelled preparation has not published an application mapping and explicitly
permits retry after signal delivery, including handlers without SA_RESTART.
Its internal daemon wait must not make the loader's mmap return EINTR.
The kernel delivers signals normally; accepted writes and ioctls do not acquire
this repeatable-preparation property. No file-table or memory
turn remains held while a stopped daemon is awaited.
When a provider finishes before the synthetic wait enters the kernel, its
cancelled syscall is drained through the exit stop before adapter registers are
restored. Otherwise a later seccomp/kernel return can overwrite a successful
provider result. The same completion owner covers open and close waits; ordinary
native-backed IO does not use this state.
Existing private mappings do not follow later daemon writes. Same-size writes
without observable timestamp changes or invalidation cannot be inferred.
Safe sealed snapshots use the common task-local mapping/FD-loan path described
in [shared memory](shared-memory.md#read-only-anonymous-views). They need no new
helper thread inside an application's seccomp sandbox.

MAP_SHARED remains unsupported and returns an error.
INTERRUPT and DESTROY protocol requests are not yet implemented; closing
the connection is the final cancellation boundary. Node metadata is bounded at
65,536 entries per view, retained until provider teardown rather than managed
by a kernel-style dentry eviction policy. Private images consume memory backing
proportional to the copied file. Cross-independent-launch provider transfer is
not supported. This is a useful subset, not full kernel FUSE compatibility.

## Descriptor Closure

Confirmed descriptor retirement is separate from reference release and cancelled
publication. Each closed alias issues `FLUSH`; final description release issues
`RELEASE`. Explicit `close` returns the daemon's error after releasing the native
FD slot. `dup2/dup3` replacement and `close_range` wait for completion but ignore
flush errors. No FD-table turn spans a daemon wait, so another thread can reuse
the number immediately. An interrupt returns without replaying the native close;
the queued flush retains its own description until reply or connection teardown.
An `ENOSYS` reply disables subsequent flush requests for that connection, as in
Linux. Ordinary native objects do not acquire provider requests or waits.

Exec retires CLOEXEC aliases before the new image resumes, including a nonleader
thread replacing its group leader. Normal exit relinquishes the task's shared
table ownership after continuation from its terminal stop; the virtual debugger
receives `PTRACE_EVENT_EXIT` before file retirement, as in Linux. The last owner
completes FLUSH before becoming waitable. Neither barrier requires guest-memory access or an injected
wait in the new image. Fatal termination abandons waiting but retains accepted
terminal requests through reply or connection teardown.

## Verification

Native fixtures cover wire validation, queue bounds, device closure, deferred
worker progress, metadata/mutations, failed publication, cancellation, snapshot
invalidation, independent metadata TTLs, late replies, indexed-name collisions,
rename exchange, cancelled-write cursor ownership, bounded watch overflow and
carrier FD limits. `test_fuse.py` exercises installed stock
clients in a private runtime under Android UID 2000:

- `rofiles`: mutations, concurrent append, `F_SETFL`, positional IO, inotify
  lifetimes and daemon-wait cancellation. Ordinary operations use stock cache
  TTLs; a separate zero-TTL mount verifies actual daemon waits across
  SIGSTOP/SIGCONT, descriptor reuse and daemon death.
- `portal`: stock document export, Flatpak read/write and live revocation.
- `squashfs`: concurrent reads, ELF/script execution, shared-library loading,
  private mmap interrupted by non-SA_RESTART signals with a stopped daemon,
  completion/signal races across independent opens, 2048 repeated mappings under
  a seccomp filter rejecting invalid syscalls, noexec and a file retained through
  lazy unmount. The filter catches early-wait completion that restores registers
  before the cancelled syscall has actually exited.
- `close`: controlled daemon errors, delayed replies, shared FD-table reuse,
  signals, caller death, replacement/range closes, debugger/exec/exit barriers and the
  connection-scoped unsupported-operation cache, with and without a guest filter.

`test_snap.py` separately boots stock systemd and snapd in a disposable Debian-like
store and requires install, run, refresh and removal of hello-world or Firefox.
Firefox must render a known page and produce the expected PNG pixel; successful
namespace construction alone is not an application pass. It uses a
shared root mount before snapd creates image mounts, as required by its
mount propagation. The fixture launcher establishes that topology; it does not
patch snapd or suppress unmount errors. Hello-world also passes under strace;
Firefox is tested without tracing, which heavily perturbs cold namespace setup.
`--app-launches N` requires a fresh profile and validated image on every launch.
The complete application log is retained and checked for loader and child-process
failures: browser recovery must not conceal a failed subprocess behind a good PNG.
A refresh with no available update verifies the refresh command,
not migration to a different snap revision.

`--namespace-only` measures one fresh confined-shell launch per boot; it retains
the snap for another independent boot. `--snap-file PATH` can use a cached
official image with normal signature checks when the external store is
unavailable. `--cold-launch-checks N` also exercises repeated launches within
one boot, with namespace-start/finish markers separate from total elapsed time.
Real cgroup population events let systemd retire completed scopes; freezing
genuinely live tasks remains separately unsupported.
Current snapd can warn about that freezer during removal even when removal and
the mount-cleanup assertions succeed; this is not advertised as freezer support.

Init fixtures mount private `/tmp` and `/var/tmp`, as well as `/run`, before
booting systemd. Its tmpfiles cleanup must not remove another launch's compiler
files. The libc builder additionally exports a temporary directory under its
own explicitly bound work directory.

The Snap fixture's `--libc-registry PATH` selects prepared replacements and
requires a dynamic entry-ABI/IO probe under the booted init. This checks the
Ubuntu userland, not every snap's private libc. Snap images select their own
matching libc, and unprepared or static binaries retain Base.

Testing Snap is not evidence of AppArmor confinement: the tested Android kernel lacks
AppArmor, and snapd reports its own reduced confinement capabilities. No
application sandbox is disabled to make a test pass.
