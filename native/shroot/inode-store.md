# Inode Store

The inode store is the runtime's hierarchical namespace model, **not a kernel
filesystem or mount namespace**. It represents shared-inode links under the
shell SELinux hard-link restriction without copying data, claiming host links,
changing identity or special-casing dpkg.

- [Ownership](#ownership)
- [Paths And Directories](#paths-and-directories)
- [Directory Cursors](#directory-cursors)
- [Offline Import](#offline-import)
- [Transactions](#transactions)
- [Checks](#checks)
- [Limits](#limits)

## Ownership

Each object has a current ordinary native file, empty directory or symlink backing.
Immutable image bodies can be shared through explicitly retained source directories;
writable instances promote regular files on mutation. Names and directory parent edges refer to objects through
SQLite. Adding a name does not copy or move the object.
Within one current backing, descriptors opened before and after linking share the actual kernel device/inode,
data, mappings and file locks. Data IO, mmap and descriptor duplication stay native.

`md_inode_stat/fstat` combine native data attributes with logical UID/GID/mode,
stable logical device/inode identity and the namespace's transactional link
count, including zero for an open, unlinked object. Socket inodes expose S_IFSOCK
while their transport is an abstract kernel endpoint; their backing regular file
supplies permission and identity metadata. Raw host fstat still sees the
backing object's native links and directory contents. Concealing that distinction
from arbitrary guest code
would require complete mediation of every filesystem entry point; Shroot does
not provide that security boundary.

Each connection has one owner and is reopened after fork/exec. SQLite is linked
only into native namespace owners and fixtures, not the freestanding bootstrap
or in-guest syscall adapter. Its heap use and locks belong to the worker. The separate
[filesystem service](filesystem-service.md) supplies explicit RPC,
native FD transfer and bounded reentrant client waits. The explicit
[namespace executor](namespace-execution.md) routes selected guest syscalls here;
a timeout is not cancellation of a committed operation.

`inode_db.c` owns transactions, allocation, identities and metadata queries;
`inode_path.c` resolves paths and reconstructs directory paths;
`inode_cache.c` owns bounded metadata caching and row-dependency invalidation;
`inode_store.c` defines namespace operations, `inode_directory.c` implements
directory cursors, `inode_socket.c` implements socket publication and address
lookup, `inode_metadata.c` owns guest permissions and metadata mutations, and
`inode_acl.c` and `inode_capability.c` own logical security attributes;
`inode_import.c` imports prepared trees. `inode_snapshot.c` owns
immutable-source snapshots; `inode_backing.c` owns source validation and copy-up.
`inode_reserve.c` owns durable allocation inventory; `inode_durability.c` owns
native data barriers and the metadata checkpoint boundary.
`inode_view.c` owns retained namespace projections within one store transaction
domain; `inode_maintenance.c` collects untracked backing objects only under
exclusive maintenance or before a store is published.
Their private contract is in
`inode_internal.h`. Callers use the explicit dirfd-based `inode_store.h` API.
The internal database format is versioned and incompatible formats are rejected,
not migrated. Format 16 uses WAL and includes durable allocation inventory,
scoped namespace views, logical owners/modes, POSIX ACLs, file capabilities,
unambiguous file-path history, stable identities, backing history,
immutable sources, socket addresses, FIFO ownership, device type/rdev, transactional namespace
counters and the [watch event journal](watches.md). Incompatible stores require a separately prepared store; opening
one never rewrites or deletes it. Bind retains a name until
unlink, including stale listeners; existing connections survive unlink/rebind.

Each retained view selects its own root and physical-to-logical inode mapping.
Different views can share a native body without aliasing their logical metadata;
copy-up retains old descriptor identity within the originating view. Roots in
the same store share one SQLite transaction and one short-lived object-directory
gate. There is no second database journal for projection publication.
Projection roots carry independent kernel leases through local references and
SCM custody. Collection removes an unleased projection's metadata; native bodies
remain while other stores may retain source leases. Exclusive maintenance
collects bodies only after metadata retirement has committed and checkpointed. Normal open/stat
does not run collection or allocate a view selector. Writable overlay uses a
connection-local mutation journal to publish its merged and upper names within
the same transaction. Upper/work reservations remain held by detached views
until their last descriptor or origin releases custody.
Each view has its own bounded lower-source catalogue. Retiring a view releases
that catalogue instead of consuming source slots in the persistent instance.
Upper/work reservations share the metadata transaction and retained projection
lease. A dependent view retains its referenced parent metadata; collection
retires children before parents. Reconnection and object-ID access preserve the
selected scope, including after sender closure and queued SCM transfer.

Overlay whiteout/opaque attributes are transactional metadata, including explicit
tombstones that mask native attributes. Ordinary xattr operations and logical
ACL/capability attributes execute through the same typed inode operation; backing
FDs do not escape for a second, detached xattr mutation. Overlay views hide private
control attributes. Directory attributes come from the selected layer.
Character-device `0:0` whiteouts and regular-file whiteout xattrs use the same
merge policy. They hide lower names and are not exposed by merged enumeration.

An overlay retains the mounting identity, supplementary groups and owning user
namespace independently of the mounting task. Access checks apply both caller
DAC/ACL and the saved identity's underlying-layer permissions. Copy-up requires
read access to the lower body; upper-name changes check directory and sticky-bit
permissions before publication. Metadata, ACL and capability changes use the same
typed authorization helpers as ordinary stores. A sealed credential snapshot
travels with cold custody transfers and reconnects; ordinary file IO does not
serialize credentials or allocate an identity. Native SELinux checks remain in
force. This is not kernel-equivalent confinement of unadapted syscalls.

FIFO and pathname-socket channels have identities separate from a view's logical
inode. Copy-up and remount retain the channel, including a lower from another
store. FIFO pin custody and rendezvous remain with the creating store; projected
opens publish their local inode association without holding two store transactions.
Attached FIFO custody borrows its store's lifetime. Only detached custody retains
an independent lease, so an idle connection cannot keep its own overlay mounted.
Snapshots create fresh FIFO channels. Regular files do not use channel lookup.
Successful upper-name publication emits the same committed directory events as
ordinary inode operations; rollback does not notify an uncommitted name.

Character/block devices use regular metadata carriers, never host `mknod`.
Guest CAP_MKNOD authorizes creation; ordinary permissions, Landlock and mount
policy apply. Snapshot, overlay copy-up, hardlinks and archive backup retain
type/rdev. Metadata refers to the logical carrier even after data open returns
a native endpoint. A retained origin carries both identities through dup,
proc-FD reopen and cold SCM transfer, including after unlink or sender exit.
`file_open` maps supported character-device numbers to explicit Android
endpoints: null, zero, full, random, urandom and the caller's controlling tty.
Unknown devices return ENXIO on data open; O_PATH and stat remain available.
Native access denials remain errors, and nodev denies new data opens without
invalidating existing IO. Readonly mounts protect metadata, not device IO.

## Paths And Directories

Absolute paths start at the model's root; relative paths use an explicit root
sentinel or a real backing-directory FD. Native descriptor duplication and
fork/exec inheritance preserve identity. Directory moves update the namespace
parent edge, so an already-open FD resolves `..` and its reconstructed path at
the new location. There is no process-global emulated cwd or cached path string.

The inode and mount walkers share the logical component lookup primitive.
Within one mount segment, the latter retains inode points and one read snapshot;
intermediate components do not allocate native descriptors. Native providers
retain their actual descriptors, while final parent/object results are pinned
before releasing the snapshot. Points retain the selected view and mount context;
native identity alone cannot choose a bind alias. Crossing a provider releases
the old transaction before entering another, avoiding cross-store lock ordering.

Directory hard links and moves into descendants are rejected. Replacing or
removing a directory requires it to be empty. Removed directories retain their
identity and parent for live descriptors, report zero links and cannot acquire
new entries; reconstructing their pathname returns ENOENT.

Symlinks have native inode identity and can themselves have multiple names.
Resolution handles relative and absolute targets, a 40-link bound, root-clamped
`..`, trailing slashes and distinct follow/no-follow/entry-mutation semantics.
`missing/..` and `file/..` cannot be collapsed lexically. O_PATH/no-follow can
return a symlink FD without opening its target. Directory search and mutation
permissions use the calling task's immutable guest credential snapshot, including
supplementary groups, sticky-directory ownership and root's execute-bit rule.
`access()` uses real IDs for traversal and the final object. New objects inherit
the filesystem UID/GID and a setgid parent's group; chmod/chown and timestamps
share this model. The native backing remains caller-owned, without kernel set-ID.
Trusted offline operations without a credential context use native authority.

`file_paths` retains the parent/name of files that have never had multiple names.
Descriptor readlink follows parent renames and marks deleted names without
substituting a newly created object. Once an object has had hardlink aliases,
the original descriptor dentry is ambiguous even after all but one alias is removed;
readlink returns ENOTSUP instead of guessing. Data and descriptor operations still work.

POSIX access/default ACLs are canonical Linux xattr values in `inode_acls`, shared
by every alias and copied with image metadata. A transactional `acl_mask` on the
object avoids extra lookups for ordinary mode-only access. Named users/groups,
the ACL mask, chmod and default inheritance use the caller's guest credentials.
Creation carries both the requested mode and kernel umask: a default ACL is
clamped by the requested mode; otherwise the umask applies. This includes socket
nodes and child-directory default ACLs. ACL mutations copy up before native
metadata changes, preserving sealed lower bodies. The backing filesystem never
receives guest-user ACLs or executable kernel file capabilities.

Ordinary xattr bytes remain on the backing inode. Their preparation uses the
same logical permission authority, including ACL masks and sticky-directory
ownership, and returns a retained descriptor after any required copy-up.
Kernel/LSM restrictions still apply; virtual root cannot bypass Android's
attribute restrictions. Attribute listing does not require file-read access.

## Directory Cursors

`md_inode_getdents` emits aligned Linux getdents64 records with logical inode
numbers and types, `.`/`..`, and opaque monotonic cookies. Committed name cookies
are not reused after deletion. Enumeration uses an indexed database read snapshot
per batch; changes between batches have ordinary non-snapshot traversal semantics.
An undersized first-record buffer fails without advancing the cursor.
An optional synchronous delivery callback runs after the read transaction and
before cursor advancement. Rejected or cancelled delivery leaves the offset
unchanged; successful delivery precedes the native seek. The namespace owner
serializes that entire operation, including delivery, against other read/seek
requests. SQLite locks are not held during delivery. A failure after publication
is not permission to replay the read. RPC uses local delivery followed by its
existing uncertain-reply contract; notifications copy directly to the caller.

The cursor is the actual backing directory's open-file-description offset,
not a client ID or service-side FD map. Thus dup, fork, exec and SCM_RIGHTS share
position, independent opens start at zero, and service restart retains position.
`md_inode_seekdir` handles rewind, saved cookies and position queries. One service
must serialize read/seek operations on shared descriptions; direct kernel
getdents/lseek or a second service bypass that contract. Arbitrary directory
offsets are verified on the current host/device filesystem, not all filesystems.

A lost enumeration reply may already have advanced the cursor. It is an uncertain
operation, not a replay-safe read. The model does not freeze a directory across
multiple batches or promise a particular ordering after concurrent rename.

## Offline Import

`md_inode_import_tree` copies an immutable prepared tree into an empty namespace
in one transaction. The source is not modified apart from normal read atime.
Callers supply byte/entry limits. Traversal uses a heap-owned stack, one copy
buffer and open directory FDs; no recursive import stack or SQLite work enters the guest.
This offline operation is deliberately not exposed as a long-running RPC request.

Regular data, permission bits, access/modification timestamps, directories and
symlink text are preserved. Source device/inode pairs identify shared objects;
aliases refer to one new backing object, never a copied file or a substitute
symlink. Metadata snapshots detect observed source changes. The source must stay
immutable: these checks are not an atomic snapshot of a live filesystem.

Default import maps ownership to the executor and keeps the destination root's
metadata. Explicit `preserve_ownership` retains source UID/GID/mode, including
root-directory and set-ID metadata, in the database; the host remains unchanged.
Neither policy reproduces ctime, sparse extents or physical layout.
FIFO metadata is preserved without copying pipe data. Other special files,
set-ID bits without preservation, cross-device traversal
and xattrs other than the kernel-assigned SELinux label are rejected explicitly.
SELinux labels are not copied or changed. Overlapping source/storage trees and
nonempty destination namespaces are rejected. No fallback clears unsupported
metadata or claims it was preserved.

Native objects and data are synced before namespace commit. Failure before commit
leaves no published partial tree, but may retain untracked objects. An uncertain
commit requires reopen/inspection before retry. Exclusive maintenance can collect
untracked physical allocations; byte limits bound the current attempt, not
accumulated failed attempts while the store remains active.
Import is not execution from the new namespace or successful package installation.

## Transactions

Sealed images, writable instances and copy-up retain these transaction boundaries;
their [backing and lifetime contract](images.md#sharing-and-copy-on-write) is
independent of OCI parsing and launch-local directory attachments.

- Each connection reuses compiled inode, descriptor, name and directory queries,
  plus BEGIN/BEGIN IMMEDIATE/COMMIT/ROLLBACK programs. Every use resets the statement and clears all bindings
  before leaving the operation. A bounded metadata cache is admitted against
  SQLite's current data version; no read snapshot survives the operation.
  Local preupdate hooks invalidate dependent object/name/backing/path rows,
  including trigger changes, without running SQL from the hook. Rollback of
  mutations discards speculative records; read-only failure does not clear them.
  Other writers invalidate the cache on the next admission. Native attributes
  and permission decisions are not cached.
  Resolved nodes in the current view also prime the descriptor index by backing
  device/inode, avoiding a second SQL lookup after open. Actual FD identity and
  native attributes still come from the kernel; old copy-up backings retain their
  independent lookup. Cache insertion replaces existing keys rather than
  consuming another slot for an alias.
  Statements are finalized with their owning connection.
- Each object stores its name count and child-directory count. Insert/delete
  triggers maintain them in the same transaction as namespace changes, including
  rollback, rename and exchange. Entry updates must use delete/insert. Node reads
  obtain these logical attributes together with identity, without counting queries.
  The independent audit recomputes both counters from names and directory kinds.
- Stat reads current native attributes, then uses the logical node snapshot already
  obtained by path resolution or the one descriptor lookup. Directory enumeration
  and parent mutation checks use that same membership model. Root is always attached;
  detached directories report zero links and reject enumeration and new entries.
  No pathname reopening or cached native attribute snapshot substitutes for an FD.
- Image opening returns one retained FD, its object identity and canonical dentry
  path in one read transaction. Ordinary opens do not reconstruct unused paths.
  Reconstructing a directory path uses versioned parent-name records.
- Ordinary writable opens retain read admission when no namespace or backing
  change is needed. Creation, copy-up and overlay publication promote that
  sole snapshot under its retained exclusive store gate. Nested read snapshots
  cannot promote. No pathname is re-resolved and no mutation is replayed.
- Guest regular-file creation claims a preallocated backing from a batch of 32.
  All backing files and their containing directory are synced before inventory
  rows enter the WAL. Claim removal and logical-object publication share one
  transaction. No live or unlinked object is recycled. A claim restored by loss
  of unsynced WAL has its data, guest xattrs and timestamps reset before reuse;
  the host SELinux label remains untouched. Final native metadata is synced
  before publication. Failed refills leave only unreachable objects.
  Active directory watches retain the single-open allocation path, avoiding
  exposure of internal preparation events. Trusted operations without virtual
  credentials preserve native umask semantics and also allocate directly.
  Other types sync their containing directory before publishing a reference.
  Snapshots do not copy a source's allocation inventory.
- Link, unlink, rename, replacement and exchange each use one database transaction.
  Names are byte strings, not UTF-8 text or concatenated SQL. A same-inode rename
  preserves both names; NOREPLACE rejects an existing target.
  Directory moves/exchanges change parent edges in the same transaction as names.
- Reads resolve names in a snapshot. They cannot see half an exchange. Contents
  are not transactional: writes through returned FDs follow kernel IO semantics.
- Store opening, connection close and each metadata operation take an exclusive kernel `flock`
  on their private object-directory description before entering SQLite.
  Independent services for one store therefore serialize metadata, including
  reads; separate stores do not share a lock. The gate is released after commit
  or rollback and by the kernel when its owner dies. It adds no per-request heap
  allocation and is not held during RPC delivery, guest execution or ordinary
  IO through returned file descriptors. Connections must still be reopened after
  fork; an inherited description would share the lock owner.
- An independent shared root-directory lease retains the store's lifetime.
  Immutable source directories retain parent-root leases as well. Exclusive
  offline maintenance fails with EBUSY while a cooperating owner is active;
  namespace transactions keep their separate short-lived gate.
- Lock admission waits for kernel release, without polling or a settling delay.
  A caught signal can fail admission before the transaction starts. Kernel IO
  and lock waiting do not promise bounded service completion; the caller's RPC
  deadline bounds observation, not cancellation of an accepted request. Offline
  import must not contend with live clients.
- Connections use SQLite WAL with `synchronous=NORMAL` for persistent stores.
  Each operation commits atomic visibility, not a synchronous storage barrier.
  Ordinary unsynced operations may be lost after power failure. Automatic
  checkpoints start at 1024 pages, with a 4 MiB retained-WAL limit on reset. A large transaction or pinned
  external reader can exceed that threshold; it is not a storage quota.
  Temporary mounts retain transactional rollback but use `synchronous=OFF`.
  Watch wakeups observe the WAL, not checkpoint writes to the main database.
  Last-connection checkpoint/sidecar removal uses the same admission gate as
  opening and ordinary operations. SQLite's Unix VFS may retain closed main-DB
  FDs while a same-process peer holds POSIX locks; subsequent opens reuse this
  bounded concurrency high-water mark, and last-owner close releases it.
  Incompatible store formats and journal modes are rejected without conversion.
  No SQLite busy timeout or
  automatic replay is installed. An external SQLite writer bypassing the store
  gate still returns EAGAIN. An IO error during commit can have an unknown
  outcome: inspect before replaying a mutation.
- `fsync` and `fdatasync` first synchronize the actual data FD, then checkpoint
  committed metadata under the store gate. `syncfs` synchronizes backing storage
  before the same metadata barrier. The SQLite transaction ends before the full
  checkpoint, while the gate remains held. Other connections' committed metadata
  is included. Open-unlinked FDs and mounted/overlay stores retain their selected
  identity; O_PATH and invalid descriptors are rejected. Native attachments
  retain native barrier semantics. O_SYNC/O_DSYNC creation and reopening publish
  a metadata barrier before returning the data FD; subsequent data IO stays
  native. Imports, snapshot publication, sealing and exclusive metadata retirement
  also request explicit barriers. Data or checkpoint errors propagate; they are
  not converted into successful durability acknowledgements.
- Detached objects and uncommitted allocations are retained and audited separately.
  There is no live garbage collector for ordinary detached objects. Removing metadata while another process
  holds an FD would break descriptor lookup. Long-lived stores can therefore
  accumulate unreachable backing data; live reclamation remains unsupported.

SQLite supplies database transactions, not Linux filesystem semantics. References:
[atomic commit](https://www.sqlite.org/atomiccommit.html),
[isolation](https://www.sqlite.org/isolation.html),
[WAL synchronization](https://www.sqlite.org/pragma.html#pragma_synchronous),
[checkpoint completion](https://www.sqlite.org/c3ref/wal_checkpoint_v2.html),
[kernel lock ownership](https://man7.org/linux/man-pages/man2/flock.2.html), and
[Linux rename](https://man7.org/linux/man-pages/man2/rename.2.html).

## Checks

`test_durability` checks data and WAL failures, directory-sync failure before
reserve publication, concurrent reserve claims, watch-event transparency,
hardlinks/rename/unlinked descriptors and snapshot-local inventory. A modeled
power-loss test kills a writer and discards uncheckpointed WAL, checking both
recovery to the old namespace and preservation after an explicit barrier.
This is not a physical power-cut test. `durability_guest` exercises actual syscall
routing with plain and nondumpable/filtered callers, tmpfs, overlay remounts and
native attachments. `test_resources.py BUILD --case durability` runs both.

`test_inodes.c` runs on the Termux build host and as a Debian/glibc process under
real shell UID 2000 in `u:r:shell:s0` on NX809J / API 36 / Linux 6.12.23 / 4 KiB:

- Open-before/after-link identity, shared writes/mappings/locks, modes, unlink to
  zero, name reuse and retained descriptors after reopening the namespace.
- Replacement/exchange, same-inode rename, enumeration, non-UTF-8 names,
  truncation and explicit rejection of unsupported API requests.
- Independent connections across fork/exec and commit visibility after a
  deterministic kernel-lock conflict. Four independent store owners concurrently
  open/create, link, stat and unlink without transient SQLite errors; the final
  audit verifies names, detached objects and absence of untracked allocations.
- Reused queries observe another connection's link/unlink and name replacement,
  missing-name lookups, native truncation and open-unlinked FD identity without
  recompiling the warmed read programs.
- Existing writable opens admit no metadata write; unrelated local mutations
  preserve warmed paths. Same-transaction negative-name and trigger-count reads,
  rollback and nested-promotion rejection validate cache publication.
- The mounted-path fixture covers 24 directory depths with two final descriptor
  materializations and depth-independent transaction admission, plus native
  crossings, symlinks, error cleanup and another connection's parent rename.
- Open/fstat query counts, directory batches observing another writer, and
  rejected/cancelled directory delivery before shared-cursor advancement.
- Node reads share transactional membership and link counts; another owner's
  removal is visible on the next operation, while stat retains exact counts
  before and after removal. Independent audit rejects corrupt name/directory
  counters. Opening an incompatible store fails without rewriting its format.
- Directory moves/replacement/exchange with retained FDs, cycle rejection,
  detached directories, directory link counts and real search/write permissions.
- Relative/absolute/dangling/cyclic symlinks, hard-linked symlink inodes, follow
  flags, O_PATH, readlink truncation and the 40-link traversal boundary.
- 189 path/flag/mutation comparisons against ordinary POSIX syscall results.
  On the build host those are direct kernel calls; in the Debian fixture the
  reference calls pass through the existing guest path adapter. Host comparison
  and device comparison are separate evidence, not independent kernel oracles
  inside the guest.
- Eleven deterministic SIGKILL boundaries: create after object sync, and
  create/link/unlink/rename/exchange before and after namespace commit.
  Precommit checkpoints flush actual dirty database pages and verify a nonempty
  WAL. Reopening checks names, inode identity, database integrity,
  foreign keys and orphan accounting.
- WAL journals keep their inode across alternating writers and repeated automatic
  checkpoints. Small commits reuse bounded space; a logical hardlink wakes a
  watcher before checkpointing. Repeated connections retain a bounded native-FD
  high-water mark and release all descriptors after the final owner closes.
  Reopening audits the namespace; a foreign rollback-journal store is rejected without
  changing its journal mode.
- Twelve additional hierarchy SIGKILL boundaries: mkdir/symlink after object
  sync, and mkdir/symlink/directory move/exchange/rmdir before and after commit.
  Retained directory FDs, parent paths and shared file data remain coherent after
  reopening. Audit checks directory parent/name agreement and root ancestry.

Pipes identify exact checkpoints; waitpid observes child termination. An outer
timeout cancels a stuck fixture; it is not a settling delay. Process-kill tests
do **not** establish power-loss correctness. No phone reboot or system change
is involved.

`test_import.c` covers contents, modes, timestamps, symlinks, source independence,
limits, unsupported metadata, observed source mutation, overlap rejection and
three additional deterministic import SIGKILL boundaries. It also imports the
prepared Debian fixture under shell UID 2000 and checks selected files and the
namespace audit. Both current Android identities deny source hard-link creation:
the fixture reports that alias-import branch as LIMIT rather than substituting
copies. It requires another host with native hard-link support. FIFO import
is covered on the Termux host; shell policy blocks creating that source fixture.
Guest FIFO names and transport use the [named-pipe contract](fifos.md).
Directory RPC paging, inherited/shared cursors, concurrent readers, lost replies
and service restart are covered in `test_rpc.c`.

## Limits

Namespace-induced ctime updates, complete set-ID/file-capability clearing on
native data writes,
exact hardlink-dentry data notifications, live import/promotion, unreachable-object
reclamation and power-loss/out-of-space recovery remain incomplete or unvalidated.
RPC descriptor transfer does not supply storage reclamation policy.
Host ownership stays the real executor identity; guest ownership is logical.

Installed distributions, package-manager transactions and OCI image workflows
use this same namespace. Their [coverage](../../docs/shroot.md#coverage-and-limits)
does not imply a complete Linux ABI or filesystem isolation. Direct-backend
hardlink controls retain the host's independent restrictions. SQLite stays in
native namespace owners, outside guest execution.
