# Process Resources

`task_resources` owns independently shared guest state in the supervisor.
Its lifecycle follows successful kernel process/resource transitions, not
Android Activities, named environments or launcher configuration.

| Resource | Clone sharing | Unshare | Exec |
| --- | --- | --- | --- |
| Filesystem context | `CLONE_FS` | `CLONE_FS` | Retained |
| Mount view | Shared independently of `CLONE_FS`; `CLONE_NEWNS` copies | `CLONE_NEWNS` copies and separates FS context | Retained |
| Descriptor-origin annotations | `CLONE_FILES` | `CLONE_FILES`, `CLOSE_RANGE_UNSHARE` | Detach; remove close-on-exec entries |
| Semaphore undo | `CLONE_SYSVSEM` | `CLONE_SYSVSEM` | Retained |
| UTS names | Shared; `CLONE_NEWUTS` copies | `CLONE_NEWUTS` copies | Retained |
| SysV IPC namespace | Shared; `CLONE_NEWIPC` creates an empty namespace | `CLONE_NEWIPC` creates an empty namespace and separates semaphore undo | Retained |
| User namespace | `CLONE_NEWUSER` creates a nested owner | Nested owner with immutable ID maps | Retained |
| PID identities and child namespace | New TID, shared TGID for threads; `CLONE_NEWPID` selects a new child namespace | Changes only future child admission | Retain TGID; retire former TID on nonleader exec |

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

The filesystem worker accepts intrusive host-side work records and publishes
results to explicit owner callbacks on the supervisor. Seccomp delegation uses
that same completion dispatch; no receiver may cast unrelated work to its own
operation type. Submitted work runs in bounded batches alongside socket and
notification readiness, with no queue lock covering filesystem execution or
completion callbacks. Queueing itself allocates no records. Stop/failure closes
admission and retires pending work with an error before the store is released.
Terminal owners retain their records through worker join and release their own
results; worker stop does not invoke supervisor callbacks during teardown.
Ordinary direct notification handling does not traverse the submission queue.

`interception_buffers` provides bounded shared payload slots for the production
syscall adapter and its transport fixture. The supervisor
alone owns allocation metadata, generations and references outside the shared
mapping. A mapping owner and each independent slot lease retain the pool.
An admitted worker pins its slot before submission and borrows only its byte
span, never the allocator. Task death or replacement of the mapping owner cannot
reuse a slot until that worker and its result release it. Exhaustion returns
EAGAIN for event-driven admission; slot reuse allocates no memory or descriptor.
The memfd has sealed dimensions, not immutable contents. Inputs are copied into
validated worker-owned requests; generation checks prevent stale host handles,
not cross-process tampering with mapped bytes or security-domain separation.

`adapter_buffer` exposes the same lease lifecycle to filesystem requests, bounded
SysV packets, shmctl metadata and private-helper control parcels. Protocols supply their own validated views;
the allocator owns no filesystem or IPC policy. A blocked SysV operation retains
its captured request outside guest memory and releases its slot before waiting.
Its watcher and epoll registration are supervisor-owned. Empty task-side ppoll
preserves the original signal mask; exact watcher events interrupt it without
an application signal or a guest wait FD.

`fd_install` owns atomic ADDFD_SEND publication for mapped filesystem results and
foreign-process image opens. The result provider retains the source FD while the
destination table turn is queued. An expired notification is distinct from a
delivered result: a live task may restart admission after a signal or debugger
stop. The provider retains its already-open result across that restart, without
repeating filesystem creation. A restarted admission may retire an expired
queued turn for the same result; a live notification cannot be replaced. Task
teardown releases the retained provider reference. After installation, the kernel result publishes origin
metadata before the next table mutation; task death cannot turn it into rollback.
An internal retirement/wakeup error is separate from the committed kernel result
and cannot produce a second notification reply. O_PATH uses its separate retained
source/rights path because the kernel rejects O_PATH in ADDFD.
SHM attachments instead use a same-address-space helper with a private file table.
Its descriptors never enter the application's table. The helper, its buffer and
mapping observation remain owned until reaping, including caller death and exec.
An address-space resource turn orders mapping publication, detach, destructive
memory calls and fork. See the [shared-memory contract](shared-memory.md).

An inode origin in the current view with no attachments uses the inode engine's
single path walk after descriptor-identity validation. It does not run a second
mount traversal or cache lookup results. Different views, native roots and
attachments retain composed traversal. Absolute paths ignore an unused base;
openat2 scoped resolution still validates it. The anchor fixture compares SQL
step/transaction counts with the unannotated path and checks stale-base errors.

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

Guest clone/unshare with `CLONE_NEWNS` prepares the candidate asynchronously on
the filesystem worker, under the caller's file-table and FS-context turns.
The host clone/unshare omits that namespace flag; successful native completion
publishes the prepared guest view before a child resumes. Unshare also separates
CLONE_FS state. The copied cwd is rebased only when it belongs to the original
view; existing descriptors keep their original provenance. Failure or caller
death releases the candidate without replacing the task's owners. Virtual
CAP_SYS_ADMIN controls admission; it grants no host capability.

Mount views support directory/file bind mounts, recursive bind,
readonly remount, private propagation, move and normal/lazy unmount. Placement
uses stable slots and a validated acyclic parent graph, independently of slot
allocation order. Recursive preparation acquires the complete subtree before
publication. Move preserves mount IDs and open anchors. Lazy detach removes
lookup visibility while retained descriptors still address the old objects.
Normal unmount rejects retained anchors, child mounts or roots belonging to
any FS context in the namespace, including prepared fork/unshare candidates.
Exported origins hold shared OFD range locks through queued rights, import and
forwarding. A normal unmount retains an exclusive nonblocking range lease through
publication, excluding a concurrent foreign-origin acquisition. Conflicts return
EBUSY without a wait, root escalation or a helper process. Lazy detach permits
existing references. Detached entries are collected during later mount admission
when no origin, selected root or child placement retains them. Collection drops
their object-cache records, policies and backing custody before slot reuse.
A slot generation prevents stale snapshots from referring to its replacement.

`pivot_root` accepts the initial base root or an attached selected root and an
attached new root below it. The base is a stable mount instance, not a missing
origin. Its physical root descriptors are acquired only when its placement changes.
The old root is moved to the resolved put_old directory. Root and cwd references
exactly at the old root move to the new one; other cwd locations and open FDs
remain unchanged. Namespace-owned weak FS-context membership includes prepared
fork/unshare candidates, independently of task-registry publication. Each
context retains its namespace; a short lifecycle lock orders membership and
root relocation without holding a lock across guest execution. Root placement
is part of the same validated revision as attachment placement; prepared roots
and covered dentries are released on failed publication. Namespace copies retain
the relocated base and remap its parents. Recursive bind, child-busy checks and
retirement traverse the base and attachments in one topological order. Returning
to the base preserves its explicit root identity for subsequent pivots; mountinfo
publishes the selected root once and the relocated base at its covered path.
Ephemeral and layered mounts use the filesystem backends described below.

The descriptor mount API separates three owners: a `fs_context` configuration,
a `mount_source` prepared filesystem, and a graph placement. Legacy mount uses
the same source factory and attachment transaction. Typed control input is
retained under the descriptor-table turn before worker submission, so close or
FD reuse cannot retarget a configuration operation. CREATE captures provider
resources using the opener's credentials and PID/cgroup/network ownership. Parameters,
created, mounted and failed phases reject invalid ordering. Ordinary filesystem
requests acquire no new owner or probe.

`fsmount` publishes a detached, parentless graph root and returns its existing
O_PATH origin through the shared FD delivery path. `move_mount` attaches that
same instance in its creating mount view without changing its mount ID or
retargeting earlier descriptors. Detached roots are included in namespace
copies and graph custody; graph validation distinguishes a parentless root
from an attachment under the namespace base. Closing the final origin permits
normal collection. Context FD close releases prepared source custody directly;
failed delivery/cancellation uses the existing result owner. Native `fsopen`
and host mount privilege are not used. Filesystem contexts use nonseekable
control-file IO, while cgroup controls retain their existing cursor semantics.
Reconfiguration, typed binary/path/FD parameters, cross-view placement and
unimplemented attributes are not silently accepted.

`mount_setattr` resolves a mount root by path or retained descriptor, including
a detached construction root. Readonly/nosuid/nodev/noexec changes use the same
policy as legacy remount. Recursive changes preflight every selected mount's
writer authority, locked attributes and backing writability before publication
on the filesystem worker. Failure leaves all policies unchanged. Atime settings
are validated compatibility hints, not timestamp enforcement. Private/slave
propagation preserves the private graph; peer groups, ID mapping and nosymfollow
are explicitly unsupported. The syscall adapter validates the versioned binary
structure and zero extension before submitting typed bytes; ordinary IO gains
no allocation, counter or observer.

`test_mount_api.py` exercises syscall state/order, descriptor flags, dup/fork,
SCM_RIGHTS, detached-root IO, readonly attachment, recursive attributes, locked
rollback, source cancellation and stock
Debian util-linux mounts. The native transient-store suite additionally checks
namespace copy, detached graph import/export and exact final FD counts.

Mounted inode filesystems retain backing custody separately from their placement.
Bind and namespace copies share that custody, not a SQLite connection or mount
policy. A worker-local storage cache opens an additional connection only on first
use; the initial-store path needs neither a cache lookup nor an allocation.
The cache retains at most 16 connections in LRU order. Scoped users exclude
eviction; cold admission and mount retirement release connections whose backing
custody has no other owner. Watches own independent connections and can outlive
cache eviction. No cache sweep or filesystem probe is added to ordinary data IO.
Path traversal, roots, metadata, object IDs and reopen select the mounted store.
Retained old-view dirfds remain usable after the original worker connection closes.
The private retained-directory SQLite VFS preserves the lease FD as the directory
anchor through rename; stock Unix VFS IO, journaling, locking and nofollow opens
remain in use. Portable graphs retain each distinct mounted store's maintenance
and loaded-source leases once, including aliases. Imports reconnect under the
same custody after publisher exit, without trusting the original store path.
Watch instances own one queue and independent sources for each selected store.
Aliases share a source by store identity; additional sources retain their own
custody and connection rather than borrowing the filesystem worker's cache.
Watch descriptors are unique across the instance. Empty sources release their
observation resources; transactions and waits never span two stores.

### Shared Mount Policy

Each attachment and the base root own a `mount_policy`. Local views keep flags inline,
without a descriptor, mapping or extra allocation. Open/reopen, access checks,
metadata/xattr admission and mount-table output read the same policy. Namespace
copying captures the current flags into an independent local owner, not a shared
writable alias. Anchors retain the policy with their exact mount view.

Explicit private publication lazily creates one memfd/mapping per exported mount.
Its bounded header contains the format and a lock-free atomic flag word. Size
seals prevent resize; `F_SEAL_FUTURE_WRITE` leaves the publisher's existing mapping
writable while blocking FD writes and new writable shared mappings. Received
observers validate the layout, seals and CLOEXEC descriptor before taking ownership
and mapping it read-only. Failed import leaves the descriptor with its caller;
failed publication releases its temporary resources and preserves the local owner.
An observer can forward the descriptor but cannot promote itself to a writer.

Readers see the writer's atomic updates without RPC, polling, descriptor
duplication or SQLite. Once shared, repeated publication borrows the same FD and
flag reads/writes need no free FD slot. Queued rights and received mappings retain
the last state after publisher teardown or exit. This is kernel-owned state
lifetime, not a background custodian process. Ordinary data IO is unchanged.

This component transfers policy; the graph parcel below associates that policy
with source/covered O_PATH references. The verified private transport must bind
the parcel to its store and message. Atomic flag visibility does not provide
mount/remount transaction ordering across workers. Local mutations run on the
filesystem worker; mutable topology uses the revision contract below.

### Portable Attachment Graph

`mount_graph` publishes immutable revisions of an attachment graph into sealed
memfds. Each bounded, pointer-free manifest records parent indices, slot
generations and the kernel
identities of each source object, covered object and policy descriptor, including
the base-root policy and its optional relocated placement. The selected graph
root is explicit. Backing type, detached state and mounted-store identities
are explicit. Parent
indices need not precede children; cyclic or out-of-range relationships fail.
The parcel retains those actual O_PATH references and policy FDs, not paths or
application data descriptions. Native aliases remain separate mount entries;
nested mounts retain their exact covered dentry and parent. Replacement of an
old source pathname cannot redirect the imported graph. Mounted inode stores
append deduplicated `inode_custody` parcels; their exact spans and root identities
belong to the sealed graph. Even a repeated import validates all backing rights
before reusing a known view. Forwarding retains those original leases.

The retained topology stream's device/inode identifies the graph across private
transfers and forwarding, independently of the publisher's process lifetime.
Mount IDs remain receiver-local and are allocated from its existing owner.
Import into an already known view verifies that identity and every descriptor,
then reuses its IDs and object cache. It does not reconstruct the cache or infer
identity from equal directory trees. A namespace copy has independent policy
and a new graph identity on publication. The origin-transfer owner below interns
imported views within one filesystem worker; concurrent workers cannot share one
mutable object cache.

Export returns an owned bounded parcel. Import always consumes it and publishes
a destination only after complete validation. Invalid seals, graph structure,
FD count/type/identity and allocation/mapping failures close partial resources
without replacing an existing destination. Empty views transfer the manifest,
root policy, anonymous pin carrier and stream. Placement needs at most 54
descriptors; each distinct additional
store adds 2..512 custody descriptors, up to 16 stores. The cold parcel allocates
only its actual FD count and travels through the existing bounded FD bundles.
Validation and duplicate-safe cleanup sort descriptor numbers rather than doing
quadratic scans of expanded vectors. Cold publication is lazy. Ordinary
unexported views create no manifest and ordinary data IO takes no new path.
Failed export can retain successfully materialized publication state in its
source view, but leaves no partial output parcel or changed mount policy.

The owner prepares a complete new revision, queues its immutable FD bundle and
then consumes the old head to expose the new one atomically. The bundle never
contains its own topology stream, avoiding SCM_RIGHTS reference cycles. Death
before commit preserves the old head; after writer exit readers retain the last
committed revision. Only that owner may publish. A foreign worker checks the
revision at operation admission; unchanged revisions require no allocation or
FD slot. Changed revisions are fully validated before merging into its local
tree. Old snapshots cannot roll back a newer view. Retired entries carry no
placement descriptors; replacement invalidates only that slot's old object cache.
Unpublished local mutation still fails ESTALE on export. Readonly updates use
the live policy mappings. Selected task root/cwd, native mount-ID-map transfer
and a complete application-origin vector are separate from graph publication.
`fs_origin_transfer` composes graphs with
backing custody and a message route. A valid graph alone does not authorize
access to another store. Local guest namespace creation has independent admission.

One empty anonymous regular file per exported graph carries independent byte-range
leases for its slots. Local origins need no extra descriptor. Exported and foreign
origins own readonly descriptions with shared OFD locks; kernel SCM_RIGHTS queues
retain them until receipt or discard. The writer temporarily takes an independent
exclusive lease for normal unmount or retirement. A receiver refreshes the graph
under its new shared lease and rejects stale generation/detach state before
publishing an anchor. Final close releases the lock without a counter protocol.
This carrier has no directory entry, payload data or per-request file creation.

### Portable Backing Custody

`inode_custody` captures the existing root maintenance lease and every currently
loaded lower's objects directory and maintenance lease. Its sealed, pointer-free
manifest records the root identity and ordered source IDs with each directory's
device/inode. It shares the bounded sealed-manifest primitive with attachment
graphs. Publication duplicates the original open descriptions: it never reopens
paths, changes flock state, queries SQLite or retains application data OFDs.

Import validates every descriptor, source/lease relationship and manifest field
before publishing an `inode_lifetime`. The root must match a retained directory
from the receiver's authenticated store scope; an equal pathname or a replacement
store cannot authorize it. Import always consumes the parcel, including on
failure. Partial export and failed import close all temporary rights without
changing the source's locks or publishing a partial owner. The private peer must
provide the actual locked descriptions: inode equality alone is not proof of
flock ownership, and import must not acquire or convert locks on those descriptions.

Imported custody uses the same lifetime constructor and allocation-free local
retain/release as a SQLite-backed store. The root and lower leases survive source
SQLite closure, sender exit, pathname replacement and forwarding. Queued rights
also retain the leases; discarding a queue, killing a receiver or releasing the
last owner lets the kernel release them. This needs no custodian process or new
descriptor per local reference. Ordinary data IO and unexported stores do not
enter the publication path.

A parcel contains two descriptors plus two per loaded lower, at most 512. The
transport must chunk that bounded vector and own partial receives; it must not
raise FD or in-flight limits. This is a snapshot of loaded sources, not a live
catalogue replica, a relocated SQLite catalogue or an authenticated origin
vector. Composition with attachment graphs and the message authority belongs to
the origin-transfer owner, not this backing component.

### Portable Message Origins

`fs_origin_transfer` exports a pinned, bound source message into one owned
control-plane parcel. Its compact sealed manifest contains only used records:
the exact message route, physical store identity, vector indices, unique O_PATH
anchors, mount slots/generations and spans identifying the graph/custody manifests. Repeated
anchors and shared owners are emitted once; unknown entries remain unknown.
Every known anchor carries a mount pin, including base-root origins created
before a subsequent pivot. They retain the old mount rather than following the
namespace's new root.
No mount pointer, SQLite connection or application data OFD crosses this boundary.
Publication is worker-only because graphs and loaded source catalogues are
worker-owned. The event loop retains the immutable message through completion.

A store-scoped import owner opens its O_PATH root relative to the retained store
directory, not by reopening its pathname or duplicating its maintenance lease.
Import checks the expected route, store, canonical indices, all rights and their
manifest identities before making origins usable. It always consumes the parcel.
New views and origins remain staged until the entire vector succeeds; failure
releases partial custody without changing an existing cache or destination.
Allocation and descriptor exhaustion return errors, not partial vectors or
automatic replay.

The import owner interns graphs by their retained stream identity. Repeated and
forwarded imports reuse receiver-local mount IDs and object caches while any
anchor retains that graph. Each worker owns its own cache; copying a namespace
still makes a distinct graph. Cache-only views are collected after successful
imports, by explicit collection, or on owner teardown, without periodic scans.
Base-store backing custody belongs to the anchors. Mounted-store custody belongs
to their graph, so cache collection also releases otherwise unused mounted-store
leases. Anchors survive cache teardown and retain all required backing owners.
Different transfers retain independent snapshots of loaded backing sources.

Imported origins use the same anchor constructor, filesystem engine and FD-table
batch publication as local origins. Local retains, ordinary data IO and unrelated
launches perform no serialization or cache lookup. All control rights are subject
to native descriptor/in-flight quotas; transport must own bounded chunking and
partial receive cancellation.

Matching a route or sealed bytes is not peer authentication. The surrounding
protocol must authenticate the issuing authority, exact message and receiving
connection, and supply that independently verified route to import. The serializer does not
select application framing, publish actual received application FDs, transfer
native mount-ID maps or order mutable topology/remount transactions. Those
production integration boundaries remain separate from the tested transfer.

### Self-Contained Origin Custody

`ipc_capsule` packages the same captured origins and actual data descriptions
into an immutable kernel-owned carrier. It requires a creation-time ORIGINS_V1
binding. The filesystem worker validates captured backing identities, issues
the directional route and serializes with `fs_origin_transfer`. No source
registry, live launch, RPC exchange or per-message persistent record is needed
to receive a published capsule.

`fd_bundle` stores each node as one seqpacket with its writer closed before
publication. A leaf holds up to 253 rights; larger metadata vectors use bounded
trees of those queues. Every traversal peeks at the only packet, without a
shared read cursor. Application data and metadata have separate bundles. The
outer queue owns both plus the original IPC epoch and store-maintenance leases.
Their queued references survive the last supervisor's exit, including messages
with no known origins. Discarding the carrier releases the complete tree.
Origin metadata never retains application data descriptions after queue disposal.

One lazy 32-byte key belongs to the live store IPC epoch. Creation uses its
existing metadata gate and atomic rename; an interrupted unpublished creation
is replaced by the next creator. The first owner of a new epoch removes stale
key state. Publishers authenticate the complete capsule header, including the
actual kernel carrier cookie, exact connection side/link and message nonce,
with HMAC-SHA256 from the existing pinned Mbed TLS dependency. The key is cached
by each worker owner, not looked up for every message. Native connections do
not create this owner or key.

The receiver performs a descriptor-free peek and verifies authentication before
installing any control rights. A copied header on another socket fails cookie
validation; replacing its cookie invalidates the tag. It then imports through
the common bounded metadata parser and annotates the actual data bundle's FDs.
The result is one `received_fds` owner with native flags and shared offsets,
usable after both the capsule and importer close. Unknown origins stay unknown.
Repeated/concurrent peeks leave the queues intact. Partial allocation or FD
installation closes only owned results; it cannot authorize application replay.

This authentication assumes trusted runtime custody of the store's private IPC
directory. It is not isolation from a hostile process with the same real UID
that can read or alter that directory. Native FD, in-flight and Unix queue-graph
limits remain explicit errors; the runtime does not raise them or substitute
unannotated delivery. Ordinary guest traffic uses NATIVE. Ancillary sends and
the receive adapter handle explicitly bound ORIGINS_V1 connections, including
mixed credentials. Addressed datagrams retain native semantics unless their
actual peer matches the binding. Unadapted consumers need a separate policy.

`--case origin-transfer` checks an independent exec sender exiting before a
fresh receiver exists, 253 mixed and all-unknown data rights, readonly/copied
views, repeated and concurrent peeks, shared offsets, copied/tampered headers,
native/wrong-direction bindings, allocation failures, five partial-FD limits,
interrupted key construction, key retirement and exact final FD/lease release.
Discard-without-import checks data pipe EOF. Separate bundle checks cover 253
and 600 rights, invalid shape and partial construction failure.

### Authenticated Origin Transfer

`ipc_origins` owns asynchronous capsule preparation and import on the existing
filesystem worker. Its event-loop owner admits at most 16 requests. It creates
no listener, control exchange, timer or additional thread. Its copied launch ID
is diagnostic metadata, not authentication; the capsule's epoch key and actual
socket binding authenticate the transfer.

Preparation retains one immutable capture containing the actual application
socket followed by up to 253 data descriptions, plus the matching origin
snapshot. Both must come from the same source-table turn. The worker resolves
the binding from that captured socket. ORIGINS_V1 lazily creates its capsule
owner, checks backing identities and returns an owned two-FD vector: the same
socket description and the completed capsule. NATIVE and unregistered peers
return the original captured owner on event-loop completion, without duplicating
descriptions or serializing origins. Completion exposes the selected format;
malformed or stale bindings remain errors rather than a native fallback.
Closing or reusing a guest socket number after capture cannot retarget the
prepared send. Preparation neither sends application bytes nor changes a
connection's creation-time format agreement.

Receive retains the actual socket and carrier in another immutable two-FD
capture. After validating the creation-time binding, the worker authenticates,
imports and peeks through `ipc_capsule`. It returns one annotated
`received_fds` owner, not metadata for caller-selected descriptors. Repeated
receives share native data offsets; known origins retain their backing leases
after the importer closes. Unknown-only vectors allocate no annotation array.
Neither operation looks up or contacts the source process.

Shared input reference counts change only on the event loop; the worker borrows
them through completion. Callers may release their handles immediately after
admission. Cancellation clears its handle and suppresses callbacks without
freeing running inputs. Pending/computed results retire on completion dispatch
or after worker stop/join. Allocation, native quota and authentication failures
return no partial custody and close only owned resources. No guest FD number is
guessed or closed, and no operation is replayed.

The source helper can export socket plus rights at one private-table clone.
A separate captured-send operation accepts a retained socket plus 0..253 rights,
covering both a capsule and an ordinary native vector. It clears inherited helper
FDs and installs a private import channel with atomic ADDFD_SEND. The kernel
receives all rights, including O_PATH, directly into an outgoing control block
in caller-owned control memory. It closes that channel before installing the
captured application socket at its original number. There is no per-right ADDFD, application
slot or lookup of original guest FD numbers. Import scratch and control ranges
are bounded, aligned and disjoint; partial import fails before application send.
The kernel reports both quota and control-copy failures as MSG_CTRUNC; the
helper returns EMFILE for incomplete private import and releases its whole table.
The queue remains supervisor-owned through exact reaping, so cancellation drops
both unreceived and installed private rights. Native filters, quota errors and
SIGPIPE remain observable; cancellation after committed send preserves its
byte count. The existing task-local send owns final execution.

The guest adapter uses this pipeline for ancillary and addressed Unix sends.
One outgoing owner spans the source-table turn, task/metadata snapshot,
private-table export, worker preparation and final task-local send. Export
releases the table turn at clone, before IO; its scratch can be reused for import
only after exact helper reaping. The adapter checks the selected format and
normalizes split rights headers into one bounded control block. No source FD
number is looked up again after capture. Cancellation before commit releases
prepared custody; cancellation during capture or send retains it through exact
helper reaping. Format selection inspects only the captured socket on the worker,
not a preliminary guest SO_DOMAIN call or a reusable source number. Non-Unix
sockets retain native selection and kernel ancillary validation. Releasing the
mapped buffer drops any unused prepared result.
An ordinary caller with an already admitted, unambiguous table-owned channel
reuses the broker capture path under the same table turn. No new infrastructure
FD is admitted for this optimization. Authenticated destinations can also use
broker sending; external peers retain task-affine IO and native credentials.
Explicit credentials join the prepared vector after captured-identity validation.
An optional native pathname anchor has separate custody and a private import;
it cannot consume the 253-right message budget or become an application right.
Its extra private slot and native in-flight quota remain real limits. Empty
rights need no rights-import channel unless a pathname anchor is present.
Native socket placement also requires its original number below RLIMIT_NOFILE;
a limit lowered beneath an existing socket number is an explicit capacity error.

`--case ipc-origins` checks source socket-number reuse, 253 mixed/repeated/unknown
origins, source worker shutdown, repeated receive and shared offsets. Eight
cancellation cases cover preparation/import before execution, during metadata
admission, after computation and after callback. Both worker-join cases reclaim
undispatched results. Failure injection and bounded concurrent admission verify
unchanged caller custody and exact cleanup. Independent exec tests receive only
after the sender exits; another receiver exits with an untaken result and live
worker, requiring kernel-only release of all data/maintenance references.
Native selection checks registered and external stream/datagram sockets, exact
owner/FD identity, pending/computed/callback cancellation, worker join and invalid
socket rejection. `--case fd-observation` checks both one-right and 253-right
captured sends, including protected/full caller tables, exact 254-slot helper
capacity, partial import, receive/close/send filter denial, SIGPIPE and terminal
cleanup. O_PATH, repeated descriptions and shared offsets survive the transfer.

`ipc_received` is the worker-owned message decoder used by `fs_buffer_service`.
It reads the transport binding from the captured socket, separates credential
tokens and expands an authenticated carrier into a distinct annotated data
vector. A compact index plan maps each native right to its output entries;
these indices are never guest FD numbers. Native messages borrow the original
custody without duplicating its descriptors or allocating an expanded vector.
The decoder never sniffs capsules on NATIVE or unregistered connections.

The receive owner keeps the original batch immutable and owns one expanded
vector per inspected message. Successful worker completion transfers that
vector before releasing the request. Cancelled and untaken results retire on
completion or worker join. Publication selects this same custody through
ordinary annotated `fd_return`, including partial output faults and terminal
observation; it does not receive FD numbers into a temporary application buffer
and copy them afterward. Subsequent batch messages replace expanded custody
only after the preceding message's publication has finished.
The terminal syscall acknowledgement releases the final receive custody; batch
and accept intermediate publications retain their explicit release boundaries.
Brokered messages fitting the shared payload and control buffers combine
admission with IO commit. Larger and batched messages retain staged preparation.
Both paths use the same socket timeout, nonblocking, low-water and rights owners;
no socket flags or readiness decisions are cached across operations.

`--case ipc-ancillary` runs guest send cases with an explicitly bound
socket inherited through the runner. Protected/unprotected cases cover one and
253 file/O_PATH rights, full caller tables, split headers, invalid FD, rejected
send, sendmmsg, payload EFAULT and a sandbox denying SO_DOMAIN. Import starts
only after the guest sender and its worker exit; exact origins, offsets, FD balance, payload EOF and final
maintenance admission must still hold. Four native-format blocked-send cases
cover protected/shared tables, caller death and source-slot replacement, with
no unrelated pipe writer or resource turn retained during IO. Signal checks
cover SIGPIPE delivery, masking and MSG_NOSIGNAL. A native/guest UDP control
checks payload delivery with ignored rights and unchanged descriptors.

The same case runs guest receive cases with a prepared,
explicitly bound socket inherited through the runner. No sender worker remains
at receive time. Protected/unprotected cases check 253 mixed rights, shared
offsets, logical openat through imported directory origins, repeated peek,
recvmmsg, control truncation, control/header EFAULT and zero/three free table
slots. Explicit credentials are tested on either side of the coalesced capsule,
with SO_PASSCRED enabled and disabled; NATIVE delivery leaves a capsule opaque.
Every case requires payload EOF, exact descriptor balance and final store
maintenance admission. The matrix also runs ordinary protected/unprotected
callers after a filtered CLONE_FILES child admits the shared channel and exits.
Their source tables, prepared sender tokens, imported rights and full-table
publication must remain correct without requiring a filter on the caller.
Seven `--case ipc-origins` worker cases check decoder
result ownership, cancellation before/after execution, join before callback,
untaken completion, wrong direction and partial annotation allocation failure.

Capsule queues consume native per-UID in-flight rights independently of free
table slots. A sufficiently reduced RLIMIT_NOFILE can make the private helper's
export fail with ETOOMANYREFS even with free slots. The guest fixture verifies
this explicit failure and unchanged caller descriptors; the runtime neither
raises the limit nor retries a potentially consumed message.

Production authorities still offer NATIVE. Source handling of explicit
credentials and addressed/mixed ancillary sends, unadapted consumers, native
mount-ID maps and mutable topology/transaction ordering remain separate contracts.

## Path Origins

The filesystem engine accepts optional `md_fs_anchor` origins for its captured
base descriptors. Each anchor retains the exact mount view, mount, an O_PATH
reference and the backing store's `inode_lifetime`. This owner keeps the existing
store/source directory descriptors and maintenance leases after the originating
worker closes its SQLite connection. Capturing or retaining origins duplicates
none of those descriptors. The SQLite connection, prepared queries, transaction
lock descriptor and watches remain worker-owned and close independently.
The retained root's device/inode identifies the store, not its pathname or a
connection's address. A sequential worker can reopen that same store, including
after rename, and use the origin; a different store or replacement at the old
path is rejected. Retained lower-source leases protect backing names through
copy-up and unlink. Releasing the last origin releases those leases immediately.
The worker alone mutates its mount view and source catalogue: reference counting
does not authorize concurrent workers or serialize a live view across processes.
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

General application SCM_RIGHTS provenance is not inferred from a successful
syscall return or a post-receive acknowledgement. Ancillary delivery can publish
valid descriptors before a later output fault. Its shared receive/publication
contract and remaining batch-fault boundary are described in
[Unix IPC credentials](ipc-credentials.md); those delivery rules alone do not
propagate arbitrary peer mount origins into the annotation table.

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

Origin vectors separate source capture from destination publication. Capture
retains the exact ordered origins under one metadata lock, including repeated
source FDs and explicit unknown entries. It uses caller-owned storage and retains
neither the source table nor data open-file descriptions. Source replacement or
owner exit does not change the captured vector. The source table turn must still
cover actual kernel descriptor capture; a metadata snapshot alone is not that
capture or a message-to-origin association.

`MD_TASK_HELPER_EXPORT` captures an explicit ordered vector of 1..254 descriptor
numbers in the existing private-table helper. It copies the vector before
acceptance, preserving duplicates; only the inherited keep-set is sorted and
deduplicated. The caller holds its source-table turn while taking the origin
snapshot and until the helper's exact clone callback. That callback releases
the turn before descriptor export, so later shared-table close/dup cannot
retarget the captured inputs. A failure before clone leaves that turn with its
caller until completion/cancellation.

The helper clears unrelated inherited descriptions, then uses the existing
authenticated FD channel and bounded 253-right packets. The result vector is
reserved once before helper creation; partial export stays private until full
completion and reaping. Cancellation or a rejected syscall releases partial
custody through the same owner as receive. No endpoint enters the caller's
table, and application filters and native quotas remain effective. Full caller
tables can succeed after unrelated helper slots are cleared; no available helper
slot returns EMFILE. Results preserve kernel OFDs, access flags, O_PATH, ordering
and shared offsets. Origins come from the ordered snapshot, not inode matching.
The helper does not negotiate a transport, send application bytes or enable
guest framing; those are the enclosing operation's responsibilities.

Batch preparation reserves the destination annotations before delivery and rolls
back every prepared entry on allocation failure. One retained source vector may
prepare independent deliveries, including peek copies. Completion validates all
FD numbers and table owners before changing anything, then publishes the installed
prefix in one metadata transaction and discards the undelivered suffix. Unknown
origins clear previous destination annotations. Publication allocates no memory;
retired anchors are released outside the lock. Internal filesystem RPC uses these
same primitives with its existing two-FD wire limit, without another allocation,
syscall or protocol phase.

The filesystem context similarly retains an optional cwd anchor. CLONE_FS
shares it, an independent context copies the reference, and exec retains it.
Root selection and cwd are independent: changing the root does not move cwd,
and cwd provenance alone does not activate the scoped-root adapter. The special
proc-root chdir clears ordinary cwd provenance.

Ordinary chdir resolves its directory through the filesystem transport and then
performs native fchdir. The supervisor captures that descriptor's origin and
publishes cwd provenance only after kernel success. A failed change retains the
previous origin; an unconfirmed change at task death clears it. A native host
chdir without a known origin also clears it after success. The kernel remains
the cwd owner; no pathname cache or synthetic cwd replaces it.

Relative requests capture the retained cwd anchor under the filesystem-context
turn. Direct requests duplicate its O_PATH reference in the worker; RPC exchanges
pin the same anchor without opening or sending a temporary guest descriptor.
The wire marks cwd inputs separately from SCM_RIGHTS inputs, and the service
validates that mask against the authenticated exchange. Both transports pass an
actual captured descriptor to the engine, never the worker's cwd.

An unknown origin retains native capture: `/proc/TID/cwd` for direct requests,
or `.` through the private-table task helper for mapped requests. The helper
copies the caller's FS context while both resource turns remain held, captures
the kernel directory and transfers it directly to the supervisor. No temporary
descriptor enters a surviving CLONE_FILES peer, including with a full table or
nondumpable caller. Cancellation retains the request until exact helper reaping;
failed clone/open/export does not execute or replay the filesystem operation.
Native host RPC still reports uncaptured cwd before send.
Application filters remain in force. Initial namespace cwd uses these publication and
native-fchdir completion paths after interception is ready and before guest code
loads. Exec retains the existing cwd. Direct-rootfs bootstrap cwd and
unannotated native descriptors have unknown provenance.

Proc aliases of the current thread's descriptor table borrow the original input
for metadata, readlink, reopen, watch registration and directory suffix traversal.
The mapped request captures its identity under the file-table turn, without a
temporary guest anchor. Current-thread cwd suffixes use the retained filesystem
context; proc-root paths resolve through the selected guest root. `/proc/self`
selects the group leader, while `/proc/thread-self` selects the calling thread.
An alias of a different thread's resources retains native lookup with unknown
provenance; it never borrows the caller's annotations, even when the owners
happen to be shared.
The mapped request describes that kernel path as a typed operand. `thread-self`
is bound to the requester before helper creation; `self` still selects the group
leader. The helper's copied file table cannot change which task the alias selects.

Filesystem opens from the direct broker and task-affine service publish their
origins automatically. Native dup/dup3, F_DUPFD/F_DUPFD_CLOEXEC, F_SETFD, close
and close_range update annotations from their actual kernel results. Fork,
unshare and exec use the same ordered ownership transition. The seccomp filter
and restricted-domain policy share the descriptor-operation list; observation
does not remove native descriptor capabilities after a proc-root restriction.

This does not yet cover inherited/native descriptors or general
application SCM_RIGHTS transfers. An unconfirmed native mutation at task death
forgets any known affected destination instead of claiming rollback or retaining
a potentially stale origin. An automatically assigned dup result is then unknown.
The dedicated O_PATH capture is narrower: at its exact openat return gate,
terminal registers identify a delivered FD or no delivery. Both ABI spellings of
the original AT_FDCWD argument are distinguished from descriptor numbers when
the kernel kills the call before executing it. Prepared provenance is published
under the retained table turn, before a surviving CLONE_FILES peer may mutate
that table. Unknown PC/syscall/results retain conservative abandonment; this
decoder is not applied to arbitrary native producers. The runtime requests exit
observation once on a task's first capture and retains it across clone/exec,
independently of nested debugger options. There is no cleanup syscall injection
at the terminal event and no extra per-read/write observation.
Complete provenance, including those terminal cases, is required before copied
guest namespaces can be published.

### Publication Ordering

`resource_order` provides an intrusive queue embedded independently in each
file-table and filesystem-context owner. Typed adapters pin their resource through
completion, including after its last task owner exits. The supervisor and
filesystem worker share the synchronized queues, while each record retains one
event-loop owner. Mutexes cover metadata changes, never kernel calls or event
waits. CLONE_FILES shares the file queue; CLONE_FS shares the filesystem queue.
Independent resource copies start with empty queues.

Operations needing both acquire files before filesystem context and release in
reverse order. Shared-cwd peers with independent file tables still serialize on
the same filesystem context. Cwd capture releases that turn once its directory
identity and origin are retained, before filesystem execution or RPC send. Fork captures both
resources at the kernel birth event; filesystem unshare holds both through its
kernel result. Neither waits for child completion while retaining a turn.

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
waits, and unrelated resource owners can progress independently.

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

`fd_delivery` owns prepared destination annotations and the retained receipt,
independently of RPC actor authentication. The caller retains its operation and
capacity-sized scratch arrays; filesystem exchanges embed the two-entry arrays
in their existing allocation. Preparation pins the target table and origins,
not the sender or data descriptions. Failed preparation releases every acquired
resource. Kernel completion publishes the exact installed prefix once; an empty
receipt may be retried after readiness or disposed on final zero delivery.
Disposal releases metadata and the receipt, never installed application FDs.
The owner serializes access and retains the destination turn through publication;
the component does not acquire a queue turn or infer syscall completion itself.

Only FD-producing RPC exchanges allocate a receipt mapping. Publication needs no
allocation. Transport readiness, peer lifetime and syscall completion remain
distinct from cancellation intent.
The shared `fd_receipt` layout supports one rights parcel of 1-253 descriptors;
capacity is retained by the operation, not read from writable guest memory.
Mappings are sized to the offered capacity, so ordinary filesystem RPC retains
its one/two-FD allocation and wire limit. The kernel receives the exact control
length, not aligned spare room that could admit an extra FD. Parsing ignores
foreign pointer fields, bounds all lengths and validates every descriptor before
copying any output. Invalid or duplicate numbers leave the output unchanged.
The shared mapping is a lifetime mechanism, not protection against a malicious
guest modifying its own memory. `fd_delivery` does not authenticate source/message
association; that belongs to the transport, while retained anchors own backing
custody. General application SCM_RIGHTS provenance is not yet connected to the
guest adapter.
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
Retained `/proc` and `/dev` directory descriptors remain usable after root
selection. Their task-owned paths return to the caller's provider, never the
filesystem worker's `self`. Selecting the initial inode root preserves its
proc/dev boundary; a different root or mounted filesystem has ordinary names
there. The separately admitted
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

Exited identities retain credentials until the guest consumes the terminal wait
event. Reaping removes their lookup visibility independently of open pidfds.
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
Status/stat use typed per-open snapshots with guest IDs, credentials and debugger
relationships; seeking to zero refreshes the snapshot. A zombie remains visible
until wait consumes it. Namespace handles retain their owners after task exit;
opening pid_for_children before its first child returns ENOENT.

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
Guest device-node creation returns EPERM: CAP_MKNOD is not advertised and there
is no device-creation authority. Regular-file and FIFO mknod remain supported.
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
task-local capture path. PRIVATE and SLAVE propagation requests retain the
private topology: there are no shared peers or masters. SHARED and UNBINDABLE
remain unsupported, rather than pretending to propagate later mount changes.

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

## Network Namespaces

`network_model` owns a retained namespace identity and user-namespace
authority. Clone, unshare, setns and typed `/proc/PID/ns/net` handles use the same
resource transaction as the other namespace kinds. A new namespace is offline;
it never silently falls back to Android networking. Existing sockets retain
their original authority. Anonymous Unix socketpairs remain kernel IPC, with
namespace annotations retained through descriptor-table operations.

`network_calls` supplies bounded requests through the existing mapped transport;
`network_namespace` owns control-socket carriers and `network_route` owns the
NETLINK_ROUTE codec. Queries and CAP_NET_ADMIN-authorized mutations share one
model: loopback, bridge/veth, master assignment, IPv4 addresses, routes and
typed namespace-FD moves. Replies preserve sequence, port identity, ACK and dump
completion. Interface state and ACK publication share a fabric turn and mutation
journal; allocation, encoding or queue failure rolls back all affected namespaces.
The journal exists only for mutations, not queries or data IO. Netlink carriers
provide kernel readiness and queue options without changing Android interfaces.
Control descriptor selection joins the close/dup table turn, including capture
of a namespace FD, and ends before guest output copying.

Default launches use native networking. Opt-in `--network routed` creates a
launch-owned fabric with an IPv4 uplink in its initial namespace. Children start
offline; configured bridge/veth routes grant connectivity. `network_endpoint`
retains creation-namespace provenance, logical bind/peer addresses and private
port translation, never a data OFD. The weak fabric endpoint list unlinks before
final release. Namespace peers can use identical internal ports; routed-root
binds use real Android ports, including conflicts and final release.

`network_io` uses the shared exact-description capture and cancellable IO owner
for control, connect/accept and addressed TCP/UDP calls. No table/fabric turn
spans blocking IO or guest copying. Connect/accept jobs use the existing
completion event and interrupt/reap path; cancellation closes an undelivered
accepted FD. Ordinary stream IO remains native. Shared payload/vector helpers
serve both Unix ancillary transport and routed message IO; native networking
does not allocate these routed owners.

IPv6, raw packets, netfilter, multicast subscriptions/broadcast,
device-bound sockets and routed recvmmsg return explicit errors. Outgoing
network ancillary data is rejected; incoming packet metadata is not translated.
This is not packet-level isolation: native ephemeral backing ports remain
reachable, and inherited native descriptions retain authority. Independent
supervisor transfer of these typed network owners is unsupported rather than
silently dropping their annotations.

## Namespace-Owned Sysctls

`network_sysctl` supplies the managed namespace's
`ip_unprivileged_port_start`, `ping_group_range` and `ip_local_port_range`.
Validated updates share one namespace lock, including overlapping port bounds.
Opening captures the network owner; subsequent setns does not retarget that FD.
Writes require CAP_NET_ADMIN in its user owner, without touching host sysctls.
Host-network views retain native access and errors. Logical unprivileged-port
and ephemeral-range settings also govern routed endpoint allocation. Ping group
configuration does not imply an ICMP transport.

Mounted proc controls are selected on the filesystem worker and retain a live
mount anchor. Readonly policy applies to future opens and already opened writers,
including after lazy detach. Ordinary proc spelling uses the same typed provider
without a logical mount anchor. The common descriptor host supplies dup/fork,
offsets and positional IO; numeric writes at a nonzero offset consume bytes without
changing the value. No additional service thread or per-IO FD is created.

## Namespace-Owned Sysfs

`sysfs_view` retains the network namespace selected at legacy mount or fsopen.
Mount authorization belongs to that network namespace's user owner. The limited
offline tree contains `class/net/lo`, its relative device/subsystem links,
identity/MTU/flags/operstate/carrier attributes and `fs/cgroup` for separate mounts.
`network_namespace` supplies the same atomic link snapshot to sysfs, ioctl and
netlink. Mounted views do not follow the reader's later setns.

The private name tree supplies stable native inode identities and ordinary
directory enumeration, not attribute data or Android device access. Typed control
files use the common IO/cursor contract; retained mount origins keep both the
tree and network owner alive. Bind/copy/detach share ordinary mount ownership.
Closing the final owner retires the temporary tree. An unknown attribute returns
ENOENT; unimplemented mutations and host-network sysfs return EOPNOTSUPP.
Cross-supervisor export is rejected rather than flattening the provider into a
native bind. No host mount, background refresh or per-read descriptor is needed.

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

The v2 controller list is empty; membership, events and domain type are real
logical state, but CPU/memory/IO limits and freezing are not enforced. The v1
devices list is always `a *:* rwm`; all-device allowance is accepted, restrictive
rules are rejected. Unsupported controller enabling, freezes and release agents
return EOPNOTSUPP. This interface never accesses Android's cgroup hierarchy or
claims that a resource/security limit was installed. Controller delegation and
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

## Boundaries

Concurrent named environments and launch-local attachments are not kernel Linux
namespaces. Guest `CLONE_NEWNS`, `CLONE_NEWUSER`, `CLONE_NEWIPC`,
`CLONE_NEWUTS`, `CLONE_NEWPID`, `CLONE_NEWNET` and `CLONE_NEWCGROUP` have the
contracts above. Time namespaces are not implemented; their creation is not
reported as successful. POSIX message delivery and UTS sysctl priority-change
notification are not implemented. They must not be inferred from the limited
mqueue filesystem, SysV separation or live sysctl reads. Tmpfs quotas remain open; unsupported
options fail explicitly. Saved overlay credentials do not establish
kernel-equivalent confinement for unadapted native access.

Proc mounts are selected process views, not a complete virtual kernel procfs.
Lookup and directory enumeration omit host-global `sysrq-trigger`, `kcore`,
`kmsg` and `keys`: no guest kernel-control, raw-memory, kernel-log or global-key
provider exists. Other native permission errors remain errors, not missing files.
Native proc descriptors outside these mounted views are unchanged.
Foreign `/proc/PID/mem` and signalfd sender translation remain outside this contract.
Inherited native proc descriptors retain their original view. Internal helper
threads are filtered in a logical PID proc mount, not in Android's native procfs.
Guest ptrace limitations are recorded in [debugging](debugging.md).

Guest filesystem calls use mapped requests, not private per-call RPC sockets.
The admitted table-owned export/return endpoints have explicit table lifetime;
ordinary requests borrow them. Sending credential capabilities stay in the
worker and a private-table helper, whose reaping bounds their lifetime. Admission
of export channels, direct ADDFD results and private-helper descriptors uses
exact gettid notification sites. Application filters still apply; denying prctl
does not prevent these admissions. A denied admission returns its error before
publishing a descriptor. Receiving
uses a private table and supervisor-owned source descriptions until kernel
publication directly into application control memory. Cancellation releases only
unpublished resources; published rights belong to the application. Batch
publication ordering and native quota differences remain explicit limits in
[Unix IPC Credentials](ipc-credentials.md). Direct-image fallback descriptors
still need terminal-custody coverage. Cleanup cannot safely close remembered
numbers after reuse, or assume a dying task can execute another syscall.

The service owns its accepted endpoint, receipt and retained request context.
Closing the authenticated exchange signals a launch-owned eventfd, independently
of client-socket EOF. The worker releases that peer on cancellation or completion,
including cancellation while dispatch is executing. No request is replayed and
an installed guest result is not closed by its former provider. A pending watch
reservation is restored before reply publication, or retired after publication
when copying is unconfirmed. Rights already queued in the guest endpoint still
belong to that kernel socket; retiring the service is not guest-slot reclamation.

This resource model does not establish security isolation from Android, other
launches or peer guest processes. Programs retain the executor's host authority;
successful browser execution is not proof of complete sandbox equivalence.

## Verification

`test_namespace_apps.py BUILD STORE` runs stock Bubblewrap in a disposable
Debian userspace under actual UID 2000. Cases cover a basic command, a read-only
root with writable tmpfs, mapped UID/GID and hostname, and nested user/mount/UTS/
IPC owners with independent temporary filesystems, PID namespaces with proc/dev
preparation, and GDB start/continue/exit inside a PID namespace. `--trace` repeats these
production paths through stock strace. Both the command exit and explicit output
are checked; this is compatibility coverage, not kernel-equivalent isolation.
Chromium automatic user/PID and explicit set-ID routes are checked separately in
[Shroot](../../docs/shroot.md#application-filters-and-browsers).
`test_resources.py BUILD --case mount-namespace` also checks PID reservations,
nested admission, signal/wait output, zombie proc lifetime, pidfd transfer to a
protected receiver, orphan adoption, init thread exit and nonleader debugger exec.

The mount-flags fixture also transfers a noexec origin over SCM_RIGHTS to a
nondumpable receiver with an installed application filter and an independent
executable mount alias. The sender detaches its mount before the receiver
checks mmap/mprotect: the received origin keeps its restriction while a fresh
open through the receiver's own alias remains executable.

`test_resources.py BUILD --case rpc` runs the filesystem transport fixture.
Its exchange-ownership cases hold the client socket open through cancellation
before and after reply publication, covering metadata, result/receipt FDs and
watch reservations. An event deadline shorter than the service's peer timeout
requires explicit retirement; complete teardown checks exact host FD counts.
This checks production native-host service ownership; guest descriptor custody
has separate intercepted checks. The fixture also runs in the complete resource suite.

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
preparation failure and allocation-free publication. Cwd inputs cover unknown
rejection, mixed explicit/cwd bases, two retained cwd bases and allocation rollback.
Shared delivery checks also force receipt creation to fail under RLIMIT_NOFILE,
retry empty receipts, release the task owner before publication, and dispose
partial deliveries without closing the installed application descriptors.
Vector tests cover source-owner loss, repeated/unknown origins, partial delivery,
duplicate or invalid result numbers, wrong destination owners, cancellation and
allocation-free unknown delivery. Concurrent vector readers cannot observe a
partially published pair, including two origins for the same inode in different
mount views.
Receipt parsing checks all capacities from 1 through 253 against an inaccessible
guard page, with malformed lengths, duplicate/negative numbers and foreign pointer
fields. No preparation or parsing allocation is permitted by these checks.
Filesystem-order checks cover all four CLONE_FS/CLONE_FILES combinations,
independent file-table progress, running cancellation and retained cwd after
all task owners exit, with allocation failure enabled.
`resource_guest` compares native Linux and Shroot cwd/umask/FD semantics,
failed-unshare rollback, close_range splitting/marking and exec inheritance. Guest-only cases check proc-root
sharing, native descriptor mutation after proc-root restriction, 32-bit fcntl
command semantics and semaphore-undo splitting, final-owner cleanup and exec retention.
Pipe acknowledgements order observations; an alarm is only a failure bound.
Concurrent cwd cases alternate successful and failed fchdir while peers perform
relative ordinary/O_PATH opens and getcwd. Both shared and independent descriptor
tables use the same shared filesystem context; guest opens exercise direct and
task-affine transports.
The RPC cwd cases install a real seccomp filter rejecting temporary O_PATH
directory opens. Relative getcwd/create/open and mixed/two-base link/rename
still succeed, both in ordinary and nondumpable callers.

`test_resources.py --case fd-custody` checks the production buffered O_PATH path.
A CLONE_FILES caller opens successfully with KILL_THREAD filters on connect or
recvmsg, and dies if the filter targets the result-delivery openat instead.
After waitpid its peer checks the entire low-FD baseline; none of the six guest
cases leaves a private descriptor, with or without dumpability. Native controls
do not enter the internal delivery gate. These checks also run in the default suite.

`--case fd-custody-dirfd` repeats the production custody checks with an explicit
known dirfd, including protected input capture and death at native delivery.
All six guest cases leave the surviving table unchanged; these also run in the
default suite and `--case fs-buffer`. `--case fd-custody-nofollow` checks the
same terminal paths through stable backing-name delivery, preserving O_NOFOLLOW.
All six guest cases pass without a private socket, and run in the default suite.
This covers inode-owned objects, not arbitrary native or anonymous sources.

`--case fd-lifecycle` measures alternatives natively under UID 2000, outside
the default suite. Redirecting registers invokes cleanup at a live ptrace stop,
but not at PTRACE_EVENT_EXIT after ordinary exit, seccomp KILL_THREAD or SIGKILL.
The surviving CLONE_FILES peer still owns the socket. A live task's real close
filter can also reject cleanup with EPERM. This matches the kernel's
[irreversible exit path](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c#L826-L934);
an exit event is not an opportunity to run another userspace syscall.

The same fixture reopens retained O_PATH references through a dumpable provider's
`/proc/PID/fd/N`. Deleted regular files, directories and symlinks retain their
native device/inode/type, even for a nondumpable receiver with one free FD slot.
Zero slots return EMFILE; a protected provider returns EACCES on the tested device.
A fixed-size register request/reply prototype performs that delivery with socket,
connect and recvmsg forbidden by real KILL filters. Its control exchange consumes
no receiver FD. Source descriptors remain pinned until the exact child exit.
This is not a general descriptor transfer: reopening an ordinary data descriptor
creates an independent offset, as its negative control verifies. The prototype
does not implement worker admission, arbitrary requests, origin publication,
fork/exec lane lifetime, cancellation or exact O_NOFOLLOW status flags. Its
results do not establish production transport coverage. Results use
`resource-fd-lifecycle-results.json`, independently of both default and custody reports.

Private-table helper controls verify kernel teardown after SIGKILL even with
inherited close denial and a nondumpable source. They also demonstrate two
admission problems: the application's clone filter prevents helper creation,
and copying the source table keeps unrelated pipe writers alive until helper
exit. This is not a transparent replacement for task-local RPC. Exact Unix
socket peer diagnostics are probed separately; creation of NETLINK_SOCK_DIAG
returns EACCES under the tested shell policy. Neither mechanism is a runtime
dependency or a reason to elevate the executor.

The lifecycle fixture also checks the kernel basis for table-owned **export-only**
channel. Its guest endpoint is infrastructure retained by the file table, not a
temporary descriptor owned by a requesting thread. Rights travel only towards
the supervisor, which owns that receive queue and each captured description.
Eight cases cover repeated protected sends, SIGKILL before dequeue or after
capture, seccomp KILL_THREAD before send, and a completely filled table after
channel admission. Regular-file offsets and flock identity remain shared; pipe
EOF proves release after explicit cancellation, not merely matching FD counts.
Receiver-side SCM_CREDENTIALS identifies the actual sender rather than the
socketpair creator; a forged PID is rejected with EPERM. This authenticates the
process, not the request, TID, source-vector origins or namespace authority.

Late ADDFD_SEND admission works in a nondumpable caller for which pidfd_getfd
returns EPERM, with socket/connect/close/clone denied by actual filters. One free
slot permits subsequent export without another allocation; no free slot returns
EMFILE without raising the limit. Native fork, close_range(UNSHARE), and exec of
a CLONE_FILES peer preserve the surviving table's endpoint. Ordinary close_range
and number replacement invalidate that slot without damaging its replacement.
These are kernel lifetime controls, separate from the production checks below.

This transport costs one infrastructure FD per admitted table and the native
SCM_RIGHTS in-flight quota. Its quota control reaches ETOOMANYREFS and then
discards the owned queue, releasing pipe EOF. It does not satisfy a zero-extra-FD
contract, and neither an FD reservation nor a limit increase is hidden from the
fixture. Production `fd_channel` integrates lazy ADDFD_SEND admission with sparse
descriptor metadata, dup/close/exec and shared/copied file-table lifetimes.
Messages match the retained channel, request token, expected rights count and
kernel sender process. Cancellation drains owned rights; request disposal closes
captured descriptions; last table/channel release closes the receive queue.
Accepted input vectors have intrusive, caller-owned leases on the channel.
The channel alone drains its queue and matches packets to those leases, including
independent callers that inherited the endpoint in copied tables. Finishing or
cancelling one owner retains other owners' accepted descriptions. Unmatched,
wrong-peer, wrong-sized, duplicate and late packets are closed. There is no
per-transfer allocation or callback into another subsystem during dispatch.
Ambiguous terminal mutations preserve an uncertain infrastructure entry. Before
reuse/admission, the caller observes F_GETFD and SO_COOKIE under the retained
table turn. The supervisor compares the cookie with its own endpoint, repairs
matching flags or retires only a closed/replaced slot's annotation. It never
closes a guessed number. Denied observation, malformed output or cancellation
leaves the entry uncertain. Only this exceptional path needs observation;
ordinary admitted transfers add no syscall or allocation for reconciliation.
This is trusted adapter coordination, not general application SCM_RIGHTS
provenance or a security boundary against hostile threads.

The protected-metadata continuation uses the same channel and input-owner leases.
Register-only observation/admission works without borrowing a mapped filesystem
slot. Its file-table turn spans capture, original-site seccomp admission and
result publication. A verified restricted proc-FD directory lookup opens the
fixed task-affine path from the borrowed original descriptor; that open creates
only the application's result FD. No temporary proc-root descriptor, private
per-request socket or intermediate result is installed into the guest table.

The production metadata custody fixture covers cold EMFILE, repeated protected
fstat with a full table, proc-FD directory opens with exactly one free slot,
relative metadata on that directory, and sixteen shared-table deaths during
export. Native controls and the guest path require exact descriptor counts.

`--case fs-export` exercises the production adapter with a nondumpable caller,
socket/connect/recvmsg forbidden by real filters, cold EMFILE, repeated exports
at a full FD table, shared directory offsets and independent opens. Sixteen
CLONE_FILES callers die at sendmsg; their parent retains exactly its one channel.
Fork, close_range(UNSHARE), shared-table exec, alias replacement and readmission
check surviving ownership and exact FD counts. Namespace exec prepares images
on the worker, retaining all temporary and final descriptions outside the old
shared table. `--case exec-custody` kills a caller at image inspection, repeats
failed exec with an invalid environment, and executes with socket/connect/sendmsg/
recvmsg forbidden. Ordinary and nondumpable CLONE_FILES callers leave their
surviving peer's exact FD set unchanged. Unit checks additionally discard malformed/truncated packets and queued
rights, checking real pipe EOF as well as allocation rollback and FD counts.
Anonymous ELF admission requires an actual regular, unlinked, seal-capable
kernel image, not a failed managed-object lookup. The supervisor retains its
readable description before exec and publishes that owner only on confirmed
image replacement. Fork shares the owner; failed exec and terminal cleanup
release candidates. A typed control-file view serves self/foreign executable
opens after the existing process-access check. It preserves native inode/seals,
per-open cursors, dup sharing and backed readonly/private mappings. Writable
opens and shared writable mappings fail explicitly. No new proc reopen or copy
of the image is needed, and store-backed executables retain their existing path.
`test_anonymous_exec.py` checks ordinary/sealed memfds, nonleader exec,
close-range, foreign executable/pipe inspection, nested fork and self re-exec.
Eight production service cases also verify wrong tokens, duplicate/wrong-sized
vectors, wrong senders, cancellation before/after queueing and a send error after
queueing. Each checks exact FD counts and pipe EOF after owner retirement.
Reconciliation checks replace candidates with files and other sockets, close
them, change CLOEXEC, reject malformed observations and deny inspection. Mapped
export and result-return tests resume after matching observations and cancel at
the observation boundary. The protected export actor also installs a real
getsockopt-denying filter. Allocation-free origin repair and exact FD counts
remain required.
Input-owner checks deliver vectors in reverse order across independent consumers
and channels, cancel one consumer while preserving another, and inject duplicate,
wrong-peer/count and retired-token packets. Exact pipe EOF and descriptor balance
are required with allocations disabled.

`fd_return` uses the same channel for mapped O_PATH results without a stable
reopen source. A channel-owned output turn spans fork-copied tables; it prevents
one task from receiving another task's result. Destination-table ordering covers
the nonblocking kernel receive and origin publication, not filesystem execution.
`fd_delivery` can borrow an existing shared receipt rather than allocate a memfd.
The retained mapping supplies exact kernel output after normal completion or
terminal task loss. Installed descriptors belong to the caller; cancellation
drains only unreceived rights through the supervisor's retained receive endpoint.
It needs no close syscall from the dead task or a surviving peer.

The same owner accepts annotated vectors with caller-owned scratch arrays and
a retained mapped receipt. It prepares
the complete selected origin vector before
kernel delivery, then publishes only the installed prefix under the destination
turn. Completion and cancellation use the same receipt; a failed acknowledgement
cannot erase installed FD provenance. Queued cancellation discards preparation
without admitting a channel. Source descriptions need remain open only until the
packet is accepted by the kernel; publication retains origins, not data OFDs.
The receipt must be the kernel's actual output, never an acknowledgement copy.
The alternative direct-output observation fixture, `fd_table_observation`, borrows an open
`/proc/<exact tid>/fd` directory captured in the task's context. Under the same
table turn, after channel admission, it records at most 253 lowest free slots.
After native receive it observes the installed prefix without reading application
memory. A failed control/header copy can install descriptors even when `recvmsg`
returns EFAULT; those installations still receive their exact origins. The read
must precede task reaping: `PTRACE_EVENT_EXIT` is the terminal observation point.
Vector completion preserves the native output error after publishing installed
origins; successful completion returns zero, not the number of installed rights.
An invalid acknowledgement remains EPROTO without erasing those origins.
An unavailable directory or non-prefix change is an error, never evidence of
zero delivery. No close/dup/exec or other installation may interleave between the
two observations. This is bounded storage and two event-bound observations, not
periodic polling, a retained copy of the file table or additional data OFDs.
The ordinary receipt path acquires no observation directory.

`--case fd-observation` exercises this production publication owner under UID
2000 with task-local private-table capture, protected/unprotected receivers,
separate/shared tables and both CLOEXEC modes. Cases include full 253-FD output,
unwritable control/message headers, partially writable FD words, zero control
space, zero/three free slots, peek, no receive and SIGKILL before/after receive.
Publication precedes queued table mutation; pipe EOF and exact FD balance verify
release. The 96-case matrix also covers invalid acknowledgement after delivery.
Reaped-task and non-prefix observations fail explicitly. Model checks
disable allocations during observation and publication and cover preparation
rollback and cancellation before admission.

The guest receive consumer selects the exact retained origin vector before
publication. A known-origin selection lazily allocates its origin-update scratch
storage; the existing adapter mapping already contains the kernel receipt for
up to 253 rights. Scalar file results and annotated messages share `fd_return`
and `fd_delivery`, independently of the caller's filters or dumpability. No
receiver directory capture or manual destination-slot installation is involved.
Static control-memory faults limit the received prefix before kernel delivery;
the actual descriptor numbers are then copied from the receipt. A concurrent
remap during that copy can leave installed caller-owned FDs without complete
application output; the receipt still owns their provenance. It does not claim
native per-word installation ordering against concurrent mprotect/munmap.
Unknown-only selections retain direct native control output and allocate no
origin scratch. CLOEXEC policy comes from the captured receive request, not a
later mutable output frame. Ordinary FD creators need no extra ordering solely
to predict the numbers of a received vector.

The same case runs 12 checks of the production helper, including protected
callers, full caller tables, repeated capture, rejected open, fatal helper
filters and cancellation during channel admission or after export. Completion
returns the stack lease once, installs no caller FD and leaves pipe EOF and
descriptor counts unchanged. Caller-supplied directory paths/flags are rejected.

Its source-export matrix adds 24 cases: ordinary/protected callers, 1/254 rights,
repeated capture, full caller tables, unavailable helper slots, invalid inputs,
clone/send filter rejection, fatal filters and cancellation before or during
either export packet. A real CLONE_FILES sibling replaces a source with a new
open of the same inode immediately after helper clone. Export retains the old
offset and captured origins after the original annotation table is released.
Borrowed input arrays may change after admission without changing the export.
Final checks cover exact descriptor balance, returned stack leases, source
teardown and pipe EOF. These checks compose real helper capture with the common
origin snapshot and received-FD custody; they do not enable application framing.

The guest receive adapter binds authenticated origins to actual custody on
explicitly selected ORIGINS_V1 connections. Ordinary production connections
still select NATIVE. Direct application-control output remains native:
receive-to-scratch followed by copying would change partial-copy installation
semantics. Actual adapter coverage is described under
[authenticated origin transfer](#authenticated-origin-transfer).

`--case ipc-origins` composes authenticated import, immutable source custody and
this vector publication after source workers/registries/importers have closed.
A protected CLONE_FILES receiver exits without acknowledgement; the survivor
publishes 253 rights, a truncated prefix, a peek or no delivery from kernel
output. A queued table mutation cannot overtake publication. FD flags, O_PATH
identity, repeated/unknown origins, final maintenance leases and descriptor
balance are checked, including receiver-local limits of zero and three free FD
slots. These component checks do not select guest framing.

Six native receive controls cover zero/one result slots and receiver death
before/after recvmsg. Sixteen production `fd_return` checks combine protected
receivers, denied receives, cancellation, exact zero/one-slot limits, pipe/O_PATH
results, metadata publication and shared-channel ordering across copied tables.
Pipe EOF and FD counts are checked independently. `--case fs-return` additionally
drives the actual bootstrap and adapter with socket/connect forbidden, cold
admission failure, caller-selected CLOEXEC and repeated full-table receives.
Twelve forked callers each perform 32 nofollow opens through one inherited
channel. Sixteen CLONE_FILES receivers die at recvmsg; their surviving parent
can receive immediately with no FD growth. These are trusted runtime results,
not arbitrary application SCM_RIGHTS provenance.

Separate stream/datagram/seqpacket controls show that closing the peer and
shutdown on either endpoint leave queued SCM_RIGHTS alive. Discarding from a
retained receiving endpoint releases them. This agrees with the kernel's
[Unix socket release/shutdown paths](https://github.com/torvalds/linux/blob/v6.12/net/unix/af_unix.c):
service-side close alone is not cancellation of the guest receive queue.

`--case fs-dispatch` joins scalar register control and shared request buffers to
the production filesystem worker, request context and descriptor-origin
publication. Under actual UID 2000, 504 cases cover files/directories/symlinks
removed before delivery, dumpable/protected receivers, zero/one free slots,
receiver death before admission, during execution or before delivery, and
registry-entry replacement while a result is retained. A 201-byte pathname is
snapshotted and validated before submission; later shared-byte mutation cannot
retarget it. Each case runs with separate files or a surviving CLONE_FILES peer,
and with inherited memory or a real kernel exec followed by fresh mapping setup.
Successful delivery publishes the prepared origin under the original table turn;
EMFILE and pre-delivery cancellation discard it. The receiving control path
creates no private FD, with socket/connect/recvmsg forbidden by real KILL filters.
Terminal cases kill the receiver at syscall entry, after kernel return, through
an openat KILL_THREAD filter, or immediately after resuming the entry stop.
Both sign-extended and zero-extended AT_FDCWD forms use the production terminal
result decoder and mutation publisher. A surviving peer checks exact descriptor
identity, O_PATH/CLOEXEC, origin publication and its entire low-FD baseline.
The immediate-kill race records the observed outcome; it is not exhaustive
coverage of every kernel interleaving. The deterministic post-return case
requires successful installation without a receiver acknowledgement.
Provider and surviving-peer descriptor counts return to baseline. The slot stays
unavailable until both task and worker release it, then reuses a new generation
with cleared bytes. Unit checks also cover independent mapping owners, failed
allocation/setup, stale handles, bounded capacity and allocation-free reuse.

The exec fixture inherits its notification filter, but not a setup descriptor.
Its new image requests a memfd through ADDFD_SEND, maps it and closes that FD
before running the receiver. On the tested shell policy, direct O_RDWR reopening
of the provider's memfd through proc returns EACCES; descriptor injection and
mapping succeed. No permission or filter is relaxed. Setup is confined to the
new exec image's private file table. A 96-record queue test checks worker failure,
cancellation of pending work, rejected late admission and completion dispatch
past an earlier callback error.

The 504-case O_PATH fixture uses its own traced control loop, not the production
syscall adapter. It does not cover concurrent CLONE_FILES mutations, all filesystem
operation payloads, protected input-FD capture or exact O_NOFOLLOW status flags.
Production-service checks exercise buffered cwd and O_PATH requests: unknown
context, invalid lengths/fields, input snapshot, transferred result ownership,
queued cancellation and submitted-open cancellation while an event gate holds the worker.
Explicit-base capture queues behind a file-table mutation. Closing the actual
unannotated input before capture returns EBADF without execution; close/reuse and registry removal
after capture cannot replace the retained input. Request validation is common to
RPC and mapped admission; resolution flags belong only to open requests.
Mapped replies copy the result header and actual payload, not the whole slot.
The RPC fixture also checks their shared result
contract using inaccessible output pages, malformed path/capability payloads,
metadata-only replies and retained/installed descriptor counts.
Removing task/resource owners cannot recycle a pinned slot before worker
completion or deliver a late callback to that task; the cancelled result closes
and final FD counts match baseline.
Results use `resource-fs-dispatch-results.json` separately from runtime regressions.
Unannotated dirfds are captured as real kernel descriptions, then replaced before
worker execution to verify that the accepted input cannot change. Watch delivery
uses the production reservation/acknowledgement state machine: successful copy,
rejected copy, invalid acknowledgement and cancellation before/after offering the
reply. Cancellation retains the worker's slot until the reservation is retired;
rejected copies preserve the exact records, and possibly delivered records are
never replayed.

`--case fs-buffer` selects the mapped-output checks also included in the default
suite, exercising the production syscall adapter and bootstrap with native
controls. Known-cwd getcwd remains usable at EMFILE with real KILL_THREAD
filters denying socket/connect/sendmsg/recvmsg, both dumpable and protected,
after fork and real exec. ERANGE/EFAULT are checked without changing the cwd;
48 simultaneous callers share the bounded pool. Unit checks cover CLONE_VM
ownership, fork's inherited shared allocator, fresh exec owners, mapping admission
and worker pins outliving every address-space owner. Production O_PATH checks
cover absolute and cwd-relative long paths, files/directories/followed symlinks,
protected callers, zero/one available FD slot, exact F_GETFL and CLOEXEC on/off,
with all four transport syscalls forbidden. Path/metadata cases exercise mkdir,
symlink, chmod, timestamps, stat, readlink, two-dirfd rename, unlink and open-unlinked
metadata, including protected callers, output EFAULT and a full descriptor table.
Nofollow file/directory/symlink cases use the same zero/one-slot matrix, checking
the selected inode/type and exact status flags. Model checks retain backing
identity across guest rename/unlink and lower-layer copy-up. The custody cases
above also run here. The report is `resource-fs-buffer-results.json`.
`--case fs-results` includes unannotated dirfds imported through actual SCM_RIGHTS
and socket/watch data inputs while socket/connect/sendmsg/recvmsg are forbidden.
The former verifies kernel-object capture, not arbitrary mount-origin transfer.
It also isolates mapped result delivery: ordinary and protected tasks
read/seek mount tables and executable images with exactly zero or one free FD slot, both CLOEXEC values
and socket/connect/sendmsg/recvmsg forbidden by real KILL_THREAD filters. These
checks also run in both the buffer and default suites.
Directory-seek controls keep those four syscalls forbidden at a full FD table:
dup shares the cursor, independent opens do not, and a rejected negative seek
preserves position. The production-worker fixture replaces the source FD after
capture and checks that only the retained original description advances. An
O_PATH descriptor remains unseekable rather than becoming its data counterpart.
Group-exit cases terminate 24 groups of eight peers during buffered calls,
including protected processes. A confirmed terminal stop after ESRCH retires
pending work and continues toward reaping without resuming the adapter. The
diagnostic counts observed races; it does not enumerate every interleaving.
Parked-group cases require deadline failure followed by completed terminal-stop
cleanup, both dumpable and protected. The expected supervisor failure is distinct
from an outer timeout, which fails the check.

The production mapped transport covers captured cwd/dirfd path identities and
metadata, O_PATH (including stable nofollow sources), and data-FD results from
creation, temporary files, ACL/xattr access, mount tables and prepared ELF images.
Socket identity, directory seeks and watch operations capture real input descriptions instead of
substituting path anchors. A mapped watch read pins its request through task-local
copying and asynchronous worker acknowledgement. Unknown explicit inputs use
kernel duplication or table-owned export without inventing mount provenance;
nofollow sources without stable backing use ordered mapped result delivery.
Directory enumeration also uses mapped copy acknowledgement. Its temporary
`ofd_order` entry owns one exact description, compares aliases with self-kcmp,
and orders read/seek across broker, mapped and RPC requests. No permanent data-FD
mirror or cursor database is maintained. Synchronous reads with no active
reservation allocate nothing; a denied kernel comparison fails explicitly.
Mapped copies hold neither a file-table turn nor a filesystem-context turn.
Peer credential queries return mapped byte snapshots, not temporary identity
FDs in the caller. The same retained socket supplies the complete supplementary
group set and its connection-time identity. Protected callers need their admitted
input channel but no result slot. Native RPC carries large byte outputs in
bounded descriptor-free continuations under the original reply deadline; EOF,
incorrect lengths and unexpected rights fail without replay. Header-prefix
clearing leaves unused mapped value pages untouched for ordinary requests.
The worker commits the next cookie only after accepted copying; cancellation
after offering commits possibly copied records without replay. Cancellation
before offering and explicit copy rejection leave the offset unchanged.
The per-launch owner does not coordinate raw bypasses or OFDs transferred to a
different launch supervisor.
The focused directory checks reproduce rejected output, then verify unchanged
position, zero free guest FD slots, forbidden RPC, and four mixed protected/
ordinary fork readers without duplicates. Worker checks cover queued alias
seeks, independently opened descriptors and cancellation of either owner.
File opens/reopens and executable-object access also use mapped results.
Metadata and path operations can identify a store object instead of supplying a
descriptor. Both mapped requests and native RPC capture that identity once;
the worker opens and releases the object under the request's retained context.
Current executable metadata and watches use this operand even after unlink,
without a temporary guest FD. Object identity cannot substitute for a stateful
open file description: directory cursors, IO, sockets and watch queues require
captured descriptors. Each slot selects one operand, never both. This contract
does not add hostile-caller authorization to the existing filesystem service.
Deferred FIFO completion uses a short-lived supervisor child with an independent
kernel file table, not a guest-side private socket. It closes unrelated inherited
FDs before waiting; only the completed endpoint is delivered to the application.
The supervisor cancels and reaps the exact child, discarding unreceived rights.
Guest-root changes retain the CLONE_FS turn through worker publication. The guest
adapter no longer contains a filesystem RPC-client fallback. Native host clients
still use RPC. Reexec image preparation and proc-image snapshot construction are
worker-owned. Snapshot chunks use the existing mapped slot; each is copied into
request-owned storage before submission. No resource turn or SQLite transaction
spans task-local copying. Cancellation before, during or between worker actions
closes the construction FD, while successful delivery transfers only the final
read-only/O_PATH result. Kernel umask queries open status on the worker and return
its current value without modifying shared state or caching it.
Kernel-path operands and unknown cwd use `task_helper`, also used for SHM
mapping. Its private table owns open results and the transport endpoint until
kernel reaping. Successful capture transfers an owned O_PATH description to the
retained filesystem request; rejection/cancellation closes it without publishing
an application FD. For ordinary O_PATH results, the supervisor opens the stopped
helper's exact proc-FD alias while its private table owns the source. This does
not repeat name resolution or require device data access. Restricted proc access
falls back to task-local SCM_RIGHTS, also used for nofollow descriptions. Stateful
inputs never use this object-only reopening. Both routes preserve caller open
filters, cancellation and terminal reaping; subsequent data opens retain native
permission checks. Two operands are captured under one request's resource turns,
with independently owned descriptions unless both select the same cwd/path.
The filesystem worker rejects unresolved kernel-path operands, and host RPC
does not accept them. Stateful inputs still require actual OFD capture.
Mount-table and proc-image results retain O_PATH provenance for subsequent
metadata even when the caller has no spare FD slot. Path chmod/chown/utimens,
statfs and managed watch registration keep their intermediate descriptors on the
worker. Native proc targets retain task-affine lookup in the private helper. Current-thread
proc-FD opens capture the original descriptor under the table turn and perform
reopening on the worker, with no private guest anchor or repeated guest-number
lookup. Native object reopening and attachment reopening use the same primitive;
attachment policy is checked before execution and FIFO completion remains deferred.
Regular-file and FIFO mknod likewise keep creation resources on the worker.
Chdir/truncate use a retained worker target and a task-affine path syscall through
its proc descriptor lease. No guest slot is installed; the final syscall retains
the caller's fs_struct, RLIMIT_FSIZE, SIGXFSZ and filter admission. The source
address binds cwd publication to that retained origin. Completion or task death
closes the worker lease. Current-thread proc-FD aliases use the same operation.
Descriptor-based fchdir uses a retained task continuation: input capture and
permission checking keep both the file-table and CLONE_FS turns through the
original descriptor syscall and adapter acknowledgement. Received descriptors
need no preexisting origin and no temporary guest FD. The worker retains the
selected origin until confirmed success publishes it as cwd. An ordinary error,
including a filter denial before native entry, preserves the previous cwd.
Cancellation before entry likewise preserves it; terminal loss after entry
invalidates the observation rather than interpreting terminal registers as
proof of a completed syscall. Both resource turns and all worker FDs are released.
Foreign executable readlink uses mapped bytes after the supervisor's existing
process/identity/domain check. It creates no guest file, needs no free FD slot,
and copies only the caller-requested prefix. Readlink never uses a temporary
readable descriptor to transport text.
Proc-FD capture retains logical provenance across a thread alias only when the
target snapshot names the exact file table held by the request. Kernel lookup
and backing identity checks remain authoritative; foreign tables do not borrow
annotations by descriptor number. Mount checks exercise `/proc/self/fd` in a
worker thread as well as the group leader.

Xattr operations capture the path or actual input description once, then perform
logical ACL/capability or native backing work under the selected worker context.
Permission checks, copy-up and readonly attachments share the filesystem engine.
Input values are captured bytes, never borrowed guest addresses or guest memfds.
Mapped and RPC responses carry size queries or up to 64 KiB of value bytes;
output rejection is explicit and does not replay a mutation. Large mapped values
live outside the header union. Pool reuse clears only the declared header prefix,
so ordinary calls neither allocate nor overwrite a 64 KiB payload. FD-style
calls retain actual descriptions rather than accepting an O_PATH origin as proof
of readable descriptor flags. Protected capture keeps the channel admission and
application-filter limits described above.
Fork-inherited shared pages are not security isolation; successful mapped delivery
does not establish general application FD-transfer support.

`--case proc-custody` checks snapshots and umask queries with CLONE_FILES callers
killed by filters at the former task-local write/read points. Ordinary and
nondumpable callers leave the peer's exact FD set unchanged. Large-argv checks
cover chunking, rejected copying, O_PATH, CLOEXEC, read-only data, native seek and
zero/one available result slots with RPC socket calls forbidden. The native
nondumpable auxv control reports EACCES on this device; the positive guest check
remains required. Worker checks additionally cancel construction at every stage
and require its own descriptor count to return to baseline.
Resource checks also cover mount-table O_PATH flags and fstat with one result
slot, path metadata/statfs/mknod/chdir/truncate with no free slots, admitted protected watch queues,
and proc reopening of unlinked files, directories and native devices with one
slot. The native/guest controls retain exact identities and independent offsets.
Foreign executable readlink is also checked with ordinary/protected callers,
full FD tables, read/RPC kill filters, truncated output, zero length and EFAULT.
Current executable metadata, xattrs and watches run with full FD tables for both
ordinary and protected callers. Worker checks cover unlinked object identity,
mutation of request bytes after admission, queued cancellation and exact FD balance;
native RPC rejects malformed identities and stateful operations without an OFD.
Imported cwd checks use SCM_RIGHTS directory inputs with full ordinary/protected
tables and repeated relative metadata after fchdir. Worker checks require queued
FS/file-table operations to remain blocked through acknowledgement, and cover
wrong descriptors, success, native/pre-entry errors and cancellation on either
side of entry with exact provider FD balance.
Foreign cmdline/auxv/exe opens check repeated delivery with exactly zero/one free
FD, protected callers, caller-selected CLOEXEC, content and seek. Native
`fd_install` checks exercise the production publication primitive, queued
cancellation, receiver death before admission and exact origin ordering.
Xattr checks cover ordinary/protected callers with full FD tables, path and FD
forms, binary values, maximum-sized logical ACLs, nofollow, EFAULT and ERANGE.
Path-only checks forbid RPC socket calls; protected FD forms first admit the
shared export channel. Native RPC independently checks maximum ACL payloads,
rejected output and subsequent successful reads. Mount-engine checks retain
readonly rejection and unchanged worker FD counts.

Initial-cwd and proc-alias cases also run nondumpable, checking known origin at
image entry/capture, independent reopened offsets and virtual metadata. A shared
file-table case races dup3 replacement against ordinary/O_PATH proc directory
suffix opens. The native/guest kernel-contract `proc-owners` case independently
unshares filesystem and descriptor state in a pthread, checking leader versus
current-thread aliases and invalid proc path errors against the kernel.

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
Vector handoffs transfer up to 253 native FDs after sender exit, with two mount
origins for one inode, unannotated FDs, shared offsets, repeated MSG_PEEK and
truncated consumption. Pipe EOF confirms that retained origin vectors do not
retain writable descriptions. These controlled fixtures supply the source/message
association; they do not implement arbitrary guest-message authentication or
publication interlocks for blocking application receives.
The same retained receipt also covers vectors after a CLONE_FILES receiver exits
without acknowledgement: repeated peeks, truncated delivery, 253 installed FDs
and a subsequent empty receive. A queued file-table mutation cannot start before
publication from the terminal receiver's kernel output.
Receiver-local RLIMIT_NOFILE checks allow 0, 1, 2, 3, 4, 252, 253 or 254 free
slots, with and without control-buffer truncation. They check the exact installed
prefix after receiver exit, unknown origins, peek reuse and pipe EOF. The shared
table survives; the receiver's limit does not change the parent or shell service.
Socket acknowledgements establish ordering without sleep or scheduler races;
alarms and parent-death termination bound fixture failure. `test_resources.py`
runs this alongside the model and intercepted guest checks; `--case fd-handoff`
selects only these native publication boundaries.

The separate `--case fd-parcel` experiment queues the original rights inside a
private Unix socket, then transfers its endpoint in an outer message. It checks
253 rights, including O_PATH, over stream/datagram/seqpacket transports, sender
exit, stable SO_COOKIE, repeated inner peeks, retained outer peeks, peek discard,
truncation, partial/complete ordinary reads, queue closure and failed sends.
The remaining endpoint observes POLLHUP after the last parcel reference
disappears; pipe EOF checks release of enclosed writable descriptions. Native
self-references and two-socket parcel cycles both reach EOF in the tested kernel's
Unix GC. An expired GC observation is reported as unobserved, not collected.

Transport variants have different resource requirements, measured separately
from native controls under actual UID 2000:

| Candidate | Verified boundary |
| --- | --- |
| Direct parcel unwrap | The endpoint consumes one receiving slot; native SCM_RIGHTS delivers one more original FD under the same pressure. |
| Preconnected broker relay | Exporting the endpoint frees the receiver slot, but that reverse send can fail with ETOOMANYREFS where native receive succeeds. |
| Receiver-local reserved slot | Moving the endpoint with dup3 avoids reverse export and preserves the available payload prefix, provided an owned slot already exists below the receiver's FD limit. A retained slot above a lowered limit is rejected with EBADF. |
| pidfd_getfd pull | Dumpable providers supply regular, O_PATH and pipe FDs even to a nondumpable receiver. Protected providers return EPERM on the tested device. |
| io_uring registered-file candidate | io_uring_setup returns EACCES on the tested shell executor. The isolated probe also reports SIGSYS denial; this API is not a runtime dependency. |

The local-slot fixture receives 253 rights with 0, 1, 2, 3, 4, 252, 253 or 254
free slots. It checks distinct origins, O_PATH, protected receivers, outer peeks,
wrong-cookie rejection, pipe EOF and terminal loss before/after dup3, temporary
close and payload receive. Kernel-written outer and payload receipts survive
receiver exit; cleanup distinguishes the old endpoint number from its reuse by
an installed application FD. A queued table mutation remains blocked until
publication and private cleanup finish. The fixture preallocates its slot and
receipts: slot ownership across guest close_range, exec, table sharing and lowered
limits is not implemented by the adapter.

Admitted relay deliveries cover the same payload prefix, protected receivers,
terminal publication, cookie rejection and EOF. With 253 queued rights and 1-4
free receiver slots, the reverse export hits the native in-flight quota. The
[Linux Unix-socket check](https://github.com/torvalds/linux/blob/v6.12/net/unix/af_unix.c#L1731-L1747)
compares the real UID's in-flight rights against the sending task's RLIMIT_NOFILE.
Source-side controls also expose the extra send: with limits 64 and 252, direct
native sending of 253 rights succeeds, while enclosing those rights succeeds but
exporting the endpoint fails with ETOOMANYREFS. Limits 253 and 254 admit both on
this device. Failed-export cleanup must release the enclosed pipe writer. UID-wide
background traffic can invalidate a control; such a case is reported as
unobserved, not transport equivalence. Neither raising limits nor changing the
sender identity is used to bypass these comparisons.

These are native fixtures, not an application protocol. The fixture supplies
peer/cookie binding; native peers, cross-launch origin ownership, lazy admission
and full quota equivalence remain unestablished. pidfd_getfd additionally needs
a pidfd and terminal publication beyond its scalar syscall result. No candidate
changes application bytes, socket queues or limits in the shipped adapter.
The experiment is outside the default regression suite, and its report lists
limitations separately from successful assertions.

### Message-Origin Association Candidate

`test_resources.py --case fd-messages` tests a kernel-carried origin association,
separately from the application adapter. The native `fd_messages` owner captures an
ordered origin vector under the sender's table turn and queues the actual rights
inside a private seqpacket socket. Its kernel cookie selects the retained vector;
the outer message's bytes, delivery order and reused source FD numbers do not.
Lookup also checks the opposite side of the sender's connection key from the
production IPC authority. Sender and receiver resolve that key from their own
captured kernel sockets, not a fixture-supplied destination FD. An unknown
carrier, the sending side or a different connection cannot claim those origins.

A routed vector also retains its sending binding and registered custodian ID.
Its private header binds that ID to the actual cookie, connection, vector length
and fresh nonce. Reading the header installs no rights and consumes no packet;
the ID selects a verified private rendezvous, not the socket creator's PID.
The source-side claim verifies the actual carrier, destination store/binding and
complete issued header before pinning its local vector. The binding shares its
epoch/store lease without retaining SQLite or a socket. It survives registry
retirement until the last operation releases the vector. See the
[message routing contract](ipc-credentials.md#message-custodian-routing) for
validation, ownership and independent-process coverage.

The candidate's metadata lifetime uses a pipe writer in a second packet of the
private socket. The first packet can still hold 253 application rights; peeking
it installs no lifetime writer in the receiver. The authority retains only the
pipe reader and O_PATH origins, not writable payload descriptions or the carrier.
EOF is an event-driven retirement boundary after the last queued/duplicated
writer disappears. Each operation pins the immutable vector independently of
the registry: retirement removes lookup visibility and closes the monitor, but
the last operation releases its origins only after completion or worker join.
Reference changes belong to the supervisor loop; workers only borrow the vector.

The registry allocates no descriptors until first admission, then exposes one
epoll descriptor to its owner's event loop. Dispatch handles at most 16 ready
monitors per call without a periodic scan. It checks actual pipe EOF, not merely
the event bit or a raw record pointer. Stale readiness cannot retire a replacement
record. Unexpected monitor data is EPROTO and retains custody, not proof of
expiry. Failed admission leaves the pipe reader with its caller; successful
admission transfers it once. Explicit withdrawal requires proof that the message
did not escape. Ambiguous sends retain their record until EOF or whole-authority
teardown. Capture uses one allocation sized to the actual vector; lookup, pins
and retirement allocate and duplicate no descriptors.

A socket-only HUP is insufficient: native shutdown of both directions reports
HUP while queued rights remain readable. The fixture checks this explicitly.
The queued pipe writer instead survives RD/WR/RDWR shutdown, partial consumption
and carrier aliases, then reaches EOF on final release. Native Unix GC cases
check data-pipe EOF and metadata-pipe EOF for cycles over all three outer socket
types; timeout reports unobserved collection, not successful cleanup.

The comparisons cover reordered messages, two opens of one inode from different
mount views, unknown origins, sender exit, source-slot replacement, repeated peek,
control truncation, raw-read discard and exact descriptor balance. Publication
uses the existing `fd_delivery` and destination-table ordering, not another
annotation model. The fixture uses the runtime registry, not a second lifetime
implementation. The private `ipc_peer` agreement component separately checks
version, directional connection and features without touching application queues;
its binding retains the live IPC epoch beyond SQLite closure. Its contract and
independent-process checks are in [Unix IPC credentials](ipc-credentials.md#private-peer-agreement).
`ipc_peer_service` admits captured socket/control pairs asynchronously through
the existing filesystem worker and returns an owned peer on the supervisor's
completion dispatch. Cancellation and worker join retain pending inputs until
their last user finishes; there is no additional poll loop or database owner.
`ipc_origins` prepares and receives self-contained authenticated capsules on the
filesystem worker. Captured socket/data inputs and annotated outputs share the
same cancellation and join ownership. Independent-process checks cover custody
after source exit. Ancillary and addressed sends use the source capture and
preparation pipeline; the receive adapter expands selected ORIGINS_V1 messages
through the shared buffered worker and annotated publication contract.
Connection association
reuses `ipc_credentials`, including its store boundary and live-owner lease;
it is not a declaration that a native peer can consume a private carrier.
The authority's separate creation-time ancillary-format declaration is captured
in `md_ipc_binding`. It is immutable across aliases and owner changes; accept
inherits the selected format instead of changing an existing queue's meaning.
Carrier operations require both an `ORIGINS_V1` binding and a verified private
peer agreement. A native connection cannot be upgraded by control negotiation.
Production owners declare `NATIVE` until application adapters own that format.

`test_task_resources` checks allocation/EMFILE rollback, wrong connection sides,
duplicate cookies, stale events, malformed monitors, bounded batch retirement
and pinned vectors after owner teardown. A real worker inspects retained origins
after the source table, mount owner and registry have been released. Exact FD
balance is checked after join. These ownership tests belong to the regular model
suite, independently of the opt-in carrier experiment.

The same fixture checks the production connection contract through independent
worker processes, send-before-accept and accept-before-connect-publication,
sender exit, socket aliases, native endpoints, failed connect, listener revision
changes and last-owner retirement. Credential tokens in both directions validate
only on the opposite side; repeated inspection does not consume them. Workers
sharing a store agree on the link, but not on in-memory mount-anchor pointers.
Queued reuse of a user-bound name with the same destination and kernel PID is
explicitly ambiguous, not a latest-record lookup. Distinct destinations remain
distinguishable; a native listener replacement cannot confirm a captured peer.

This adds a real queued FD and send for the lifetime marker. With 253 payload
rights, native direct sending succeeds at tested source limits 64/252/253 where
the candidate's marker or outer export fails with ETOOMANYREFS. Limits 254/255
admit the candidate on this device. Failure cleanup releases all queued writers;
no quota or identity is changed. Receiver admission and reverse-export costs of
the other parcel experiments remain relevant. These differences block treating
the candidate as transparent native SCM_RIGHTS support.

An alternative exact `NETLINK_SOCK_DIAG` lookup checks inode and kernel cookie
without a socket-table dump, but gets EACCES under the tested UID 2000. This is
recorded as unavailable, not absence of the queried socket. The pipe-lifetime
candidate needs neither that API nor periodic diagnostics.

### Root And Filesystem Checks

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
Message-origin checks close every source connection and retain only the message
pins, with no additional descriptors for capture. Independent maintenance probes
must remain busy for the store and its lower layer. A sequential reopened worker
checks readonly attachments, rename, copy-up/unlink and foreign/replaced-store
rejection; releasing the message permits maintenance and restores the FD count.
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
