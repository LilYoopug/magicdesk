# Cooperative Syscall Entry

The namespace bootstrap exposes an opt-in, libc-independent entry descriptor
through the private `MD_AT_COOPERATIVE` auxiliary vector entry. Unmodified
programs ignore it and retain their syscall route. This is an internal versioned
contract, not an installer option. Isolated source-built musl and glibc fixtures
exercise it without replacing the libc of any installed distribution.

## Call Contract

`cooperative_entry.h` accepts a syscall number and six original 64-bit arguments,
with one zero-initialized opaque handle per thread. ABI version 6 supplies a
runtime-owned syscall-offer table and a caller-compiled action driver,
`md_entry_invoke`, with these terminal results:

- `COMPLETED` supplies the raw Linux result, including negative errno.
- `DECLINED` has no committed side effect; the caller may execute its original
  SVC. Unsupported numbers, nested entry and inherited clients decline before
  request publication.
- `UNKNOWN` is a terminal protocol failure, never permission to replay.

The runtime can yield a cancellation checkpoint, the original kernel call, or
one admitted native effect to this driver. The action executes after the runtime
C frame has returned; the driver then calls the explicit continuation. This
keeps libc's forced cancellation unwind within caller-owned unwind metadata.
The shared worker request contains only the syscall number and arguments, never
libc callbacks or continuation pointers. An abandoned continuation is not
replayed. Channel ownership and native-effect retirement remain runtime-owned.

The fixed handle is three pointer-sized opaque words, not a copy of the runtime's
transport structure. The runtime interprets its channel/owner and reentry/backoff
fields; sequence and spin feedback live in the already-owned channel. No per-call
allocation, extra mapping or thread destructor is needed. Extending that channel
does not change libc's thread layout. An active handle must not be copied or
shared across threads; fork resets the child handle before reuse.

`syscall_catalog.h` and `entry_route.h` remain runtime-private. Bootstrap builds
the per-image offer table before guest execution. Libc checks a bounded byte flag
for ordinary or cancellation-point entry, without embedding syscall numbers or
engine routes. An unlisted syscall stays at its original SVC, without an indirect
handler call. The table is fixed for the image lifetime, not hot-swapped while
threads run. The implementation routes offered calls as follows:

| Route | Ownership |
| --- | --- |
| Caller | Native IO, time/futex, unknown calls and original-stack operations such as clone, exec and signal return retain their ordinary syscall site. No channel registration or synchronization. Dynamic FD selectors and kernel seccomp still apply. |
| Worker | Stat/statx/statfs, directory reads, readlink, mkdir/unlink/rename/link/symlink, access/ownership/mode/timestamp operations and path/link/FD xattrs use the existing filesystem dispatcher and checked task-memory copying. |
| Value | Scalar UID/GID reads use current registry credentials and the same user-namespace translation as the ordinary supervisor path. They neither retain a filesystem operation window nor cache caller credentials. |
| FD | Existing regular-file/directory `openat` and `openat2`, including O_PATH and writable/append/truncate flags, can use a checked native plan. Known ordinary-file close, dup/dup3, lseek and supported fcntl commands share that protocol and the existing file-table owner. Other open/fsopen calls retain their exact kernel publication carrier. |
| Task | Other FD producers, filesystem/control calls, networking, credential mutations and pointer-bearing queries, UTS, namespaces and SysV IPC enter the existing kernel-admitted dispatcher and completion owners in the original guest thread. |

The task route, failed registration and a worker's explicit pre-execution decline
invoke the kernel continuation and return `COMPLETED`. The callback receives the
original number and arguments for that continuation; the broker never calls a
guest function pointer. An unfiltered native-open plan invokes the optional
cancellation checkpoint in the guest before publication and before the effect,
never after a successful open. Ordinary wrappers leave it NULL; cancellation
wrappers supply libc's own check. No synthetic futex or other kernel call is
needed for this checkpoint. The kernel continuation receives only actual calls.
The musl integration uses **one SVC site with entry both enabled and disabled**,
preserving instruction-pointer-sensitive application filter policy. Callers that
omit this callback use the adapter's ordinary SVC, not its privileged raw gate;
such callers must not assume their own instruction address is preserved.

Thus every syscall has a route, but only worker operations and admitted native
plans avoid ordinary syscall interception. A common entry is not an accelerated
implementation of every family.

Registration is an authenticated supervisor trap. Eight persistent slots in the
existing per-image buffer pool are separate from its 32 ordinary response slots
and control reserve. Exhaustion selects the kernel route without waiting, with
bounded retry backoff; unsupported admission is remembered by that client. No guest socket,
temporary FD or helper thread is created. Fork cannot reuse an inherited client;
a fresh client registers separately. Thread exit returns its slot, and exec
replaces the descriptor and pool.

## Execution Ownership

`namespace_broker` routes kernel notifications and cooperative requests through
the same operation owner, task snapshot, argument decoder, FS/file-table ordering,
filesystem engine and result copier. Guest pointers are read/written with the
existing checked task-memory operations, not unchecked host dereferences.
Inaccessible protected memory can decline before output; a partial output fault
is a terminal `EFAULT`, not a replay. A request cannot supply credentials or a
namespace identity: the registered task selects a fresh authoritative snapshot.
Logical chroot, mount views, credentials, DAC and Landlock remain engine policy.

The task registry retains an immutable resource generation for repeated reads.
Each admitted read owns one reference instead of independently retaining every
namespace and credential object. Publishing changed credentials or resource
handles replaces that generation; old readers keep their exact snapshot until
release. Root/cwd are captured afresh under their filesystem owner, and resource
contents such as file-table entries and mount topology stay live. This shared
registry path also serves ordinary kernel notifications and filesystem RPC.
Retirement invalidates admission before releasing the registry reference; no
allocation is required to retire or reap a task.

For cooperative calls, the caller can capture two bounded path operands before
publication, using the same string-argument selectors as the worker. Bootstrap
compiles those selectors into a bounded per-image byte table; FD-only calls do
not construct a filesystem request just to discover that they have no paths.
Openat2 shares pathname capture, while the executor still reads and validates
its open_how structure. The capture is bound
to the request sequence and original addresses, never reused as a pathname or
permission cache. Uncaptured operands retain checked remote copying. The shared
`guest_copy.S` owner stops strings at the first NUL instead of copying a whole
page first; ordinary task-affine adapters use this same implementation.

Small stat/statx/statfs, readlink and xattr outputs travel in a sequence-bound
response buffer. After the engine finishes, the caller copies them to its own
destination. The supervisor converts only synchronous SIGSEGV/SIGBUS at the
published copy PCs into EFAULT, with an active copy owned by that task (or its
ordinary dispatch phase). Unrelated signals are delivered normally. A partial
copy is terminal; it never retries the operation. Directory reads retain
synchronous checked output because cursor advancement requires a successful
write. Large outputs retain the existing transport.

Except for admitted native plans below, FD-producing and task-affine calls reuse the existing kernel result-custody
protocol, file-table/OFD ordering, atomic ADDFD publication and protected-caller
transport. No second cooperative FD-delivery channel is introduced. An accepted
mutation is never retried because its result delivery was interrupted. Ordinary
blocking calls continue to wait in their guest thread, not in the shared worker.

The FD request has a distinct pending state: speculative worker scans never
execute it. The listener matches task, sequence, number and all six arguments
before adoption. A kernel denial before admission withdraws only that request;
at admission, a receipt retires the now-copied shared request record while the original
kernel continuation supplies the authoritative FD or errno. Interruption never
replays creation or truncation. Native-leaf eligible births instead use the
unpublished prepare/effect/commit protocol below; other creating endpoints retain
the original notification carrier.

### Native FD Plans

The engine can return one owned `O_PATH` anchor instead of a readable data FD for
an admitted existing regular file or directory. Resolution, credentials, DAC, Landlock and
mount checks use the same engine. Identity is checked with `fstat` on the opened
pin, not a preceding pathname lookup. That verified identity and owned pin become
the existing FD-origin object without another open or stat. The guest reopens
that exact object through the
supervisor's proc FD, so rename, unlink and pathname replacement cannot redirect
the data open. Each open creates an independent native OFD. Only the guest owns
the data FD; the worker reserves its origin update before any effect.

Native-leaf path resolution can retain the final O_PATH descriptor and its fresh
fstat together, avoiding a separate pathname stat followed by reopening. The
walk owns that descriptor until transfer or failure cleanup. Unpinned metadata
lookups still compare identity after opening an encoded-metadata file: a prior
pathname stat is not proof that the later descriptor names the same object.

Ordinary interception reuses this provider pin for eligible existing-file opens
too: the engine transfers it to the origin and opens the data OFD from that exact
pin, without another identity query or origin capture. Write/append/truncate use
the same authorization and COW preparation. Failure to allocate the data FD
releases the origin and precedes truncation. Creation keeps its existing
publication path; special endpoints decline the pin plan before effects.

A leaf assembly gate executes `openat`, ordinary-file `close`, `dup`, `dup3`,
regular-file `lseek` or admitted `fcntl` commands and
publishes a native-result journal. Shroot's filter admits those numbers only at
that exact instruction; this is still a real kernel syscall, without its ordinary
notification/ptrace round trip. Application filters are not bypassed: their
installation revokes eligibility as described below. Known FD flags can be read,
or set to their current value, under the file-table turn without another kernel
effect. F_GETFL/F_SETFL use the kernel's actual open description, and
F_DUPFD/F_DUPFD_CLOEXEC use the common FD-mutation owner. Directory seeks retain
their acknowledged cursor path. Selector-owned descriptors and active FD loans
retain existing handling. FD-only operations pin only the authenticated live
task's file table, not unrelated namespace resources.

Native FD admission reads a value-only kind/flags snapshot under the running
table turn, without temporary object references or a data-OFD capture. Unknown,
uncertain, provisional, channel and typed-wrapper slots are not native authority;
regular IO additionally requires a known regular-file kind. A dup3 destination
must also have an unambiguous selector observation.

The original file-table turn owns the operation until result bookkeeping and pin
retirement complete. The journal distinguishes not-started, executing, completed,
cancelled-before-effect and unknown outcomes. At a stop inside the assembly gate,
the supervisor captures the real result or skips an unexecuted effect before
delivering the signal/exit event. In particular, cancellation before `close` must
not retire a slot as if Linux had completed `close` with a late `EINTR`. Unknown
outcomes abandon the metadata claim, never replay the effect. No allocation is
required to publish an already-created native FD.

After a completed native effect the caller may return its exact result before
worker bookkeeping finishes. A distinct `RETIRING` state lets it queue one next
request in the separate call record, without reusing the native journal or pin.
The worker first commits the old FD result and releases its turn, then admits
that request. An ordinary kernel notification from the same caller also drains
the pending result before route selection. A signal stop cancels any unadmitted
next request before its handler can abandon the call frame. This is bounded
one-request pipelining, not an unbounded FD cache or a second descriptor table.
The synchronous receipt remains valid when the worker wins the publication race.

Writable, append and truncate opens prepare any required copy-up in the normal
engine. Preparation never performs the application's data open or truncation:
the guest kernel open owns those effects, including `EMFILE` before truncation.
Internal COW copying keeps its existing IO and publication contract. Nonexclusive
`O_CREAT` may use a plan when the file already exists. Missing regular files in
native-leaf eligible or host-permission catalogue directories use an explicit
unpublished birth owner.

Existing-open resolution and optional birth preparation share one namespace
walk and store admission. A missing native leaf does not restart resolution in
a separate create call. Publication still revalidates catalogue occupancy; for
native destinations `RENAME_NOREPLACE` checks physical occupancy atomically,
without an additional pathname stat. Physical absence is not cached across
operations.
The owned sequence is:

1. Prepare a hidden backing and O_PATH pin with the live guest identity, umask
   and parent policy. No name or CREATE event is visible, and no database
   snapshot is held across the caller's effect.
2. The caller opens that pinned object in its own file table. `EMFILE` precedes
   publication. The prepared FD-origin update includes provisional custody,
   including the application's actual CLOEXEC flag.
3. Revalidate the parent, mount/storage write policy and destination, then
   publish with `RENAME_NOREPLACE`. Only this commit makes the FD returnable.
   The watch owner translates the hidden move to CREATE/OPEN exactly once.

Ordinary implicit-metadata births use `mknodat(S_IFREG)` followed by an O_PATH
pin. Preparation opens no data description and needs only one spare worker FD;
the guest still owns the real data open. A denied/unsupported regular-file
mknodat leaves no name and uses the existing prepare/open path. Exceptional
ownership, ACLs and catalogue directories retain that path. Failure to capture
the pin removes the hidden name before returning the original error; a cleanup
failure is reported without retry. Conflicts never remove another creator's file.

If publication fails, the existing task-action/FD-loan owner closes the exact
provisional FD under its original table turn before the error is returned.
An exclusive loser preserves the winner and returns `EEXIST`; a nonexclusive
loser may resolve the winning name only after its private effect is compensated.
Cancellation before the effect removes the unpublished backing. Process death
releases kernel FDs; exclusive store maintenance collects orphaned backings.
There is no predicted close, deferred visible creation or cached negative name.
Default ACLs are inherited into the private backing before publication, using
the existing native metadata owner. They override umask exactly as ordinary
creation does, and survive later hardlink promotion. Host-permission directories
retain their real permissions and catalogue layout: a separate random backing
name becomes visible only with the namespace transaction. The staging name
never acquires a catalogue identity, so queued preparation events cannot become
application OPEN/CLOSE events. Its final move publishes CREATE/OPEN in order.
The commit receipt transfers ownership at SQLite commit, before watch-marker,
checkpoint or unlock retirement; a later error cannot authorize discard/replay.
Completion joins only the birth owner's exact operation gate, under the normal
count/time budget. A window held for another store ends before publication.
The publication transaction still commits independently before the guest's
successful return. Existing-file retirement needs no publication transaction.
Other ineligible providers retain their original creating carrier rather than
claiming native-plan semantics.
Pin-only existing-file preparation does not need an umask;
birth preparation reads it freshly through the retained proc-status descriptor.
FIFOs,
devices, typed providers, executable snapshots and selected-object reopens retain
their current route before a data open. Inode-backed mount paths may produce a
plan; nested/native providers do not inherit that capability implicitly.
Openat2 captures and validates the exact known open_how structure, including
BENEATH/IN_ROOT/symlink restrictions; extended sizes retain the original decoder.
O_PATH symlink endpoints also retain their existing route.

Deferred FIFO opens retain their helper and unpublished endpoint in the buffer
service. Their guest waits in an interruptible native poll. Completion wakes the
exact task; a signal cancels and reaps the helper before its ownership disappears.
The existing syscall-restart path preserves kernel `SA_RESTART` and libc's
cancellation PC. Neither the namespace worker nor a permanently stopped guest
waits for the peer. Temporary signal shields do not become application masks.

A release-published request has a monotonic sequence and one response receipt.
Conditional wakeups use sequentially consistent wait registration and state
publication. The existing worker drains a round-robin burst, bounded by 32
requests and a 100 us between-request budget, then services other work. An idle
channel does not add a periodic polling loop. Each endpoint uses a bounded 25 us
spin; four unsuccessful spins select immediate parking for 128 subsequent waits.
Only progress actually observed within the spin budget counts as a hit. A reply
already ready after a blocking wake, or seen after descheduling beyond the
deadline, cannot reset the miss history. The notification wake is acknowledged
after its immediate work (or resource-queue admission), avoiding a redundant
client wake/park. This is local feedback, not CPU-affinity or scheduler policy.
When an FD request is already visible, an idle worker yields to its listener
instead of spending the remaining spin budget waiting for another memory request.
Awake publication ends at the service's actual poll boundary, not after each
burst. The shared request/native-result check and producer's wake check form a
sequentially consistent handshake: work observed during parking forces a
nonblocking poll, which still services other sources before the next burst.
Clock reads are batched every eight empty worker iterations and 32 guest
iterations; the budget remains time-based, not a presumed fixed iteration cost.
At the request/time burst limit, the worker releases the store window and may
spend at most another 25 us retiring native effects it already admitted. It does
not consume a new request or predict a following close. With no outstanding
effect this final drain neither spins nor reads the clock.

The bootstrap resolves `__kernel_clock_gettime@LINUX_2.6.39` from the kernel's
`AT_SYSINFO_EHDR` once, before guest threads exist. Bounded guest spinning uses
that monotonic vDSO clock instead of an auxiliary syscall on every clock sample.
An absent symbol, unsupported image layout/version, or failed vDSO call retains
the raw clock syscall; failure of both selects parking. No ARM counter frequency
or fixed address is assumed. A cooldown which already selected immediate parking
does not read the clock. This changes neither application time syscalls nor
filter admission, and adds no libc dependency to the bootstrap.

The caller does not abandon accepted output memory on a wall-clock timeout.
Response/owner closure completes its event wait; launch cancellation terminates
the task. A kernel stop observed during admitted work is retained by the existing
broker event owner until that work and its resource turns retire. Only then can
signal/exec/exit handling release or reuse its mapping.
If the request has been published but not admitted, the stop cancels that request
under the broker lock before signal delivery. A handler may then `siglongjmp`
without a later worker write into abandoned memory. Reentry on a busy client
keeps the ordinary syscall path; abandoning that client does not authorize reuse
of an in-flight channel.

`execution_window` is transport-independent bounded resource reuse. The inode
provider holds only the store gate and its validated catalogue generation, not
a transaction or an unfinished read operation. Stat, FD metadata, access,
readlink, xattrs, creation, rename, link/unlink and attribute changes can share
that gate in a single uncomplicated store. Each operation resets its own
authorization checks, watch context and transaction state; writes commit or
roll back independently before completion. Local row invalidation remains
active, and publication recovery runs before each operation when needed.
An unchanged admitted read starts directly; completion with no transaction,
event publication or pending sync does not enter the write-retirement path.
Native attributes and policy are never cached by the window. COW and promotion
may therefore complete without discarding the gate or replaying preparation.
Explicit nested read scopes retain their stricter no-write contract and the
internal pre-effect `MD_OPEN_NEEDS_WRITE` result.
An interrupted preflight is not an executed operation: the original
signal/restart owner retains EINTR/SA_RESTART semantics instead of a saved
cancellation errno. Ready resource waiters use the same window admission as
new requests, including both operands of rename/link.
Relative requests first capture the live
cwd or dirfd anchor under the existing FS/file-table turns. Path-only operations
borrow that retained anchor's descriptor, as do fstat/fstatfs. Data/offset and
descriptor mutation operations which need the actual OFD still capture it.
A relative operation additionally requires the exact
base-mount anchor and descriptor, never a stale pathname or cached FD number.
Nested mounts/providers and restricted
native roots do not opt into this scope. Count/time expiry, provider changes,
delegation, parking and teardown end it. It caches neither stat
results nor credentials/permission decisions; native attributes are read anew.
Only the physical identity of a managed directory backing may survive between
operations under that gate; catalogue write admission invalidates it. Logical
permissions are projected from the current node and caller every time.
Catalogue lookup also has a per-query recent exact-key hint within the same
validated cache. It bypasses hashing, not row/generation validation. Local writes,
rollback and external versions invalidate the same entries; native leaf results
remain uncached. Path walking advances a cursor and materializes a new remaining
path only when following a symlink, retaining the existing root/resolve policy.
The store gate supplies the existing writer/version ordering. Kernel IO or
descheduling can extend a scope; 100 us is not a real-time latency guarantee.

Kernel notifications use this same bounded admission window when the listener
already has queued work. The worker checks readiness with a zero-time poll before
each additional receive, never spins for a future syscall, and releases the scope
before delegation, result delivery, queued resource turns or watch service.
The shared metadata catalogue selects stat/statx/statfs, access, readlink and
path/link/FD xattr reads for this route, including unmodified and filtered
programs. It also defines the read-only interrupted-SVC restart set. Cursor and
mutation calls are not added to that set. Protected memory and restricted native
roots retain the task-affine adapter when direct capture is unavailable.
Exactly one owner reads the listener. A request cancelled between readiness and
receive may return ENOENT; it does not authorize waiting for a replacement call.
The notification-batch call counter includes such receive attempts. This reuse
also applies to filtered programs, without moving their calls outside seccomp.

An inode-produced native-leaf anchor may retain a membership proof with its
exact O_PATH identity and store lifetime. Fstat can then skip reconstructing
membership through proc paths. Every call still reads live native attributes
and checks the catalogue first, so promotion to hardlinks, OCI or COW wins over
the original native representation. This retains neither modes/owners nor a
pathname result. Unknown/imported provenance uses the ordinary resolution path.

## Sandboxes And Debuggers

An installed application seccomp filter disables **shared-memory execution**, not
the entry API. Before
attempting a filter installation, the supervisor revokes the relevant task or
TSYNC thread group's authoritative eligibility. A failed installation leaves it
disabled conservatively. Already admitted operations may complete; later requests
use the kernel continuation. Fresh filtered clients are rejected at registration
without first issuing helper syscalls. Debugger tracing and protected native-root
restrictions also select the existing kernel-admitted route.

Thus the entry contract works in sandboxed programs, but **their filtered calls
still cross kernel seccomp at the caller-supplied SVC**. Already-queued calls can
share a bounded worker operation window, but they do not acquire the direct-entry
speedup. The runtime does not emulate arbitrary BPF, alter filters, or
exempt helpers from them. Concurrent filter installation still affects any
kernel helper calls already in flight. A client-writable flag is an optimization,
not authority or a security boundary; shared memory is cooperative transport for
trusted guest code, not authentication against hostile writers in an inherited
mapping. Shroot's documented isolation limits remain in force.

Kernel-admitted close uses compact bookkeeping even with an application filter:
PTRACE_GET_SYSCALL_INFO supplies the actual syscall and descriptor, never an
application-controlled TRACE cookie. The existing table turn and observed exit
result still own retirement. Filter denials do not retire a slot; debugger,
pending-loan and conflicting-owner cases retain the full path.

## Source-Level Libc Integration

`native/guest-exec-lab/build-cooperative-musl.sh OUTPUT` downloads checksum-pinned
official musl 1.2.5 sources and builds an isolated AArch64 sysroot, static probe
and dynamic probe. `integrate_musl.py` checks each source boundary before editing;
it is not a patch assumed to apply to arbitrary future releases.

The seven ordinary AArch64 syscall wrappers check runtime offers before binding
syscall registers. Native operations do not enter the handler or register a
channel. Unlike the old compiled catalogue, this is a table lookup rather than a
compile-time route decision. Initialization discovers the auxiliary-vector
descriptor after TLS setup and validates its ABI version, minimum size, callback,
table and reserved flags. A missing/incompatible descriptor retains the ordinary
syscall path. The per-thread handle starts zeroed, and `_Fork` resets the child's
inherited handle. No Bionic/ART dependency is added.

Only `cooperative_entry.h` and the small libc hook are imported into musl. Build
musl once for that caller ABI; subsequent transport, spin, channel-state and
syscall-catalogue experiments rebuild the native runtime, not libc. The current
provider stays in the existing freestanding bootstrap, whose pointer is supplied
through auxv. A separately mapped module can implement the same contract later;
libc needs neither a new `dlopen` dependency nor loader reentry to call it. The
provider remains mapped for the whole process image, including static binaries.
Changing the caller ABI or the libc cancellation integration still requires a
new libc fixture. There is no distribution-wide ABI rollout in this experiment.
`build-cooperative-probes.sh OUTPUT` rebuilds only the static/dynamic test programs
against an existing sysroot, keeping libc unchanged when adding workloads.

Cancellation-point assembly, clone/vfork and signal-return assembly remain
unchanged. The cancellation-point C wrapper offers FD calls through a continuation
that invokes musl's original cancellation assembly; its post-`EINTR` check is
unchanged. The native-open checkpoint uses musl's existing __testcancel.
A thread with asynchronous or masked cancellation retains its native
continuation. Non-cancellation-point wrappers do not change cancellation state:
a signal handler may `siglongjmp` past the entry frame. The supervisor's common
stop owner retires worker memory before delivering signals. Tests cover blocked
cancellation, signal abandonment without changing cancellation state, threads,
fork/exec, static/dynamic linking and real seccomp denial. FIFO tests cover pending
open cancellation, `EINTR`, `SA_RESTART`, actual data and exact FD counts, also
under a guest filter. Relative-path tests replace dirfd numbers, change cwd and
rename an anchored directory between calls.

`SHROOT_COOPERATIVE=0` disables handler invocation while retaining the same
compiled libc, offer table and kernel continuation. Keeping the table also keeps
the SVC site of offered calls identical in enabled/disabled controls. Pass it with the runner's `--env` option;
arbitrary Android shell environment variables are not inherited by a guest.
This fixture is not distribution-wide libc rollout or a patched Chromium build.

## Verification And Performance

`test_cooperative_runtime.py BUILD` runs buffer/execution-window contracts, the
filesystem dispatcher and an opt-in guest through the actual bootstrap and
supervisor as Android UID 2000. The guest checks pointer/partial-write faults,
native FD operations, signals and reentry, fork/exec, thread/slot churn,
dumpability, credentials, mounts/chroot, private PID namespaces, debugger fallback
and actual TSYNC denials. It checks kernel continuations including argument- and
instruction-pointer-sensitive filters, FD results and exclusive creation without
replay, and signal-handler `siglongjmp` with reused output memory. It also
exercises Landlock's distinction between metadata and file-data
access, and repeated SIGKILL/exit_group while peers use active channels.
The native journal fixture stops real `openat`, `close`, `F_SETFD`, `dup`, `dup3`
and `F_DUPFD_CLOEXEC` at every instruction around the effect (112 cases,
including failed open), verifies the
actual FD table and exercises restart classification. Entry tests additionally
hold 192 live opens, replace FD flags, use dup/close_range, replace/unlink a pinned
path, cancel a pending plan, exit before its effect and check exact inotify
open/close events. These complement the existing shared-table thread tests.
Writable tests check append/truncate, exact write-watch effects, pre-effect signal
cancellation, exhausted FD capacity and bounded creating-open resampling. The
inode fixture checks sealed-source COW and hardlink aliases, including explicit
write admission from a read window. Operation-window checks prove one gate and
generation read across native cycles, independent SQLite commit visibility,
rollback, live caller permissions, physical-directory reuse, exact birth
ownership and fresh external changes after release. Deterministic SIGKILL
tests also kill owners while their operation window is still held.
Another 2000 concurrent park/publication
checks cover both requests and completed native effects.
`--statistics` reports direct completions, declines and kernel notification wakes
separately. `cooperativeDescriptors` counts FD-request adoptions and
`cooperativeNativeYields` counts avoided idle spins. FD receipts also contribute
to `cooperativeCompleted`; that total is not an SVC-free syscall count.
`nativeOpen`, `nativeClose`, `nativeFlags`, `nativeDuplicate` and `nativeSeek` count admitted native plans/flag
queries, not necessarily successful effects (a stop can cancel a plan).
`nativeDeferred` counts completed effects whose caller returned before the
worker's receipt; a concurrent 1000-iteration contract verifies that retirement
cannot erase the following shared-memory or kernel-carried request.
`test_cooperative_libc.py BUILD MUSL_BUILD --rounds 7` uses real libc calls, verifies
that enabled/disabled modes have different direct-completion counters, and compares
relative/absolute/dirfd stat, create/rename/unlink, readonly opens with/without
CLOEXEC, writable opens, existing-file `O_CREAT`, truncation and native IO with
rotating modes. `files` uses exclusive new-file creation; `files-create` uses
nonexclusive creation of a missing name. Neither file-cycle workload writes data.
`--proot-prefix` adds a hash-verified
PRoot control under the same shell UID, CPU mask and exact static musl fixture;
native and PRoot share the physical control directory. PRoot's seccomp accelerator
must be active. Its environment is clean, without disabling seccomp or preloads.
`--profile` records a separate post-series pair; it does not explain individual
timed samples. `--sample-statistics` instead attaches the complete profile to
each timed sample. Broker prepare/capture/execute/reply elapsed times include
descheduling; execution includes the engine's nested store costs. Do not sum
those nested values. Profiling clock samples and diagnostic counter increments are off
on ordinary launches. The fixture also reports guest CPU time and context
switches; `--scale` lengthens short workloads. `--reference-build` interleaves
another entry-enabled runtime against the same libc/store and records verified
binary hashes. When that runtime has an older entry ABI, `--reference-musl`
selects its preserved matching static/dynamic libc fixture. Both routes must
pass their correctness and direct-completion assertions before timing; an ABI
mismatch silently falling back to syscalls is not a valid comparison.
`--reference-kernel` also interleaves the reference runtime with entry disabled,
so shared adapter changes are measured separately from cooperative acceleration.
`--busybox PATH` runs an unmodified musl-linked BusyBox through both modes in the
isolated store: shell pipelines, traversal, archive/restore, hashes, metadata,
hardlinks and symlinks. It does not replace an installed environment's libc.
`--condition` records charging or other session conditions.
Reports retain both mode medians and median within-round ratios; a ratio of
independent medians can mislead when storage latency changes during the series.
Imported and logically created directories are
separate `--directory-mode` workloads; their durability work is not interchangeable.
`test_watch_runtime.py BUILD --contracts`, resource `fs-buffer` checks
and both stock Chromium sandbox routes exercise unchanged entry paths.
Resource `fs-signals` isolates notification cancellation/restart stress; its
`MD_NOTIFICATION rebounds` counter distinguishes actual token replacement from
a successful run which did not encounter that race.
`readmissionsRetired` distinguishes completed-open handoff from a duplicate,
unexecuted admission. The runtime suite explicitly runs the broker-directory
contract, including deterministic live-token, identity mismatch, ioctl failure
and interrupted-token-check cases; a successful check never installs another FD.

`benchmark_cooperative.py BUILD --workload metadata --iterations 32768
--rounds 5 --cpu-mask 3 --logical-root --modes native shroot shroot-entry`
compares identical production workloads. `shroot-entry` retains real guest
pointers, task identity, lifecycle and completion ownership; the older
`cooperative-*` modes are controlled captured-request experiments, not production
timings. See [experiment measurements](../guest-exec-lab/cooperative-entry.md).

No storage-format change, runtime dependency, ART integration or kernel newer
than 5.15 is required. Extending SVC-free execution to more syscall families and
to filtered tasks remains separate from this complete routing contract.
