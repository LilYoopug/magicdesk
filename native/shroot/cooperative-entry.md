# Cooperative Syscall Entry

The namespace bootstrap exposes an opt-in, libc-independent entry descriptor
through the private `MD_AT_COOPERATIVE` auxiliary vector entry. Unmodified
programs ignore it and retain their syscall route. This is an internal versioned
contract, not an installer option. An isolated source-built musl fixture exercises
it without replacing the libc of any installed distribution.

## Call Contract

`cooperative_entry.h` accepts a syscall number and six original 64-bit arguments,
with one zero-initialized opaque handle per thread. ABI version 4 supplies a
runtime-owned syscall-offer table and accepts a caller-owned kernel continuation:

- `COMPLETED` supplies the raw Linux result, including negative errno.
- `DECLINED` has no committed side effect; the caller may execute its original
  SVC. Unsupported numbers, nested entry and inherited clients decline before
  request publication.
- `UNKNOWN` is a terminal protocol failure, never permission to replay.

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
| Worker | Stat/statx, directory reads, readlink, mkdir/unlink/rename/link/symlink and path access/ownership/mode operations use the existing filesystem dispatcher and checked task-memory copying. |
| FD | Existing regular-file `openat`, including writable/append/truncate flags, can use a checked native plan. Known ordinary-file `close` and `fcntl(F_GETFD/F_SETFD)` share that protocol and the existing file-table owner. Other `openat`/`fsopen` calls publish a request before their original kernel continuation; its exact notification admits descriptor publication. |
| Task | Other FD producers, filesystem/control calls, networking, identity, UTS, namespaces and SysV IPC enter the existing kernel-admitted dispatcher and completion owners in the original guest thread. |

The task route, failed registration and a worker's explicit pre-execution decline
invoke the kernel continuation and return `COMPLETED`. The callback receives the
original number and arguments for that continuation; the broker never calls a
guest function pointer. An unfiltered native-open plan also uses the callback
for a harmless zero-count futex wake before publication and before the native
effect, entering libc's cancellation check without cancelling after a successful
open. This is runtime-private preflight, not an application futex operation.
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
replays creation or truncation. A new file still needs that original notification;
accelerating opens of existing files does not remove birth publication cost.

### Native FD Plans

The engine can return one owned `O_PATH` anchor instead of a readable data FD for
an admitted existing regular file. Resolution, credentials, DAC, Landlock and
mount checks use the same engine. Identity is checked with `fstat` on the opened
pin, not a preceding pathname lookup. That verified identity and owned pin become
the existing FD-origin object without another open or stat. The guest reopens
that exact object through the
supervisor's proc FD, so rename, unlink and pathname replacement cannot redirect
the data open. Each open creates an independent native OFD. Only the guest owns
the data FD; the worker reserves its origin update before any effect.

A leaf assembly gate executes `openat`, ordinary-file `close` or `F_SETFD` and
publishes a native-result journal. Shroot's filter admits those numbers only at
that exact instruction; this is still a real kernel syscall, without its ordinary
notification/ptrace round trip. Application filters are not bypassed: their
installation revokes eligibility as described below. Known FD flags can be read,
or set to their current value, under the file-table turn without another kernel
effect. Other fcntl operations, selector-owned descriptors and active FD loans
retain existing handling.

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
Internal COW copying keeps its existing IO and publication contract. Nonexclusive `O_CREAT` may
use a plan when the file already exists. A missing name declines before creating
anything; exclusive creation goes directly to its original carrier. After a
declined creating-open probe, the caller skips speculative plans for 128 creating
opens, then samples again. This hint retains no pathname, errno or permission
result, does not affect ordinary opens, and never skips the engine or an effect.
Pin-only preparation does not read the guest umask: it cannot create a name.
The creating carrier captures the live mask normally, including after a decline.
New-file creation is not yet SVC-free. Directories, FIFOs,
devices, typed providers, executable snapshots and selected-object reopens retain
their current route before a data open. Inode-backed mount paths may produce a
plan; nested/native providers do not inherit that capability implicitly.

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

`execution_window` is transport-independent bounded resource reuse. The current
provider retains the existing inode read scope for consecutive eligible stat
calls and native-open preparation in a single uncomplicated store. Writable
preparation can join only while it needs no metadata mutation. COW returns the
explicit internal `MD_OPEN_NEEDS_WRITE` admission result before any change; the
executor ends its window and prepares once outside it. This is not a retry of a
completed open and never exposes an internal `EAGAIN` to the application.
Ready operations from the resource-waiting queue share the same window admission
as new requests; they cannot mutate metadata inside a preceding read scope.
Relative requests first capture the live
cwd or dirfd anchor under the existing FS/file-table turns. Path-only operations
borrow that retained anchor's descriptor; data and empty-path operations retain
their actual OFD capture. A relative read scope additionally requires the exact
base-mount anchor and descriptor, never a stale pathname or cached FD number.
Nested mounts/providers and restricted
native roots do not opt into this scope. Count/time expiry, provider changes,
delegation, mutations, parking and teardown end it. It caches neither stat
results nor credentials/permission decisions; native attributes are read anew.
The store gate supplies the existing writer/version ordering. Kernel IO or
descheduling can extend a scope; 100 us is not a real-time latency guarantee.

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
still cross kernel seccomp at the caller-supplied SVC**. This change does not accelerate
those calls through shared memory, emulate arbitrary BPF, alter filters, or
exempt helpers from them. Concurrent filter installation still affects any
kernel helper calls already in flight. A client-writable flag is an optimization,
not authority or a security boundary; shared memory is cooperative transport for
trusted guest code, not authentication against hostile writers in an inherited
mapping. Shroot's documented isolation limits remain in force.

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
unchanged. A thread with asynchronous cancellation enabled retains its native
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
The native journal fixture stops real `openat`, `close` and `F_SETFD` at every
instruction around the effect (64 cases, including failed open), verifies the
actual FD table and exercises restart classification. Entry tests additionally
hold 192 live opens, replace FD flags, use dup/close_range, replace/unlink a pinned
path, cancel a pending plan, exit before its effect and check exact inotify
open/close events. These complement the existing shared-table thread tests.
Writable tests check append/truncate, exact write-watch effects, pre-effect signal
cancellation, exhausted FD capacity and bounded creating-open resampling. The
inode fixture checks sealed-source COW and hardlink aliases, including explicit
write admission from a read window. Another 2000 concurrent park/publication
checks cover both requests and completed native effects.
`--statistics` reports direct completions, declines and kernel notification wakes
separately. `cooperativeDescriptors` counts FD-request adoptions and
`cooperativeNativeYields` counts avoided idle spins. FD receipts also contribute
to `cooperativeCompleted`; that total is not an SVC-free syscall count.
`nativeOpen`, `nativeClose` and `nativeFlags` count admitted native plans/flag
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
binary hashes. `--condition` records charging or other session conditions.
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
