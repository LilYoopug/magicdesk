# Cooperative Entry Experiments

This laboratory compares captured-request experiments with the opt-in
[production entry](../shroot/cooperative-entry.md). Neither the fixture nor the
runtime replaces a distribution's libc. A separate fixture now builds patched
musl in an isolated sysroot. `shroot-entry` uses the real bootstrap API and
guest pointers; the `cooperative-*` modes isolate transport/engine costs with
captured operations. Do not treat their timings as interchangeable.
The shared-engine path, stat and directory-validation improvements also apply
to ordinary Shroot execution.
The [FD delivery experiments](#fd-delivery-experiments) below are historical lab
prototypes, distinct from the current caller-owned open/close implementation.
For the current ABI-6 result, see
[final paired measurements](#final-paired-baseline-and-filtered-routes) and
[final regression coverage](#final-regression-coverage). Earlier receipts retain
their original build boundaries; their fastest samples are not current guarantees.

## Independent Runtime Iteration

The libc fixture now imports only the versioned caller ABI and its small musl
hook. Runtime syscall offers replace the compiled syscall catalogue; the fixed
opaque per-thread handle no longer contains sequence/spin implementation fields.
The provider is currently part of bootstrap and remains mapped for the process
image. No guest `dlopen`, extra library deployment or hot replacement is needed.

Build the isolated libc once after changing its caller ABI or libc hook:

```sh
JOBS=2 sh native/guest-exec-lab/build-cooperative-musl.sh build/cooperative-musl
```

For subsequent runtime/transport changes, keep those libc artifacts and use:

```sh
cmake --build app/build/shroot --target bootstrap supervisor -j2
python native/guest-exec-lab/test_cooperative_libc.py \
  app/build/shroot build/cooperative-musl --checks-only
```

The runner hashes the staged libc/probes and checks that the local artifacts did
not change during execution. Its native static/dynamic controls exercise the
absent-provider path; guest controls use the same binaries with entry enabled
and disabled. This command does not run the timed benchmark loops. Runtime
changes can alter admission and routing without changing libc; changes to the
caller ABI or cancellation hook still require rebuilding it.
For new test workloads, relink both probes without rebuilding libc:

```sh
sh native/guest-exec-lab/build-cooperative-probes.sh build/cooperative-musl
```

The runner records their new hashes independently.

The version-4 boundary passed the full cooperative runtime checks in
`oci-services-cabbbb773c0b4f5ca9b21371eaaf39df.json` and the real-musl checks in
`oci-services-c31539e9ed784d6fa732fdd7281783ee.json` on 2026-10-17. These receipts
are under `build/cooperative-runtime` and `build/cooperative-musl-results`.
The latter has no timing samples and records unchanged libc/probe hashes.
Offer lookup adds a runtime table check where the previous catalogue could
constant-fold a native route; performance comparisons are deferred while the
device is in concurrent use. No new throughput claim follows from these checks.

## Paths Under Comparison

| Mode | Execution |
| --- | --- |
| `native` | Actual syscalls against a disposable native directory |
| `proot` | Same static fixture and native directory under shell UID 2000, fake root and verified seccomp acceleration; opt-in `--proot-prefix` |
| `shroot` | Same fixture through the built production supervisor and adapter |
| `shroot-entry` | Same production launch with the opt-in auxiliary-vector entry and original-SVC fallback |
| `cooperative` | Shared request/receipt and futex handoff to a separate filesystem owner |
| `cooperative-bounded` | Conditional wakeups and a bounded spin before futex sleep |
| `cooperative-adaptive` | Bounded handoff with temporary parking-only periods after repeated misses |
| `cooperative-leased` | Adaptive handoff with a bounded store read window across consecutive stat calls |
| `cooperative-leased-recheck` | Same read window, but recheck directory backing identity on every call |
| `cooperative-shared-files` | Separate address spaces sharing the kernel FD table; numeric slot publication, native client close |
| `cooperative-shared-tracked` | Shared FD table with real mount anchors, FD-origin bookkeeping, table turns, custody and worker close |
| `cooperative-fd-executor` | Private filesystem owner plus a small FD relay sharing only its own table with the client; delivery/close cost experiment |
| `cooperative-fd-executor-parked` | Same relay; client parks immediately while the relay awaits the filesystem owner |
| `engine` | Direct calls to the same engine in the fixture process, without a transport |
| `engine-read-lease` | Metadata-only lower bound holding the store gate for the whole loop; not a production candidate |

The engine modes estimate local-entry cost, not production readiness. Every
engine invocation obtains a fresh task snapshot, reads the actual creation mask
when needed, and uses the existing permissions. Ordinary modes acquire the store
gate and check SQLite's version per operation; leased modes retain that gate
as described below. The worker, not the request, supplies credentials and task resources.
No filesystem operations are batched, reordered or deferred across their return.
Writes remain kernel operations in the calling process. Close remains there
except in the tracked/shared and FD-executor experiments. In production Shroot,
close still has ptrace bookkeeping even when libc uses the original SVC.

The files workload performs 1024 cycles of exclusive create, write of 4096 bytes,
close, rename and unlink. Metadata runs only stat; directories run mkdir, rename,
rmdir and stat. The `opens` workload repeats open(O_RDONLY|O_CLOEXEC)/close.
Each invocation warms up 32 cycles. Modes rotate between rounds; reports include
both ratios of medians and matched-round ratio ranges.
The binary is installed inside the test store so the Shroot baseline does not
have an extra bind attachment absent from the direct engine.

Preparation creates `/bench` with guest credentials, not as a physical-permission
legacy directory. The root retains physical permissions by default; the explicit
`--logical-root` control assigns guest 0:0/0755 metadata to the root as well.
Every Shroot mode in that series uses the same root configuration. This matters:
physical-permission directories cannot reuse logical-directory identity proofs.
No root metadata is changed silently to improve a baseline.
The fixture asserts that an ordinary file cycle admits zero catalogue writes
and issues no object/directory sync barriers. Earlier runs without either of
these controls are not an equivalent baseline.

## Captured-Request Protocol

This section describes the laboratory channel. The production channel uses
supervisor registration, the existing worker and checked guest-memory IO rather
than this fixture's private worker/socket. Both use the same adaptive spin policy
and bounded execution-window primitive.

- Requests contain validated scalar values and captured absolute paths, not
  application pointers or client-selected authority. Supported calls and flags
  are deliberately narrow. Deferred/control opens fail explicitly.
- A handle belongs to one task. Fork inheritance and signal-handler reentry are
  refused before publication. The test interrupts an in-flight request and
  acknowledges the reentrant refusal before its original response is published.
- `DECLINED` means no operation was admitted, `COMPLETED` carries an executed
  result, and `UNKNOWN` means publication may already have changed the namespace.
  There is no automatic replay after an unknown result.
- Separate-table open results use a private SCM_RIGHTS socket and a sequence-matched
  receipt, never the owner's numeric FD. The sender closes its copy on every
  outcome. Received FDs are close-on-exec. A queued FD with a lost receipt is
  released by endpoint teardown; the exclusive create is not repeated.
- Shared-table modes require an actual `CLONE_FILES` relationship. Publication
  transfers a slot, not a duplicate; the sender must not close it after success.
  The reply reports publication separately from wake success. Tracked mode
  retires unacknowledged and retained slots after the sole client's exit.
- Sequentially consistent wait registration and state publication prevent lost
  conditional wakeups. Closing cannot be overwritten by request publication.
  Every spin budget expires into a futex wait; the operation deadline closes
  the channel and does not authorize replay.

Checks also cover malformed and stale requests, engine denial after credential
changes, protected (`dumpable=0`) callers, retained open-unlinked data and FD
balance. These component tests are not tests of application seccomp admission.

## Bounded Read Windows

The external owner can retain the existing store gate for at most 32 consecutive
stat requests, with a 100 us deadline checked between requests and after replies.
Each stat still completes separately and reads fresh file attributes from the
kernel. Only store admission/version validation and eligible directory backing
proofs are shared. Task snapshots and permissions are evaluated on every request.
There is no cached stat response or new storage coherence protocol.

The owner releases before a non-stat operation, before parking in futex, on
failed task admission and on channel teardown. Another namespace writer can then
acquire the existing gate; the next window rechecks the data version. The deadline
is not a real-time bound: descheduling or kernel IO can extend a held scope.
Out-of-band host mutations do not participate in this gate's consistency contract.

Tests cover raw `ftruncate` through a retained FD during a window, credential
changes within the same scope, an independent writer after a cached negative
lookup, release before parking/mutation, count/deadline expiry and teardown.
The whole-loop `engine-read-lease` control deliberately blocks namespace writers
and must not be confused with the bounded candidate.

This fixture has one actor, one store and an empty attachment set. A production
read-window owner must classify pure reads and release before cross-owner,
reentrant or blocking provider work. It cannot retain an arbitrary proc, mount
or control operation simply because its syscall is stat.

## FD Delivery Experiments

### Cost And Ownership

The real-musl baseline adds `opens` and `opens-cloexec` (4096 pairs). In
`oci-services-32cad17a759947d6a16236fb54f97c23.json`, the entry took 395.5 ms for
opens versus 394.9 ms with the entry disabled and 9.2 ms natively. One measured
entry invocation spent about 64 ms in engine execution, but still issued 16515
ptrace requests and 8237 stops. Close is therefore not an unmediated native
operation. Musl's O_CLOEXEC open also performs F_SETFD, adding another observed
FD mutation; the fixture preserves that libc behavior. This receipt lives in
`build/cooperative-musl-results`, not the captured-request directory.

The radical experiment removes per-open ADDFD/notification delivery and
per-close ptrace stops by sharing the kernel FD table with a separate-address-space
executor. The tracked variant uses existing `md_fd_origins`, mount anchors,
table ordering, mutation completion and operation-loan inventory. It does not
discard inode metadata or filesystem permission checks. The loan here models a
single actor's CLOEXEC slots; it is not yet a general process-tree ownership model.

Checks cover ordinary slot reuse, protected callers, CLOEXEC, retained data
after rename/unlink, refusal before mutation, signal-handler reentry and:

- Lost response before FD publication, without replaying exclusive creation.
- SIGKILL after publication but before consumption of the receipt.
- Exit after receipt with the application FD deliberately still open.
- Exact FD retirement and no catalogue-write/sync work for native-leaf cycles.
- Refusal of deferred FIFO opens without leaking the pin/control descriptor or
  publishing an FD origin. The lab does not implement deferred completion.

Final lab correctness and inode/native-leaf/credential/mount contracts passed
in `oci-services-84fa246f6f0f4882b45bf608af15bd1b.json`, including existing
hardlink promotion, COW/overlay, watch ordering and deterministic crash recovery.
Those engine contracts do not substitute for end-to-end executor lifecycle tests.

Sharing the whole filesystem worker also exposes its internal descriptors and
consumes application FD slots. Consequently it is **not a production candidate
as-is**. The separate FD-executor mode keeps SQLite, root and backing descriptors
private to the filesystem owner. It receives SCM_RIGHTS, publishes an actual
client-table slot and executes close. That relay currently tracks slot custody
only, not cross-process mount-origin publication; its timings isolate topology
cost and must not be represented as the fully tracked production design.

### Results

Seven rotating rounds on CPUs 0 and 1, logical root, 25 us adaptive spin:

| Workload | Native | Shroot | Current entry | Shared tracked | Separate FD executor |
| --- | ---: | ---: | ---: | ---: | ---: |
| Open/close, 4096 pairs | 14.3 ms | 421.3 ms | 423.9 ms | 75.3 ms | 207.5 ms |
| Create/write/close/rename/unlink, 2048 cycles | 88.1 ms | 411.9 ms | 358.4 ms | 205.9 ms | 322.2 ms |

Receipts in `build/cooperative-entry`:
`oci-services-43a20523177f43d58c7b2332d3a93d3a.json` and
`oci-services-4005c2f32ef4461ab9b3eaea2f043a63.json`.
Shared tracked gave 5.6x for open/close and 2.0x for the whole cycle versus
ordinary Shroot in these series. Earlier tracked runs gave 5.4-5.5x and 2.35x;
the lower-bound untracked shared-table result of 7.8x omits real FD bookkeeping.
The musl `files` workload has no 4096-byte write, so do not compare its absolute
duration to this table. The native control is native syscalls, not a new chroot
or PRoot measurement.

Topology matters. Five rounds restricted to CPU 0 measured 321.0 ms Shroot,
146.6 ms shared tracked and 213.8 ms with the separate executor
(`oci-services-335dcdf1b94b43759ed1afdc327f48bc.json`). Five unpinned rounds
measured 462.8, 59.5 and 70.7 ms respectively
(`oci-services-a3ab2e6c5d4f41a9ab0dfd0aed401753.json`). Three participants with
two active spinning waits can contend when constrained to two CPUs. These
controls support investigating that cost; they do not prove a universal ratio
or justify changing application affinity.

The phase-aware relay marks a request delegated while awaiting the engine so
the client parks immediately. A seven-round two-CPU control reduced median
client CPU from about 79 to 50 ms, but latency varied heavily: matched-round
speedup versus the ordinary relay ranged from 0.63x to 1.57x
(`oci-services-aeba8d4714914f2397bd84d679af29ec.json`). Retain it as an explicit
experiment, not the default waiting policy. Whole-invocation worker CPU and
timed-loop client CPU are not interchangeable or a total CPU measurement.

### PRoot Control

A fresh seven-round series interleaved all four modes, rotating their order on
CPUs 0 and 1 with the same logical root and 25 us lab spin. PRoot 5.1.107.92
and its dependencies were staged from the installed Termux prefix into the
disposable shell-owned directory. All modes ran under shell UID 2000. PRoot used
`-0`, `/proc` and `/dev` binds, and a clean environment; a preflight verified
that seccomp acceleration was actually enabled. Native and PRoot used the same
physical data directory and static binary. Shroot and the prototype used the
same native-leaf store on the same host filesystem.

| Workload | Native | PRoot | Shroot | Shared tracked |
| --- | ---: | ---: | ---: | ---: |
| Open/close, 4096 pairs | 9.7 ms | 192.6 ms | 335.8 ms | 73.1 ms |
| Create/write(4096)/close/rename/unlink, 2048 cycles | 70.3 ms | 327.7 ms | 357.9 ms | 134.9 ms |

Ratios of medians give 2.63x and 2.43x prototype speedup over PRoot; ordinary
Shroot took 1.74x and 1.09x PRoot time respectively. The prototype still took
7.51x native time for open/close and 1.92x for the complete file cycle.
Matched-round prototype speedups over PRoot ranged from 2.29x to 3.62x for
open/close and 2.02x to 2.71x for files. These are workload-specific lab results,
not production application or sandbox performance claims. The integration gate
below still applies, including internal FD exposure in the shared-table design.

Receipts in `build/cooperative-entry`:
`oci-services-55cc5b5b27a5475eb9e805ce0c47260d.json` (opens) and
`oci-services-962c6ca843d746a896506231e0be18d8.json` (files). Both passed the
fixture's correctness preflight; reports retain hashes and the PRoot diagnostic.

### Private Engine Experiments

These modes test the cost hidden by sharing the entire worker's file table:

- `cooperative-fd-sidecar[-parked]`: requests go directly to the private engine;
  only FD installation and close go through the table-sharing executor. Unlike
  the older relay control, these use real mount anchors, FD origins, ordered
  mutation completion and operation-loan retirement.
- `cooperative-fd-pipeline`: an engine and helper share runtime memory but have
  different kernel file tables. The guest shares only the helper's file table,
  not its address space. After SCM_RIGHTS installation, the helper publishes
  origins and replies directly to the guest, without an engine acknowledgement.
- `cooperative-fd-reopen`: the same topology, but ordinary files reopen a pinned
  engine descriptor through `/proc/self/fd`. It is a narrow cost control: reopen
  creates a new open description and is not a substitute for shared OFD offsets.
- `cooperative-fd-pidfd`: flags-zero, same-process pidfd_getfd copies the pinned
  source from the engine/leader table. It preserves the open description without
  per-open SCM messages. Availability is probed, not inferred from kernel version.
- `cooperative-fd-local-close`: the guest sends close directly to the helper.
  The real origin mutation completes before reply; only destruction of retained
  private anchors is deferred through a bounded 64-entry queue. A full queue
  wakes its owner and applies backpressure. Other requests and teardown drain it.

An anchor's final destructor must execute in the table that owns its descriptors.
Sharing pointers does not make descriptor numbers interchangeable. The engine
retains an extra reference until helper completion; helper-side close returns
the reference rather than accidentally closing an unrelated helper FD. The
engine stays the thread-group leader because its existing `/proc/self/fd` paths
resolve that table; helper inventories use `/proc/thread-self/fd`.

All new modes test protected callers and an installed guest filter rejecting
recvmsg. Sidecar/pipeline checks cover loss before publication, SIGKILL before
receipt consumption, exit with a retained FD, CLOEXEC, slot reuse and exact FD
balance. Optional `test-pidfd` also verifies shared offsets with a memfd, a
bidirectional socket and a pipe. Local-close checks include 192 opens followed
by closes without intervening engine requests, and EBADF on a repeated close.
These are fixed-actor fixtures, not Chromium sandbox or general lifecycle tests.

A three-participant run exposed a real lab protocol deadlock: waking one waiter
on the shared state futex could wake the owner instead of the guest. Separate
endpoint event words now distinguish reply and owner wakes. A regression parks
both endpoints, verifies that reply wakes only the guest, then closes the
channel to release the owner. Maintenance advances the owner event independently
of request state; the owner samples it before draining pending work so work
published during its wait registration cannot be lost.

The first seven-round fully tracked sidecar controls measured open/close at
14.50/196.93/333.50/76.73/185.49 ms for native/PRoot/Shroot/shared-tracked/parked
sidecar. File cycles measured 71.43/330.99/367.80/140.32/249.40 ms respectively.
Receipts: `oci-services-e024691eb2e84a70a456c2b7044819ca.json` and
`oci-services-d94fd57d5b214fd6873ff9dbbb903ef1.json`. Private descriptor ownership
therefore does consume much of the optimistic shared-table gain.

Changing only the copy mechanism was insufficient. With helper spin disabled,
seven-round open/close medians were 214.39 ms for the SCM pipeline and 203.60 ms
for self-pidfd, versus 195.75 ms PRoot and 65.44 ms shared-tracked
(`oci-services-c1e7826732d94640ab58ac44333220c7.json`). The proc-reopen control
was likewise essentially equal to SCM in its separate series
(`oci-services-47d917a4f09047d09723d48fc8c48395.json`). Unpinned results were
highly variable (`oci-services-6a8c0154458f46cdb14b6a66ce26b6af.json`); they do
not establish an unpinned advantage.

Local-close initially inherited the helper's zero-spin budget for its guest
endpoint too. That control was slower than pidfd (384.35 vs 310.65 ms;
`oci-services-9f868e4665c9415eb5f85f34217604c6.json`). The receiver budget is now
independent: `--helper-spin-ns 0` does not turn off the guest's adaptive spin.
Do not merge that control with the corrected endpoint-policy measurements.

Final corrected controls, seven rotating rounds, CPU mask `3`, logical root,
25 us adaptive guest spin and zero helper-receiver spin:

| Workload | Native | PRoot | Shroot | Shared tracked | Private pidfd | Private local-close |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Open/close, 4096 pairs | 13.26 ms | 268.18 ms | 432.97 ms | 89.32 ms | 289.48 ms | 257.96 ms |
| Create/write(4096)/close/rename/unlink, 2048 cycles | 87.17 ms | 424.76 ms | 500.62 ms | 253.53 ms | 389.84 ms | 357.42 ms |

Receipts: `oci-services-f88ecc4bbfb746408094313015dc019b.json` and
`oci-services-032da524397c4b21b9bd5818dcd7eb59.json`. Local-close improved on
the private pidfd topology in every paired round: 1.05-1.16x for opens and
1.02-1.31x for files. It does not recover the shared-table result. Open/close
remains approximately PRoot speed; file cycles improve by about 19% in ratio
of median speeds. These different time regimes must not be spliced into older
benchmark tables to imply a larger gain.

The file series also passed all inode, native-leaf, credential and mount
contracts, including hardlink promotion, watch ordering, COW and deterministic
crash recovery. A separate zero-spin metadata control passed with no per-stat
helper jobs: `oci-services-cdb08f0b9dc848a8ac1a88e6c43c9cc3.json`. Its helper
counts stay at setup/teardown values despite 4096 stat requests. These checks
exercise the lab transport and shared engine, not production libc integration.

Reproduce the corrected comparisons (replace workload/count for the file run):

```sh
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot \
  --workload opens --iterations 4096 --rounds 7 --logical-root \
  --cpu-mask 3 --spin-ns 25000 --helper-spin-ns 0 \
  --proot-prefix /data/data/com.termux/files/usr \
  --modes native proot shroot cooperative-shared-tracked \
    cooperative-fd-pidfd cooperative-fd-local-close
```

### Prepared Readonly Open

Two opt-in lab modes now split existing regular readonly opens after the real
engine's path, permission and Landlock checks. A linker wrapper around
`mdi_backing_open` is linked only into this benchmark. It returns an `O_PATH`
pin instead of opening data; the existing origin capture still runs. The engine
therefore retains two pins in this first prototype, not the minimal final plan.
Creation and write opens keep the previous pidfd delivery path.

- `cooperative-fd-plan`: the helper opens the pinned object in the client table,
  then publishes the real origin before replying.
- `cooperative-guest-plan`: the guest receives the engine PID, pinned FD,
  readonly/CLOEXEC flags and native device/inode identity. It opens
  `/proc/<engine>/fd/<pin>` itself, validates identity and publishes the actual
  result. The engine completes the ordered origin update and releases the pin.
  The next tracked operation waits for that receipt; close still uses the
  table-sharing helper. Ordinary read/write can use the new FD immediately.

This is not an unprotected pathname cache. A deterministic test removes the
name and replaces its contents between plan preparation and execution: the first
open must read the old pinned object and the next open the replacement. Other
checks retain CLOEXEC, exact FD balance, 192-open/close bursts and controlled
death before plan consumption or after committed publication. A guest seccomp
filter denying `openat` produces EPERM, cancels origin publication and releases
both pins; the operation is not replayed through the unfiltered helper.

These are cooperative, single-actor controls. Concurrent FD users, fork/exec,
death between native open and receipt publication, arbitrary guest filters and
production proc-access policy are not admitted by this experiment. It does not
establish production sandbox compatibility or mutation/watch semantics for
prepared creation, truncation or COW. Plans are used once; reusable plans would
need coherent invalidation. The backing store is not an ordinary guest pathname
tree, so simply supplying a root prefix is insufficient.

Device controls on 2026-10-17, seven rotating rounds, 4096 open/close pairs of
one existing file, CPU mask `3`, logical root, 25 us adaptive guest spin and zero
helper-receiver spin:

| Series | Native | PRoot | Shroot | Private local-close | Helper plan | Guest plan |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| First | 12.98 ms | 274.03 ms | 457.73 ms | 258.49 ms | 298.69 ms | 221.16 ms |
| Repeat | 19.16 ms | 299.78 ms | 491.25 ms | 282.29 ms | not run | 227.47 ms |

Receipts: `oci-services-6f88c209326340d08eaf755e368a2fec.json` and
`oci-services-8fa042d4dffd43f5bb2a80608ca6c37e.json`. Guest-plan ratios of medians
are 2.07/2.16x versus ordinary Shroot, 1.24/1.32x versus PRoot and 1.17/1.24x
versus local-close. Paired-round median improvement over local-close is only
1.15x in both series, and individual rounds regress. The helper-plan control
is slower than local-close in all seven paired rounds. Removing FD transfer
alone is not enough; removing a participant on the open path matters here.

The three-round 2048 create/write/close/rename/unlink negative control
(`oci-services-c603a4367f304e388b2ed389131152a0.json`) leaves every measured
creation on pidfd delivery. Local-close/guest-plan medians were 382.64/322.87 ms,
but their paired-round speed ratio was 0.995x, with large environmental variation.
Do not attribute a creation improvement to the readonly plan.

A separate three-round decomposition
(`oci-services-f36dbb3ae4cf4195b474b79e2013fe1e.json`) measured native/inline
engine/shared-tracked/guest-plan at 12.42/63.25/77.39/209.25 ms. Inline engine
omits origin tracking and transport; shared-tracked includes origins but exposes
the engine's private descriptors, so neither is a deployable substitute. The
separate instrumented engine invocation reported 4128 opens including warmup,
zero write admissions, zero transactions, 8256 directory-check misses and four
SQL prepares. Its phase timers overlap and must not be summed as disjoint costs.

Reproduce the first series by replacing the modes in the previous command with:

```sh
--modes native proot shroot cooperative-shared-tracked \
  cooperative-fd-local-close cooperative-fd-plan cooperative-guest-plan
```

### Queued Native Completion

Three further opt-in controls retain the private engine table and real FD-origin
accounting while reducing work around each readonly open:

- `cooperative-guest-pin` transfers ownership of the one prepared `O_PATH` pin
  into the origin anchor. The plan borrows it until completion; origin capture
  no longer opens a second pin. This uses a lab-only `md_view_capture` wrapper.
- `cooperative-guest-queued` also executes close in the guest. A bounded
  single-producer completion queue records actual open/close results. Capacity
  is reserved before the native side effect. The engine drains records in order
  before the next request or parking, updating real origins and ordered FD
  mutations. Close needs no synchronous acknowledgement unless the queue fills.
- `cooperative-guest-window` additionally admits readonly opens to the existing
  bounded read window: at most 32 requests or 100 us, released before mutation
  or parking. Each request still resolves its path and checks access; this is
  not a reusable pathname plan or permission cache.

The timed workload includes the final completion drain. In the readonly series,
helper invocation counts remain at five setup calls, independent of iteration
count: three pidfd checks and two creation checks, not one job per open/close.
Tests exercise 192 outstanding opens, FD-number reuse, queue backpressure at 64
records, unsigned queue-index wraparound, denied native close, and controlled
guest exit after posting a close without waiting for its retirement. Denied
close retains the origin until table teardown. Replacement, denied-open and
exact FD-balance checks also run for these variants. The queue tests synchronize
on actual backpressure rather than relying on a delay.

Seven rotating rounds on 2026-10-17, with the same affinity/spin settings as
above, measured 4096 readonly open/close pairs of one existing file:

| Series | Native | PRoot | Shroot | Guest plan | Queued | Read window |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| First window control | 13.88 ms | 202.20 ms | 325.66 ms | 166.80 ms | 64.68 ms | 48.18 ms |
| Repeat, reserved queue and timed drain | 14.81 ms | 199.85 ms | 331.80 ms | 165.67 ms | 62.07 ms | 48.78 ms |

Receipts: `oci-services-8994608027624565b9ec525d1389a5d0.json` and
`oci-services-9162f7fd84e34c01ba5d90b823b97458.json`. The repeat's read-window
ratio of medians is 3.40x versus the guest-plan control, 4.10x versus PRoot and
6.80x versus ordinary Shroot; it remains 3.29x slower than native. Its paired
round improvement over guest-plan has median 3.48x and range 2.39-3.78x. Compare
within each series: dividing the earlier 221 ms result by the later 49 ms
would conflate different timing regimes. The intermediate single-pin series
(`oci-services-1f7042e4671742c98d3e87f44134e1a1.json`) measured guest-plan,
single-pin and queued medians of 215.87, 157.42 and 83.00 ms respectively.

The seven-round 2048 create/write/close/rename/unlink control
(`oci-services-fb9d223a349545558a9f14ec8e510a89.json`) measured native/PRoot/
Shroot/guest-plan/queued/window medians of 89.82/336.86/377.54/265.92/245.87/
238.63 ms. Creation still uses pidfd delivery, so this is not evidence of a
threefold creation speedup: window versus guest-plan is only 1.11x by medians,
with paired rounds ranging from 0.89 to 1.52x. The same run passed inode,
native-leaf, credentials and mount contracts. All controls remain single-actor
lab executions, not an integration test of patched libc in ordinary Shroot.

Reproduce the final comparison with the previous command and:

```sh
--modes native proot shroot cooperative-guest-plan \
  cooperative-guest-queued cooperative-guest-window
```

### Integration Gate

The experiments establish headroom, not accelerated production open/close.
The queued control joins real FD-origin publication with native guest execution
for a fixed actor. Production admission still needs concurrent FD users,
fork/exec, CLONE_FILES/unshare, dup/close_range, arbitrary task death, FD reuse,
resource limits and cancellation without replay. In particular, controlled
death tests do not close the interval between a native side effect and posting
its completion record. Application seccomp
and debugger admission remain production owners; `dumpable=0` tests do not
prove compatibility with every filter. No filter was disabled in these runs,
but the new lab transports themselves have not run inside Chromium's sandbox.

Do not add a permanent sequential relay for all syscalls based on the unpinned
best case. Keep ordinary path requests direct to their engine; evaluate a
descriptor-only completion path and dependency-aware waiting separately.
All prototypes use existing kernel interfaces available by 5.15. Storage family
17, production FD transport and the default runtime are unchanged by these
FD-delivery experiments.

## Measurements

Device measurements on 2026-10-16 used authorized shell UID 2000, no forced CPU
affinity, and the same disposable store for the engine modes. Two seven-round
files series with a 25 us spin budget gave these medians:

| Series | Native | Shroot | Cooperative | Bounded | Inline engine |
| --- | ---: | ---: | ---: | ---: | ---: |
| First | 44.8 ms | 217.1 ms | 175.3 ms | 72.6 ms | 81.8 ms |
| Repeat | 36.6 ms | 217.0 ms | 161.8 ms | 82.5 ms | 87.4 ms |

Artifacts in `build/cooperative-entry`: `oci-services-29c297d649ad4f37ac933031d9ed7d6a.json`
and `oci-services-baba2e9f953b4805ad2b420e9f949b3b.json`. These are local run
receipts, not repository dependencies. The repeat's median voluntary client
switches fell from 3067 to 691. Caller CPU increased with spinning; whole-worker
CPU includes warmup/checks and must not be treated as exact timed-loop CPU.
The bounded two-process path occasionally beating the inline path reflects
different scheduling/frequency conditions, not a lower computational cost.
Do not turn these figures into a universal speedup claim.

A three-round zero-spin control did not improve the plain cooperative path
(167.8 versus 147.8 ms). These measurements preceded production integration.
Single-core, CPU contention, idle cost and metadata workloads matter.

Five rounds of 16384 stat operations gave medians of 26.5 ms native, 505.4 ms
Shroot, 513.6 ms cooperative, 112.4 ms bounded and 136.5 ms inline engine
(`oci-services-f1dd7e76b893498dbbd5c1d4beb52a33.json`). Merely bypassing syscall
interception did not improve this workload until the handoff was changed.

A single-core control exposed the fixed spin budget's failure mode: 193.2 ms
versus 86.5 ms for immediate parking. The peer cannot progress on that CPU while
the caller spins. The adaptive experiment parks without spinning for 128 waits
after four missed budgets, then probes again; only useful request/response
handoffs reset the miss history. This is a measured candidate, not a universal
scheduler policy or a promise that all contention patterns are handled.

With this feedback, the final seven-round unpinned series measured 220.2 ms
Shroot, 170.7 ms cooperative, 78.8 ms bounded and 83.6 ms adaptive
(`oci-services-aed273463d9b423e82ea93887dfccbdd.json`). Median voluntary client
switches were 5128, 3066, 588 and 918 respectively. The adaptive candidate thus
retained about 2x over the first protocol in this series. Its caller CPU was
58.6 ms versus 47.0 ms for immediate parking; this remains a latency/CPU tradeoff.
The final three-round CPU-0 control measured 94.0 ms cooperative, 192.7 ms fixed
spin and 92.7 ms adaptive (`oci-services-239d5a1cb6cf48d1b2889a38e2e302a6.json`).
The large single-core regression was absent with feedback in this control.

The shared-engine change passed the inode, native-leaf, credentials and complete
mount contracts, including overlay/COW and Landlock. Production watch/RPC checks
passed in `watch-runtime-a96989a3f5be47f48f08d861585f8fac.json` under the native
build directory. Host-native hardlink/FIFO import subchecks remain unavailable
under shell policy; the logical guest cases are separate and passed. At that
stage, no real patched-libc application or browser had been tested.

The shared engine now reuses physical-directory validation within a locked
operation only. Profiling the file cycle counted 11 reused checks per cycle;
permissions, ACLs and Landlock are still evaluated. Tests include changed mode
and credentials, catalogue-write admission and backing replacement between
operations. See [store transactions](../shroot/inode-store.md#transactions).

### Stat Follow-up

Controlled follow-up runs used 32768 stat calls, rotating modes over seven rounds
on CPUs 0 and 1 (`--cpu-mask 3`), without changing frequency policy. Lookup now
carries the already observed native-leaf attributes and resolved parent, avoids
general-purpose hex formatting, and hashes cache keys by words. A saved-binary
comparison first measured about 9-10% improvement in the cooperative stat path
from attribute reuse alone (`oci-services-f0daad55492f42fa8c25e023fce17b15.json`).

The larger gain came from bounded read windows:

| Series | Root permissions | Native | Adaptive | Leased | Leased/native |
| --- | --- | ---: | ---: | ---: | ---: |
| Directory-proof control | Physical | 33.8 ms | 203.7 ms | 115.3 ms | 3.41x |
| Logical-root control | Guest 0:0/0755 | 40.4 ms | 194.5 ms | 91.4 ms | 2.26x |
| Resolved-parent follow-up | Guest 0:0/0755 | 30.3 ms | 196.5 ms | 83.4 ms | 2.76x |

Receipts: `oci-services-1db15f0279ee40469269e0a0abdba596.json`,
`oci-services-ef18b8833b234ea9a6d5a1c78b570326.json`, and
`oci-services-bb33190722b24fdb8de6b5eab5405b0a.json`. The last series' recheck mode
took 118.1 ms, separating gate/version amortization from directory-proof reuse.
All inode, native-leaf, credentials and mount contracts passed on that build,
including fresh attributes, permission denial, replacement, hardlink promotion,
overlay/COW and Landlock. Fixed-width identity encoding is checked against the
previous formatter for 4096 input pairs and scoped IDs; no format changes.

The native baseline is actual native syscalls, not a separate chroot invocation.
Its time varies substantially even under affinity, so these runs do not prove
a universal 2x target. The final single-CPU control (16384 calls, three rounds)
measured 25.2 ms native, 236.1 ms adaptive and 167.9 ms leased
(`oci-services-19a9012fdcdc45db9ff8330fc15af903.json`). The read window still helps,
but process handoff dominates when both peers must share one CPU. Bounded spinning
also spends caller CPU; reduced wall time is not the same as reduced total CPU.

A five-round 1024-file-cycle control measured 38.5 ms native, 187.0 ms ordinary
Shroot, 71.3 ms adaptive and 77.8 ms leased, versus 75.0 ms for the saved older
adaptive binary (`oci-services-f12025d6ad2b4ba4b302edbc0b81e1e8.json`). File
mutations do not retain read windows. These scattered samples do not establish
a file-cycle benefit from the window, nor justify enabling it everywhere.
A narrower nine-round repeat with 2048 file cycles measured 143.50 ms adaptive
and 143.74 ms leased, a 0.16% difference
(`oci-services-01a47aec14be49219597ce2ff9ae1b2a.json`). This control found no
material file-cycle regression, not a claim that the paths are always equal.

The final production watch/import/RPC suite passed in
`watch-runtime-0c08c2d459ab4634a0d3ec5796c0e376.json`, including protected
callers, filtered FD receive, independent owners, watcher rollback and 10000
descriptor exchanges. The same two native-host import limitations noted above
remain explicit; no logical guest test was weakened.

## Reproduce

Use a fixture-enabled native build and the configured MagicDesk MCP connection:

```sh
cmake --build app/build/shroot --target benchmark_cooperative -j4
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --rounds 7 --spin-ns 25000
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --workload metadata --iterations 16384 --spin-ns 25000
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --rounds 3 --spin-ns 25000 --cpu 0
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --workload metadata --iterations 32768 --rounds 7 --spin-ns 25000 --cpu-mask 3 --logical-root --modes native cooperative-adaptive cooperative-leased cooperative-leased-recheck engine
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --workload opens --iterations 4096 --rounds 7 --spin-ns 25000 --cpu-mask 3 --logical-root --modes native shroot shroot-entry cooperative-shared-tracked cooperative-fd-executor
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --workload opens --iterations 4096 --rounds 7 --spin-ns 25000 --cpu-mask 3 --logical-root --proot-prefix /data/data/com.termux/files/usr --modes native proot shroot cooperative-shared-tracked
```

For the PRoot file-cycle comparison, replace `--workload opens --iterations 4096`
with `--workload files --iterations 2048`. The prefix supplies PRoot assets only;
the benchmark still runs through the shell service, not as the Termux app UID.

`--profile` adds a separate instrumented invocation, not a benchmark sample.
`--reference PATH` interleaves a saved older fixture's inline/bounded/adaptive paths.
`--modes` selects a subset; `engine-read-lease` is available for metadata only.
Omit `--logical-root` to repeat the physical-root control.
`--contracts` also uploads and runs built `test_inodes`, `test_native_leaf`,
`test_credentials` and `test_mounts` targets. Production watch/RPC checks use
`test_watch_runtime.py BUILD --contracts`. The cooperative runner records binary
hashes and device/kernel identity and removes only its own disposable directory.

## Production Integration

`test_cooperative_runtime.py BUILD` verifies registration, checked pointers and
partial writes, signals, fork/exec, thread-slot reuse, credentials, mount/chroot
views, debugger fallback and actual TSYNC denials through the production runtime.
`test_watch_runtime.py BUILD --contracts`, resource `fs-buffer` and both stock
Chromium sandbox routes are separate regression checks of the ordinary path.
Stock Chromium does not opt into the new entry.

The final entry/buffer/dispatcher receipt is
`oci-services-6687d20f665c4ccc991c178e92cce622.json` in
`build/cooperative-runtime`; watch/import/RPC passed in
`watch-runtime-22c5c97e2e9b43ed892390dbc828be81.json` under the native build.
The 125-check `fs-buffer` run passed separately. Its earlier concurrent run
with Chromium failed a protected full-table xattr export with `ETOOMANYREFS`
from SCM_RIGHTS. Competing in-flight FD pressure is a hypothesis, not an
established root cause or a fixed leak; the separate repeat does not prove that
concurrent stress case resolved. No resource assertion was weakened.

Production measurements on 2026-10-16, with rotating modes and the logical root:

| Control | Calls / rounds | Native | Ordinary Shroot | Opt-in entry | Speedup vs Shroot |
| --- | --- | ---: | ---: | ---: | ---: |
| CPUs 0 and 1 | 32768 / 7 | 53.9 ms | 988.6 ms | 226.8 ms | 4.36x |
| CPU 0 only | 16384 / 5 | 27.0 ms | 429.3 ms | 255.5 ms | 1.68x |

Receipts: `oci-services-4f3d1b49a9334b178616d46ba6a72b12.json` and
`oci-services-afff40497d16439eb7c7b39b8ec098e5.json` in `build/cooperative-entry`.
These are real guest pointers and execution ownership, not the captured-request
lower bound. The latter measured 122.2 ms in the two-CPU series. Production is
still 4.2x native there; this does not establish the earlier proposed 2x target.

The single-CPU control initially regressed: 516.8 ms entry versus 423.5 ms Shroot
(`oci-services-fbed8ca5f38247bcae4ff2784908ed83.json`). Feedback incorrectly
counted replies after a blocking wake or an expired spin as useful spinning.
Only an attempted spin with timely progress now resets misses; ready responses
avoid clock calls entirely. A wake notification also returns after immediate
work, not before it. The corrected single-CPU result above retains a benefit
without changing application affinity or frequency policy.

A 12-round alternating file-cycle control (2048 cycles per mode, CPUs 0 and 1)
measured 374.2 ms ordinary Shroot and 368.4 ms opt-in entry
(`oci-services-7318e046aea34c1684ed482818b37695.json`). All create/rename/unlink
requests declined before registration and retained their original path. An
earlier seven-round series had measured 350.4/366.0 ms respectively
(`oci-services-7d60ae109ea54b37afd80741fbb1d6dc.json`); these varying samples do
not establish a file-cycle speedup or a stable regression.

```sh
python native/guest-exec-lab/test_cooperative_runtime.py app/build/shroot
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --workload metadata --iterations 32768 --rounds 7 --cpu-mask 3 --logical-root --modes native shroot shroot-entry
python native/guest-exec-lab/benchmark_cooperative.py app/build/shroot --workload metadata --iterations 16384 --rounds 5 --cpu 0 --logical-root --modes native shroot shroot-entry
```

Those controls preceded the common route and direct mutation support below.

## Common Entry And Real Libc

The current [runtime contract](../shroot/cooperative-entry.md) shares a syscall
catalog between the libc adapter and engine: native/original-stack operations
stay at their caller, supported filesystem operations use the worker, and other
adapted families use a caller-owned kernel continuation. FD results retain the
existing custody/publication protocol. Application filters still decide in
kernel seccomp, at the same caller SVC site whether entry is enabled or disabled;
this is not SVC-free filtered execution.

The updated runtime receipt
`build/cooperative-runtime/oci-services-30880adfc8cd416b8e69bd792c4698fc.json`
passes direct mutation/cursor checks, FD/pipe/socket/O_PATH completion, exclusive
create without replay, argument/IP-sensitive filters, TSYNC, and signal-handler
`siglongjmp` before reuse of output memory. The broker now cancels a published
but unadmitted request before delivering its task's stop; admitted work retires
before that stop can release caller memory.

The real-musl fixture builds official checksum-pinned musl 1.2.5 for AArch64,
with a private thread client and source-level ordinary syscall wrapper hooks.
It tests static and dynamic linking, four concurrent metadata callers, blocked
pthread cancellation, signal abandonment without altering cancellation state,
fork/exec and actual seccomp denial. Cancellation-point assembly and
clone/vfork/signal-return assembly are deliberately unchanged. This is a tested
libc integration, not a distribution-wide deployment or a patched browser.

Seven rotating rounds on CPUs 0 and 1 used a guest-created directory and logical
0:0/0755 root. The baseline is the **same rebuilt libc**, with entry disabled via
the runner's explicit `--env SHROOT_COOPERATIVE=0`. Counter assertions verify
zero direct completions in both disabled correctness runs and over 6000 in both
enabled runs. No runtime affinity or frequency policy was changed.

| Workload | Native | Kernel route | Entry | Kernel / entry |
| --- | ---: | ---: | ---: | ---: |
| Relative stat, 32768 calls | 31.4 ms | 1085.8 ms | 419.4 ms | 2.59x |
| Absolute stat, 32768 calls | 58.9 ms | 1093.9 ms | 219.9 ms | 4.98x |
| Exclusive create/close/rename/unlink, 2048 cycles | 58.7 ms | 568.1 ms | 509.1 ms | 1.12x |
| Native pread/pwrite, 65536 pairs | 71.7 ms | 108.6 ms | 81.4 ms | Not an entry-path speedup |

Receipt: `build/cooperative-musl-results/oci-services-f39c692e00ce480db94e4da29bc92988.json`.
The preceding valid series (`oci-services-ed4c0a304404443ab2c2a7cd73308f0c.json`)
measured 2.32x relative stat, 4.72x absolute stat and 1.06x files. Native IO keeps
the same syscall path in both modes; its variable samples cannot be attributed
to direct dispatch. Absolute stat remains about 3.7x native in the final series,
and relative stat about 13.4x: the 2x-native target is not established.

Two initial comparisons, `oci-services-6b14b3bb2306487cb65be207a69cad58.json` and
`oci-services-d238efe2d070450ea5a50f23f18a7b25.json`, are **invalid for route
comparison**: the disable variable was set outside the runner and was not
inherited by the guest. Both modes entered the worker. They remain local evidence
of the fixture error, not speedup/regression measurements.

### Imported-Directory Control

`--directory-mode imported` retains physical-permission directory metadata,
instead of silently replacing it with a logical-root/native-leaf setup. Three
rounds (`oci-services-776daa65b9be41be8772377ade53d21a.json`) measured 997.7/429.5 ms
for relative stat and 1012.0/257.4 ms for absolute stat (kernel/entry), but
2724.1/3055.9 ms for files. A seven-round file repeat measured 2757.9/2897.7 ms
(`oci-services-73c5c97435d747f1834a7eb4decc292a.json`). This is a remaining
performance concern, not a claimed improvement.

Separate instrumented runs in the latter receipt measured 2903.5/2812.5 ms,
with identical 47196 SQLite steps, 6146 commits and 4097 object-sync calls.
Ptrace requests fell from 39044 to 18563 and worker queue submissions from
4101 to 4. Commit time alone was about 1.1 seconds; these nested instrumentation
durations must not be summed as independent costs. The comparison does not show
extra storage work, but it also does not establish absence of a timing regression
under all scheduling/storage conditions. No durability rule was relaxed.

### Regression Receipts

The ordinary watch/import/RPC suite passed in
`app/build/shroot/watch-runtime-f871afb0434e4628a7db2523ebf5c18e.json` and all 125
checks passed in `resource-fs-buffer-results.json` under the same directory.
The two host-native import limitations noted above remain explicit.
Stock Chromium passed four namespace cases and three set-ID cases plus the
expected unadmitted-helper rejection in stage receipts
`browser-stage-results-561c20bf030242e282435bf8882fcb6e.json` and
`browser-stage-results-36af561350ba4fbd80d7f12d410a0a62.json`. These are sandbox
compatibility regressions; stock Chromium does not use the patched musl.

```sh
sh native/guest-exec-lab/build-cooperative-musl.sh build/cooperative-musl
python native/guest-exec-lab/test_cooperative_libc.py app/build/shroot build/cooperative-musl --rounds 7
python native/guest-exec-lab/test_cooperative_libc.py app/build/shroot build/cooperative-musl --directory-mode imported --workloads files --rounds 7 --profile
```

`--checks-only` skips timings. `--profile` adds untimed instrumented invocations,
not samples for the median. Uploaded libc/probe hashes and route counters are
part of the report. Extending SVC-free FD/control execution or mirroring arbitrary
application filters remains separate work; the current common mechanism retains
kernel admission and its established ownership protocol for those calls.

## Relative Anchors And FD Admission

The next implementation retains cwd/dirfd anchors under the existing resource
turns instead of duplicating a descriptor for each pathname-only operation.
Eligible relative stat calls now share the same bounded read scope as absolute
ones, after capture verifies the exact base-mount anchor. Metadata and rights
are still checked for each call. Tests replace dirfd numbers, change cwd, and
rename the directory behind an open anchor.

ABI 3 gives `openat` and `fsopen` an explicit FD-request state. The listener
adopts only an exact task/sequence/number/argument match. The copied channel
record retires at admission; the original kernel continuation, existing
ADDFD/result custody and protected-caller transport still own the actual result.
An earlier experiment waited for operation retirement after the kernel result;
that redundant wait is removed. FD effects never run before kernel admission,
and failure or cancellation does not replay them. This is not SVC-free open.
An idle worker also stops spinning when a pending FD request needs its listener.

The new cancellation test exposed an existing kernel-route FIFO deadlock: a
stopped guest could not process cancellation while its isolated open helper
waited for a peer. Buffer-service completion now parks the guest in an
interruptible native poll, reuses kernel syscall restart and retains helper/FD
ownership through reaping. Static and dynamic musl check cancellation, signals
with and without SA_RESTART, real FIFO data, filters and exact descriptor counts.
The same checks passed natively under the Termux app UID; native FIFO creation
under the shell UID was denied on this device, so that is not an equivalent
shell control. Guest checks use shell UID 2000.

### Charging-Session Measurements

These are separate seven-round, rotating-mode series with the same compiled
libc, CPU mask `3`, and profiling pinned to that mask. The user connected a
charger; do not compare absolute times directly with preceding unplugged runs.
No other test suite ran during the final timing series.

Logically created directory, receipt
`oci-services-de54aae027a84cd8b298fda97e2754e3.json` under
`build/cooperative-musl-results`:

| Workload | Native | Kernel route | Entry |
| --- | ---: | ---: | ---: |
| Relative stat, 32768 | 29.75 ms | 1103.67 ms | 263.25 ms |
| Absolute stat, 32768 | 44.92 ms | 1097.19 ms | 251.35 ms |
| Dirfd stat, 32768 | 26.53 ms | 1054.05 ms | 233.63 ms |
| Create/close/rename/unlink, 2048 | 52.76 ms | 584.84 ms | 486.80 ms |
| Native pread/pwrite, 65536 pairs | 74.87 ms | 83.06 ms | 84.05 ms |

Imported-directory receipt `oci-services-491f270094324cf8aece3a79e6fd3c11.json`:
files 2876.97/2984.08 ms and dirfd stat 1079.15/272.55 ms (kernel/entry).
The earlier late-FD-receipt experiment
`oci-services-867bc645b65c46c29061238ac3109a5b.json` measured files
2969.68/3369.90 ms. These sequential experiments suggest that early record
retirement helps, but are not a thermally controlled causal estimate.

The final imported profile retains identical 47196 SQL steps, 6146 commits,
4097 object syncs and 64 directory syncs. Ptrace requests fall from 39044 to
18563; queued filesystem submissions from 4101 to 4. In its separate profiled
pair, wall time rises 428 ms while commit time alone rises 479 ms
(1159.98/1638.59 ms). These nested durations must not be added. This is evidence
of storage/scheduling sensitivity, not extra durability operations or proof of
zero regression. The remaining 3.7% median file difference is explicitly not
claimed as a speedup; neither storage format nor durability was weakened.

The current entry improves relative metadata and logical-directory file cycles,
but does not establish the 2x-native target. Native IO retains its ordinary
syscall path, so its approximately 1% mode difference is not an entry speedup.

### Cancellation And Final Regression Checks

Higher-frequency signal tests exposed two additional ordinary kernel-route
ordering defects, independent of patched libc:

- A process-directed signal can expire a notification and restart the same SVC
  before the requested ptrace stop. The existing admission owner now replaces
  only an expired token for the exact task, syscall, site and arguments.
- A restarted open can request delegation while the original worker still owns
  its completed FD. At the shared stop, that retained result supersedes only the
  exact unexecuted admission. Neither creation nor truncation is repeated.

The failed runs are retained locally in
`build/cooperative-notification-rebound-failure.json` and
`build/cooperative-completed-open-conflict-confirmed.json`. The latter records
the conflict in `DELEGATE_CANCEL`. Final `resource-fs-buffer-results.json` passed
133 checks and `resource-fs-signals-results.json` passed 46, including cleanup.
Both encountered the corrected completed-open handoff
(`readmissionsRetired=1`). Their token-replacement counter stayed zero: those
successful runs do not claim to have repeated that rarer ordering.

Runtime receipt `build/cooperative-runtime/oci-services-0919f3df238f48bdb776eff0cde7cad3.json`
explicitly runs the broker-directory fixture as well as buffers, dispatcher and
entry guest. Deterministic token tests reject live old requests, all changed
arguments, PID, number, architecture and instruction address; ioctl errors leave
the old request intact and EINTR retries only token validation. Successful
replacement sends no result and installs no FD.

Watch/inode/import/RPC receipt:
`app/build/shroot/watch-runtime-5b8f44b989174c2b9712cf4f904962ac.json`.
Chromium stage receipts:
`browser-stage-results-2756b645ad43431aa862920d902b0ec2.json` and
`browser-stage-results-cec283e5d03348678e3d91de61fe9bfd.json` in the same directory.
All four automatic-route runs and three set-ID runs verify actual JavaScript,
installed filters and the selected namespace/identity path; the fourth set-ID
case verifies rejection of the unadmitted helper. No `--no-sandbox` was used.
These headless checks do not establish hardware GPU rendering or strict kernel
namespace isolation. Missing session services and GPU initialization diagnostics
remain in their reports, not silently classified as clean desktop sessions.

A preceding concurrent resource/browser run returned ETOOMANYREFS during
protected descriptor capture. The isolated native `fd-lifecycle` control confirms
the kernel's in-flight SCM_RIGHTS quota (65 rights with nofile=64) and release on
queue cancellation; this does not prove the precise source of the earlier
pressure. Low-limit suites and browser workloads were subsequently run serially.
One earlier native-only FD-balance assertion did not recur; it now reports exact
counts and descriptor targets. Its cause remains unproven, not a claimed runtime
leak fix. None of these assertions or kernel limits were relaxed.

## Per-Sample Profiling And Native Clock

The unplugged follow-up records profiling with each timed sample, rather than
attributing a later profile pair to an earlier median. `--sample-statistics`
retains store/engine/broker counters; the C fixture records guest user/system CPU
and voluntary/involuntary switches outside its elapsed-time interval. `--scale`
lengthens short workloads. `--reference-build` uploads a second checked runtime
and interleaves its entry-enabled mode against the same musl and store.
Both mode medians and median within-round ratios are reported. These are not
frequency-locked or thermally controlled measurements.

Initial imported receipt `oci-services-5ea81902efd345c2b6f9877f55dd5e05.json`
in `build/cooperative-musl-results` reproduced the slowdown: file-cycle medians
2540/3605 ms (kernel/entry). The operation counts stayed essentially identical:
47196 SQL steps, 6146 commits, 4097 object syncs and 64 directory syncs. Slow
entry samples also had larger worker CPU and store costs, not just longer
handoffs. This alone does not identify the cause of those larger costs.

Broker phase profiling in `oci-services-73b668557652409a936d4b4c4e4d9ae1.json`
separates prepare, cwd/FD capture, engine execution and output delivery. For one
32768-dirfd-stat entry sample, their elapsed totals were 19.85, 2.43, 57.85 and
22.16 ms out of 173.01 ms. These costs exclude some ordering/retirement and
transport work. Engine/store timings are nested, not additive.

The confirmed avoidable work was auxiliary clock syscalls during bounded guest
spinning. Bootstrap now resolves the kernel's versioned arm64 vDSO clock, with
raw-syscall fallback; it does not cache application attributes or replace libc.
Immediate-parking cooldowns do not sample the clock. Diagnostic atomic counters
are also conditional on `--statistics`, like the rest of the broker profile.

Eight-round logical-directory A/B receipt
`oci-services-4398a7d69dcb4bb7898c8ec0e22e9678.json` compares the pre-vDSO entry
with vDSO, before the final diagnostic-counter gating:

| Workload | Native | Kernel route | Pre-vDSO entry | vDSO entry |
| --- | ---: | ---: | ---: | ---: |
| Relative stat, 32768 | 22.14 ms | 779.00 ms | 156.45 ms | 139.34 ms |
| Absolute stat, 32768 | 39.84 ms | 843.61 ms | 148.60 ms | 138.17 ms |
| Dirfd stat, 32768 | 28.62 ms | 863.23 ms | 160.82 ms | 141.69 ms |
| File cycles, 2048 | 63.40 ms | 407.72 ms | 373.50 ms | 364.46 ms |

This establishes an additional metadata improvement, not the 2x-native target.
The small file-cycle difference is not a claimed independent speedup.

Imported A/B receipt `oci-services-d013c0bd46df427a8ef3262b498d78cd.json` attaches
profiles to all eight rounds. Median within-round file ratios are 0.969 against
the kernel route and 1.011 against pre-vDSO entry. The ratio of independent
mode medians would misleadingly suggest an 8% vDSO regression: samples crossed
between roughly 1.2 s and 2.8-3.1 s regimes. Commit time alone changed from
0.33 s to 1.47 s, with the same counts; both entry versions and the kernel route
show that change. Slow imported-storage tails remain observable, not declared
fixed, and no fsync/transaction guarantee was weakened. Profiled dirfd stat's
paired entry/reference ratio was 0.914.

The longer native-IO control, `oci-services-ab72efbef71642daa7ccc2150a24468a.json`,
used seven rounds of 524288 pread/pwrite pairs: native 295.43, kernel 354.03,
entry 338.60 ms. The loops had no broker IO notifications; entry completions
were only six setup/teardown operations. This does not reproduce the earlier
short-run entry regression, nor establish that entry accelerates native IO.

Final unprofiled long A/B receipt
`oci-services-0c428bdc362d402bad0b8864a9b15069.json` includes diagnostic-counter
gating and four rotating rounds. For 262144 dirfd stats: native 116.12, kernel
5263.23, entry 798.04, reference 845.00 ms; the paired entry/reference ratio is
0.939. Native IO (524288 pairs) measured 301.51/342.89/356.29/333.49 ms in the
same order, with entry/kernel 1.046 and entry/reference 1.072. This opposite
direction from the preceding IO control remains recorded, not filtered out:
the current series do not establish a stable native-IO regression or improvement.

Final UID-2000 runtime receipt
`build/cooperative-runtime/oci-services-8372b47db54d4252839b0386fc13115a.json`
includes the vDSO parser/live clock, dispatcher, exact notification identity,
FD/cancellation, fork/exec, seccomp/TSYNC, Landlock and lifecycle contracts.
`build/cooperative-vdso-fs-buffer-results.json` passed 133 checks and
`build/cooperative-vdso-fs-signals-results.json` passed 46. Both now encountered
the rare expired-notification replacement (`rebounds=1`, protected mode 8);
their completed-open retirement counter stayed zero. Watch/inode/import/RPC:
`app/build/shroot/watch-runtime-05ef603fa91b4c4ea58f002ffea11949.json`, 22 checks.
Stock Chromium stages `browser-stage-results-3edd7a1d77734359b1ae1e4527dca5e6.json`
and `browser-stage-results-ddf3d63b28f5441782f80853d7aa23d5.json` in the same
directory passed the automatic and forced set-ID routes, including rejection of
an unadmitted helper. All verified runs retain `noSandbox=false`.

### Unplugged Follow-Up

The user disconnected the charger before this separate seven-round series.
The same binaries and CPU mask `3` were used with rotating modes and no parallel
test workload. Both static/dynamic musl correctness paths passed again before
timings. Do not merge these samples with the charging series above.

Logical-directory receipt
`build/cooperative-musl-results/oci-services-52650a0b31d840b09887bcd40b8b5233.json`:

| Workload | Native | Kernel route | Entry |
| --- | ---: | ---: | ---: |
| Relative stat, 32768 | 25.66 ms | 777.33 ms | 167.63 ms |
| Absolute stat, 32768 | 39.86 ms | 800.86 ms | 159.60 ms |
| Dirfd stat, 32768 | 25.45 ms | 801.15 ms | 167.25 ms |
| Create/close/rename/unlink, 2048 | 49.57 ms | 414.65 ms | 361.21 ms |
| Native pread/pwrite, 65536 pairs | 69.61 ms | 71.74 ms | 86.22 ms |

Native IO samples span roughly 45-99 ms across the modes. Their unchanged kernel
route and this scatter do not establish a transport-related speedup or explain
the median difference. The 2x-native target remains unachieved.

Imported-directory receipt
`build/cooperative-musl-results/oci-services-e7e0e2a916ff4838be115bbf014e6f9c.json`:
files 2403.94/2812.79 ms (kernel/entry, 17% slower), dirfd stat
732.26/158.79 ms. Individual entry file samples range from 1130.94 to 2969.96 ms.
The separate instrumented pair reverses the difference: 1184.18/1120.94 ms,
with commit time 336.25/334.07 ms and identical 47196 SQL steps, 6146 commits,
4097 object syncs and 64 directory syncs. Ptrace requests remain 39044/18563;
worker submissions 4101/4. This confirms reduced transport work, not elimination
of the imported-file performance concern. Its cause and an improvement require
further controlled experiments; no storage durability shortcut was introduced.

### Production Native FD Plans

The captured-request lab's 48.78 ms open result is not a production measurement.
The production route now uses the authenticated task context, checked paths,
the ordinary FD-table turn and one engine-owned O_PATH anchor. The data open
executes in the guest; the native journal and supervisor stop owner retain the
actual result through signals and exit. No libc rebuild was needed: the static
probe, dynamic probe and libc hashes stayed unchanged in the runtime reports.
The musl CLOEXEC workload also performs a redundant `fcntl(F_SETFD)` after each
open. The general known-FD flag route removes that extra intercepted operation,
not a benchmark-specific special case.

After the user reported the CPU available, seven interleaved rounds under UID
2000 and mask `3` produced this synchronous-receipt baseline:
`build/cooperative-musl-results/oci-services-38ee013e9536481888ab1b37072b4a5f.json`.
PRoot uses its seccomp accelerator, a clean environment, staged hash-verified
assets and the exact same static libc fixture. Native and PRoot use the same
physical control directory; Shroot uses its logical-directory store.

| Workload | Native | PRoot | Shroot kernel route | Native plans, synchronous |
| --- | ---: | ---: | ---: | ---: |
| Readonly open/close, 4096 | 8.44 ms | 268.91 ms | 448.05 ms | 94.84 ms |
| Readonly CLOEXEC open/close, 4096 | 9.10 ms | 271.14 ms | 557.39 ms | 110.97 ms |
| Create/close/rename/unlink, 2048 | 50.02 ms | 396.95 ms | 549.89 ms | 249.88 ms |

These are mode medians, not a guarantee at every CPU frequency. Entry open
samples ranged 78.35-139.96 ms, CLOEXEC 86.60-152.83 ms and file cycles
233.29-290.75 ms. Paired entry/kernel ratios were 0.212, 0.199 and 0.448.
The earlier user-loaded run (`oci-services-bc8f3b345e194890a8a9b423270bfc0e.json`)
preceded the FD-flag route and is not mixed into this series.

Correctness work found and fixed two protocol issues: parking on a native-plan
offer before executing it, and treating a pre-effect close cancellation as a
completed Linux close with late EINTR. Plan decline is also now explicit before
typed/native provider data opens and before writable/create/truncate effects.
An initially deadlocked pin-replacement fixture parked the opener with its
FD-table turn held while its peer used the ordinary FD-capturing path. The peer
now uses an admitted absolute cooperative rename/unlink, preserving the intended
concurrent object-replacement assertion without needing that same FD-table turn.

`build/cooperative-runtime/oci-services-c604bb54c8bd49dab8541207052ee802.json`
passed all inode, dispatcher, buffer, native-journal and entry checks, including
exact inotify open/close counts. The journal test executes real kernel effects
with a breakpoint at each instruction: 64 cases across successful/failed open,
close and F_SETFD. It distinguishes cancelled-before-effect from completed EINTR.

The subsequent bounded retirement pipeline lets a caller return the kernel
result and queue one next request while the previous owner finishes bookkeeping.
It does not release the FD-table turn early or reuse its journal. It drains the
old result before a subsequent ordinary kernel notification, and cancels an
unadmitted next request before delivering a held signal. Runtime receipt
`build/cooperative-runtime/oci-services-1926fab01ac840e9ab0260f53de13e6c.json`
passed the full suite plus 1000 concurrent next-request publication races;
2373 real effects used deferred retirement. Performance is measured separately
against the preserved synchronous build, not inferred from this count.

The seven-round five-mode musl A/B receipt
`build/cooperative-musl-results/oci-services-d034fd1743b840eeaf672f3e3327b6d8.json`
measured 95.46/88.56 ms for plain opens and 107.66/117.13 ms for CLOEXEC
(pipeline/synchronous); file cycles were 262.48/261.09 ms. It did not establish a
consistent additional gain from pipelining alone.

The longer 16384-iteration follow-up, again seven rotating rounds,
`build/cooperative-musl-results/oci-services-2f550d1bc1f24235a62815242c0f0e62.json`:

| Open/close workload | Native | PRoot | Shroot kernel | Pipeline | Synchronous |
| --- | ---: | ---: | ---: | ---: | ---: |
| Plain, 16384 | 25.37 ms | 1072.20 ms | 1706.62 ms | 387.11 ms | 379.61 ms |
| CLOEXEC, 16384 | 28.34 ms | 1050.11 ms | 2183.78 ms | 354.02 ms | 352.90 ms |

Within-round pipeline/synchronous ratios were 0.958 and 0.974. Mode medians
slightly favor synchronous, illustrating why this small difference is not a
robust new speedup claim. The major gain is the native FD plan and flag route:
pipeline/PRoot paired ratios 0.357/0.343 and pipeline/kernel 0.223/0.164.
Static/dynamic libc correctness, including FIFO cancellation, SA_RESTART and
filter denial, passed for both versions before each series. The prebuilt libc
and both probes were hash-identical throughout.

The original lab harness was then rebuilt with the current engine and compared
in the same seven-round run, mask `3`, 4096 readonly CLOEXEC open/close pairs:
`build/cooperative-entry/oci-services-5d8e3b4ca506482785d32e320080316e.json`.

| Mode | Median | Sample range |
| --- | ---: | ---: |
| Native | 12.53 ms | 9.06-17.83 ms |
| PRoot | 270.74 ms | 221.67-274.78 ms |
| Shroot kernel route | 439.60 ms | 387.65-483.64 ms |
| Production entry | 99.58 ms | 80.94-111.94 ms |
| Lab guest window | 103.55 ms | 92.64-122.10 ms |

This fixture calls the entry ABI directly, without musl's cancellation preflight
or follow-up CLOEXEC fcntl. It is therefore a separate comparison, not additional
samples for the musl series. The production mode retains real task/FD ownership;
the lab mode still uses its fixed captured actor. All harness correctness checks
passed. This run did not reproduce the earlier 48.78 ms, but its lab control used
different spin parameters, as established below. It does not prove that
production ownership doubled the cost. It establishes a 2.72x speedup over
PRoot and 4.41x over the kernel route by mode medians in this run. The production
entry remains about 7.95x native, so the 2x-native target is still open.

### Matched Spin Parameters And Writable Plans

The 48.78 ms receipt (`oci-services-9162f7fd84e34c01ba5d90b823b97458.json`)
selected a 25000 ns lab guest spin and zero helper spin. The 103.55 ms lab
comparison above used the harness's 10000 ns guest default and unspecified
helper spin. Repeating with the former explicit parameters, seven rounds and
mask `3`, produced `build/cooperative-entry/oci-services-0979d59fb66841caad80b717fea2a6d7.json`:
native 11.41, PRoot 265.57, kernel route 442.27, production entry 89.76 and
captured-request lab 59.71 ms. Transport tuning accounts for a substantial part
of the discrepancy; neither exact 48.78 ms reproduction nor production at that
speed has been established. The lab still omits production task/lifecycle work.

The production follow-up removes a pathname stat and repeated anchor stat by
checking the actual O_PATH pin once, retains worker-awake state until the real
service park boundary, and admits writable preparation into bounded read windows.
COW explicitly leaves that window before mutation. Data opens, truncation and
their kernel events remain in the guest, under the same FD-table turn and native
result journal. Extending the total worker burst to 250 us did not consistently
improve opens and was discarded; the bound remains 100 us. Clock batching does
not replace the time budget with a fixed iteration count.

The first writable series (`oci-services-bfd3ca64ed4d49e2889af578f4375753.json`)
found a real regression in nonexclusive missing-name creation: 338.24 ms versus
233.50 ms in the preserved runtime, with paired ratio 1.408. Every birth tried an
existing-file plan and then entered its normal carrier. The final version skips
128 creating-open probes after a pre-effect decline, then resamples. It caches
no path or authorization; ordinary opens remain eligible throughout. Actual new
file creation still uses the original publication mechanism, not a native plan.

With writable read windows, the intermediate five-round receipt
`oci-services-0455ee7505d54aab9cdbb1e9720dd7f1.json` measured 82.51/249.39 ms for
writable opens, 130.34/296.31 ms for existing-name O_CREAT and 106.26/285.22 ms
for truncation (new/preserved entry). Plain readonly opens had a paired ratio
0.995, not a demonstrated additional speedup. The final combined series follows.

The seven-round combined receipt `oci-services-725dcf835c5247fba387d53b805e194d.json`
reduced missing-name creation's paired regression from 1.408 to 1.027, with only
16 pre-effect declines over 2048 cycles instead of probing every birth. This is
not a new creation speedup claim. Its separate writable-open paired ratio was
0.383 versus the preserved entry, existing-name O_CREAT 0.507 and truncation
0.418. That series still captured umask unnecessarily for existing-name O_CREAT;
the final engine captures it only in the actual creating carrier.

Concurrent relative mkdir/rename/rmdir mixed with native opens exposed an
existing window-admission defect: a resource waiter could become ready inside
another request's retained read scope. The new stress assertion failed in
`build/cooperative-runtime/oci-services-4fcbc51dfdc34e79a7e8014a6ee29358.json`.
Passing the current execution window into queued-operation admission fixes the
ownership boundary, without ending it for every native-result retirement.
Full runtime receipt `oci-services-5c930ec715fd463d8f98e4d667bd8e9d.json` then
passed that scenario, live-umask birth checks, EMFILE-before-truncate, COW,
64 journal instruction stops, 1000 retirement and 2000 park-publication races.

Broader unchanged-path checks passed: 133 filesystem-buffer checks and 46 signal
checks (`build/cooperative-writable-fs-buffer-results.json` and
`build/cooperative-writable-fs-signals-results.json`), plus 22 watch/inode/import/RPC
checks in `app/build/shroot/watch-runtime-c715bf3a9a3248388a62e9fdaad24d7d.json`.
The signal set also exercised a cancelled-notification replacement in protected
mode 8 (`rebounds=1`). These are newly run receipts, not earlier saved reports.

The final seven-round, rotating five-mode series is
`build/cooperative-musl-results/oci-services-33af474a32c04ebdba607e0ea974fef7.json`.
It ran under UID 2000, CPU mask `3`, after the user released the CPU, with no
concurrent build or test. Statistics were disabled for timed samples; profiling
ran separately. The preserved entry is `build/cooperative-before-open-write`,
not HEAD. Native and PRoot share the physical control directory; Shroot uses its
logical-directory store. Each mode passed static and dynamic libc correctness
before timing. The libc itself was not rebuilt for this phase; the probes were
relinked to add cases and their hashes remained unchanged throughout the run.

| Workload | Native | PRoot | Shroot kernel route | Preserved entry | Current entry |
| --- | ---: | ---: | ---: | ---: | ---: |
| Readonly open/close, 4096 | 5.84 ms | 262.28 ms | 388.21 ms | 92.57 ms | 77.43 ms |
| Readonly CLOEXEC open/close, 4096 | 7.91 ms | 267.20 ms | 591.76 ms | 90.63 ms | 89.59 ms |
| Writable open/close, 4096 | 5.75 ms | 263.77 ms | 450.08 ms | 258.30 ms | 91.44 ms |
| Existing-name O_CREAT open/close, 4096 | 8.35 ms | 273.85 ms | 457.16 ms | 282.02 ms | 96.67 ms |
| Truncating open/close, 4096 | 24.07 ms | 280.81 ms | 460.78 ms | 272.74 ms | 105.02 ms |
| Exclusive create/close/rename/unlink, 2048 | 57.09 ms | 404.88 ms | 545.43 ms | 254.38 ms | 251.96 ms |
| Nonexclusive create/close/rename/unlink, 2048 | 60.52 ms | 398.43 ms | 549.23 ms | 256.02 ms | 234.24 ms |

The table contains mode medians. Median within-round current/preserved ratios
are 0.899/0.976 for readonly/CLOEXEC opens, 0.380 for writable opens, 0.343 for
existing-name O_CREAT and 0.412 for truncation. The latter three establish about
2.63x/2.92x/2.43x improvements in this series. File-cycle ratios are 0.998/0.952:
the creation-probe regression is gone, but there is no comparable new speedup
for file birth. Readonly entry samples range from 71.64 to 93.39 ms; writable
samples from 61.79 to 119.51 ms. Neither a single best sample nor the old 48 ms
lab result is a production guarantee.

Paired current/PRoot ratios range from 0.290 to 0.387 for these open workloads
and 0.594 to 0.622 for file cycles. The native gap remains roughly 10-14x for
nontruncating opens and 4-5x for truncation/file cycles; the 2x-native target is
not achieved. These gains require the opt-in cooperative libc entry. Installed
application seccomp filters retain the ordinary kernel-carried path, and new
file creation still retains its existing publication owner. No storage format,
durability or sandbox-policy shortcut was used for the measurements.

Rebuilding the `run` and `image` targets after this series succeeded. The
post-build entry smoke receipt
`build/cooperative-runtime/oci-services-1726b01b62384aedb1ee20b1d4d0a80b.json`
passed, with 1009 native opens, 998 native closes and 576 native flag operations.
No owned test processes remained after cleanup.

### Broader Entry And Retained Membership (After baafc2a6)

The reference for this phase is the exact `baafc2a6` runtime in
`build/cooperative-baafc2a6`. An ABI-4 musl fixture is preserved in
`build/cooperative-musl-baafc2a6`; ABI-5 comparisons use `--reference-musl`,
not an old runtime silently declining a new libc ABI. Both static and dynamic
correctness checks run before measurements. Installed distribution libc and
storage format 17 are unchanged.

The expanded entry admits directory/O_PATH/openat2 plans, regular lseek,
dup/dup3, F_DUPFD/F_DUPFD_CLOEXEC, F_GETFL/F_SETFL, FD metadata, timestamps,
statfs and all twelve xattr calls. Open_how and xattr scalar decoding are shared
with the original adapter. FD-only requests retain only their file table;
fstat/fstatfs borrow authenticated anchors rather than duplicating data OFDs.
The native journal now checks 112 exact instruction stops. Full runtime receipt
`oci-services-7def5887e4c943fe882672fab7bd8914.json` passed this coverage.

Three transport experiments were discarded:

- Ignoring adaptive spin cooldown while an effect was pending improved one
  open series, but regressed file churn (paired 1.212 in
  `oci-services-cdd0fdf56af24dadaf58c2fc4a318c72.json`). Limiting that policy to
  opens did not fix it (`oci-services-e8aef8b58cb44456aaf88e14766b05ee.json`).
- A second journal for a likely following close was correct under the tested
  stops but rarely used: 147/4096 plain opens and zero CLOEXEC opens in the
  separate profile. Receipt `oci-services-f420221f8bfb4742a1316691599a4185.json`
  showed no reliable benefit. The entire speculative continuation was removed.
- Coverage alone did not establish speed: the first paired open/close series
  regressed (`oci-services-25e4c865663349ce96ed7762110267aa.json`). Neither a
  new route nor a single fast sample is sufficient performance evidence.

ABI 5 separates libc's cancellation checkpoint from its real kernel
continuation. Native opens no longer invoke two synthetic futex calls. Ordinary
wrappers have no checkpoint; musl cancellation wrappers use __testcancel.
Masked/asynchronous cancellation retains the original path. The real-libc
receipt `oci-services-789c902c731f44c8a3beae20c78d3a52.json` passed pending and
disabled cancellation, no truncation before cancellation, FIFO signals, fork,
exec and filters. This is an ownership cleanup, not a measured 1.5x open gain.

The common inode engine now retains native-leaf membership with the existing
O_PATH anchor. Fstat checks the live catalogue first, then projects fresh kernel
attributes without rediscovering membership through proc paths. Promotion,
ownership changes and unlinked hardlinks are covered in the full runtime and
publication receipt `oci-services-aa24f23ef1dc47e9917130535942b126.json`.
No attributes, permission verdicts or mutable pathnames are cached. Immutable
anchor type also avoids a redundant fstat before regular-file lseek.

Seven rotating rounds with native/PRoot controls, mask `3`, UID 2000 and no
concurrent build/test produced
`build/cooperative-musl-results/oci-services-3c414afd1ac3447c8ccff4dadd6e7a59.json`:

| Workload | Native | PRoot | Kernel route | HEAD entry | New entry |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fstat, 32768 | 10.06 ms | 1417.85 ms | 851.98 ms | 521.71 ms | 87.21 ms |
| Lseek, 32768 | 8.17 ms | 7.52 ms | 829.75 ms | 851.48 ms | 99.06 ms |
| Open/close, 4096 | 8.20 ms | 257.32 ms | 416.20 ms | 86.74 ms | 92.98 ms |
| File cycle, 2048 | 50.94 ms | 401.02 ms | 548.43 ms | 263.82 ms | 252.01 ms |

Median within-round new/HEAD ratios are 0.171, 0.116, 0.990 and 0.977,
respectively. Fstat and lseek improve substantially, but remain much slower than
native; PRoot leaves lseek native. Open/file-cycle target gains remain unproven.
The cancellation-only predecessor (`oci-services-addc8616ee114cbf80c9e02f94018274.json`)
also did not demonstrate the open target. The six-step plan, especially native
birth, filtered-call acceleration and glibc rollout, remains open in tmp-notes.

### Pinned Lookup And Caller-Owned Copy

The final native-leaf walk now returns the exact O_PATH pin with its fresh
attributes. Deterministic publication tests replace/unlink that pathname while
the pin remains live, and check failure cleanup without spurious OPEN/CLOSE
events. An unpinned encoded-metadata lookup still rechecks the opened identity;
the replacement-race fixture rejects stale observations. Full runtime receipt
`oci-services-5572e69277ee4500955e895fef1ce79b.json` passed both sets.

The isolated musl fixture no longer repeats F_SETFD after a successful
O_CLOEXEC open; atomic close-on-exec is part of the supported Linux baseline.
An actual exec test verifies both preserved ordinary FDs and closed CLOEXEC
FDs. Stock Alpine 3.23.6 BusyBox also passed shell/archive/traversal/link/metadata
workflows with entry enabled and disabled in receipt
`oci-services-3ee86ea68754459e8066360c1321d6c7.json`.

A completion-feedback spin experiment was removed. Seven paired rounds against
its immediate predecessor (`oci-services-18c7e175070d466b9a90dd7832c27127.json`)
regressed CLOEXEC opens by 16% and file churn by 5%; faster seeks did not justify
that regression. No assumed following close or new spin prerequisite remains.

Caller-owned guarded output eliminates remote writes for small read-only
results. Alone it improved metadata but regressed open/close in receipt
`oci-services-825eb05db0f249ffa1ab203a14acc7b0.json`; this was not accepted as
sufficient performance evidence. Adding bounded caller-side pathname capture
and a shared exact-NUL string copier gave the following seven-round result
against the same pre-copy runtime, with identical ABI-5 libc, mask 3 and UID 2000:
`oci-services-ccd30a9f1b4b46ecb3a832a3504ff72b.json`.

| Workload | Native | PRoot | Kernel route | Pre-copy entry | New entry |
| --- | ---: | ---: | ---: | ---: | ---: |
| Path stat, 32768 | 23.38 ms | 2044.17 ms | 951.42 ms | 186.73 ms | 143.02 ms |
| Fstat, 32768 | 10.19 ms | 1569.62 ms | 846.14 ms | 101.43 ms | 80.91 ms |
| Open/close, 4096 | 7.79 ms | 272.93 ms | 438.39 ms | 72.21 ms | 69.28 ms |
| CLOEXEC open/close, 4096 | 6.47 ms | 275.59 ms | 428.64 ms | 81.69 ms | 66.32 ms |
| File cycle, 2048 | 53.90 ms | 405.63 ms | 471.35 ms | 242.42 ms | 230.21 ms |

Median within-round new/reference ratios are 0.766, 0.755, 0.898, 0.855 and
0.930. Independent medians differ because scheduling varies between rounds.
The <=52 ms open target is still unproven. Fault receipts
`oci-services-00e66a73c5b34a2ea0a43ab535870446.json` (outputs) and
`oci-services-8f106f9c7e884ce38881003151b20241.json` (inputs and outputs) cover
partial/readonly writes, file-backed SIGBUS, unrelated signal delivery,
terminal-NUL/page boundaries and receipt reuse. Directory output still commits
its cursor only after synchronous delivery; large output retains the original
transport. The copier has since been extracted to guest_copy.S for direct
boundary tests and use by both entry paths.

### Admitted-Effect Drain And Resource Generations

The burst owner now has a bounded final drain of native effects already issued.
It releases the store read window before that drain, admits no next operation,
and neither waits nor reads the clock when no effect remains. This is not a
prediction that the application will close an FD. An initial seven-round run
(`oci-services-5025efe427064695a4dc41ce448686d4.json`) reached 56.45/55.12 ms
for plain/CLOEXEC opens but regressed file churn and FD metadata. After removing
the empty-drain clock, the repeat
`oci-services-b28d88f7280e40b6ae0c8b10b73b51de.json` gave:

| Workload | Native | PRoot | Kernel route | Pre-drain entry | Drain entry |
| --- | ---: | ---: | ---: | ---: | ---: |
| Open/close, 4096 | 6.53 ms | 273.79 ms | 422.38 ms | 74.20 ms | 45.58 ms |
| CLOEXEC open/close, 4096 | 6.27 ms | 271.93 ms | 440.36 ms | 81.09 ms | 46.10 ms |
| Fstat, 32768 | 9.14 ms | 1589.18 ms | 841.05 ms | 80.14 ms | 89.93 ms |
| File cycle, 2048 | 60.02 ms | 391.74 ms | 463.03 ms | 236.94 ms | 235.64 ms |

Paired new/reference ratios are 0.616, 0.619, 1.206 and 1.026. The open target
is demonstrated in this series, not established as a stable result across all
conditions; the metadata regression must not be omitted from acceptance.

Task snapshots now retain one immutable resource generation. Changed identity
or resource handles invalidate it at publication; root/cwd remain fresh per-read
observations. No mutable file attributes, permissions or resource contents are
cached. Full receipt `oci-services-48dd7f3a7cbd4efaa5885345e965dfb3.json`
passes concurrent publication, retained old readers, TID reuse and existing
namespace/IPC/Landlock custody. Its immediate-predecessor comparison
`oci-services-a8b277f34c8849169e4164fc3450d4c1.json` has paired ratios 0.885
(opens), 1.175 (CLOEXEC), 1.048 (path stat), 0.836 (fstat), 0.962 (file churn)
and 1.000 (native IO). Open medians are 53.36/49.15 ms, with individual rounds
35.39-73.58 ms and materially different context-switch counts. This does not
justify claiming every workload got faster.

Additional checks passed: full copy/runtime receipt
`oci-services-036752becfd941c283f1e2675208bfd3.json`, 133 filesystem-buffer and
46 signal checks, and the production watch suite
`watch-runtime-58d283d4f1204c84a039f2ed1ef62e32.json`. Explicit sequence-bound
copy assertions under nondumpable execution pass in
`oci-services-d147cb942d444464ab80d8e4abf56301.json`, both for an existing
channel and a newly created protected thread. A second client in the same thread
cannot register a second channel; that is not a protected-memory failure.

Separating the native journal and copy buffers onto additional cache lines was
rejected after receipt `oci-services-cb539bc79caf452887c328a5bc3b6fd0.json`:
seven-round paired ratios were 0.888 for opens but 1.135 for CLOEXEC opens,
1.023 for fstat and 0.988 for file churn. Its full correctness receipt
`oci-services-74e79865368f4cd7a8caa4404284ee36.json` also covers immutable-snapshot
allocation failure, reuse without allocation, and retirement without allocation.
Correctness alone does not justify retaining that layout experiment.

The shared guarded copier now uses aligned machine words when both addresses
have matching alignment, retaining exact byte prefixes/tails and the same
recoverable fault-PC range. It never reads beyond the requested size; pathname
capture still stops at the first NUL. The fixture checks every pair of 16-byte
alignments and lengths 0-256, canaries, and precise page-edge fault prefixes.
Full runtime receipts `oci-services-8f59902d584e4dae8fc7746e0a7a5ef4.json` and
`oci-services-5a813ba5c06c4d57be48faa983aeda5b.json` pass. The latter also covers
direct scalar credentials after ID changes and entry into a user namespace.
No new timing claim follows from these correctness checks.

The production watch suite passed again in
`watch-runtime-7b1c91aff1a340f1ae98a0bf8467d221.json`. Real musl static/dynamic
checks, now including cancellation cleanup handlers, passed in
`oci-services-a0cde14dfa73401388af428cca89bf52.json`.

## glibc Fixture

`integrate_glibc.py` applies checked source boundaries to official glibc 2.41.
`build_cooperative_glibc.py` builds it in a disposable Debian toolchain under
shell Shroot, with a checksum-pinned source and `--enable-kernel=5.15`.
It exports a separate sysroot and static/dynamic probes; it does not replace any
installed distribution library. The shared libc runner accepts `--libc-kind
glibc` and applies the same correctness assertions as musl. Compile cancellation
probes with `-fexceptions` to verify cleanup, not merely eventual thread exit.
The fixture links CRT objects in their real order: probe code must follow
`crtbegin`, otherwise static frame registration misses its cleanup handlers.
Native static and dynamic probes check pending-cancellation cleanup before the
Shroot comparisons. Build receipt `oci-services-94355d6c745840559da2e8ab62d7b77c`
exports ABI 6. Native/static/dynamic and kernel/entry checks pass in
`oci-services-b74547c0eff74f65b5b4b521dbdbc7a1`. The isolated rootfs supplies
`/lib64 -> lib` for glibc's configured default lookup path. No installed libc
was changed and this receipt makes no performance claim.

## Caller-Owned Actions And Birth Ownership

ABI 6 moves cancellation checks and kernel/native execution into the common
caller-compiled action driver. The freestanding runtime returns before libc may
unwind, then resumes through an explicit continuation. Full runtime receipt
`oci-services-2ae1b07eaff341b0945906e6ab1c232c` and static/dynamic musl receipt
`oci-services-d663c9ad44e846c1a40b9c17cfb14ec2` pass. No timing comparison has yet
been made for this change.

Task snapshots now retain a lazily opened proc-status descriptor, not an umask
value. Each creation reads offset zero again; CLONE_FS umask changes remain live.
Concurrent first readers, credential generation changes, nonleader exit and
final descriptor retirement pass in `oci-services-69119bb6ec7e4e0ea9cb4c6ab826718f`.

A stronger exhaustion test exposed a carrier defect: a creating open can return
EMFILE after publishing its file. Native-leaf eligible creation now resolves this
with an unpublished prepare/effect/commit owner. Provisional guest slots retain
their table turn and reuse the supervisor's exact FD-loan retirement owner when
name publication fails. No store snapshot spans the guest effect.

Runtime receipt `oci-services-72ef4186461f42edbe0be73491a0ac39` passes live umask,
EMFILE-before-create/truncate, 24 exclusive/nonexclusive/parent-removal races,
signals after the native effect, both CLOEXEC states, FD-count restoration and
exact CREATE/OPEN/CLOSE events. Pre-effect cancellation leaves no name or events,
including mode-zero files. The fixture preserves import ownership, matching
distribution metadata; its old host-directory import used real Android modes.
Those host-permission directories and other native-birth ineligible cases still
use the original creating carrier and need the same exhaustion fix.

Storage/resource receipt `oci-services-d348bf2ef4424063ae76c92d153e2fb6` passes
custody allocation/retirement, catalogue conflicts, parent rename/removal,
read-only commit rejection and SIGKILL at preparation, effect and publication.
Exclusive maintenance removes unpublished orphans without deleting a committed
name or its data. These are process-crash tests, not power-loss durability claims.

Expanded receipt `oci-services-28c0dac6b4a0406b8300724f18a7fe99` also passes birth
promotion to hardlinks, sealed-source snapshot/COW, upper/merged overlay watches,
the FD filter decision matrix and protected remote filter installation.
The explicit fsopen carrier fixture exposed a genuine native dup3 regression:
Shroot's later selector filters did not exempt the native-effect gate. The
common filter generator now includes it, like the existing raw/watch/task gates;
application filters are unchanged. Full runtime receipt
`oci-services-378689e793454776935ce7e2c6bf5d76` and glibc static/dynamic receipt
`oci-services-4102a2f09e1d4c65a41ac19082c3f7e5` pass after this fix.

Five-round paired receipt `oci-services-f1588e8639c644d98a0d58fb0e606ee6` compares
ABI 6 with the retained pre-caller-actions ABI 5 runtime and matching libc. No
build ran during timings. Values are median milliseconds, not best rounds:

| Workload | Native | PRoot | Kernel route | Entry ABI 6 | Entry ABI 5 | Paired new/old |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4096 opens | 7.89 | 263.31 | 435.93 | 45.25 | 55.78 | 0.900 |
| 4096 CLOEXEC opens | 5.95 | 262.72 | 445.17 | 62.20 | 59.85 | 1.024 |
| 2048 create/close/rename/unlink | 64.34 | 407.46 | 483.69 | 236.74 | 239.33 | 0.912 |
| 32768 fstat | 13.49 | 1515.74 | 842.97 | 81.47 | 66.36 | 1.228 |
| 65536 native IO pairs | 71.30 | 67.46 | 87.61 | 85.55 | 87.43 | 0.978 |

Ratios are medians of paired rounds, not ratios of medians. Native birth improves
ownership/correctness but has not shown a large throughput gain. Plain opens meet
the original 77 ms to <=52 ms target in this series; CLOEXEC does not. FD metadata
regressed against the preceding prototype and needs investigation/repetition.

### Read-Family Expansion

Caller pathname capture now uses the same small argument-selector table as the
executor. Pathless calls leave the old capture untouched; request sequence
matching excludes it. An unadmitted carrier withdrawal invalidates its capture
before reusing the sequence. The decoder fills one authoritative FS request
instead of building and copying a second one. Access, readlink and read-only
xattr requests now share bounded inode read windows; writes end the scope.

Seven-round receipt `oci-services-71667426db3c4ae2bb601aec8b323ff2` compares this
with the retained ABI 6, 32-request notification-batch build. No concurrent
build/test ran during measurements. Values are median milliseconds:

| Workload | Native | PRoot | Kernel route | Entry | Previous entry | Paired new/old |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4096 opens | 6.77 | 270.62 | 415.98 | 59.02 | 47.62 | 1.182 |
| 4096 CLOEXEC opens | 6.82 | 269.58 | 406.13 | 52.43 | 46.65 | 1.038 |
| 32768 fstat | 11.61 | 1584.38 | 849.24 | 68.96 | 66.78 | 0.970 |
| 2048 file cycles | 49.74 | 394.08 | 459.83 | 208.66 | 208.54 | 1.026 |
| 32768 access | 26.59 | 1164.72 | 4857.55 | 180.55 | 337.91 | 0.534 |
| 32768 readlink | 22.00 | 1959.19 | 932.48 | 116.33 | 249.91 | 0.435 |
| 8192 getxattr | 12.21 | 299.14 | 1412.42 | 237.05 | 374.10 | 0.635 |
| 65536 native IO pairs | 73.77 | 71.27 | 82.83 | 75.44 | 82.40 | 0.976 |

The read-family gain does not establish the open target: plain opens regressed
in this series. Increasing the burst limit from 32 to 128 was rejected after
the seven-round repeat `oci-services-87827b40e02744ec92de8423b05a122d` showed
paired regressions of 1.109 for fstat, 1.057 for opens and 1.138 for CLOEXEC.
The retained policy is 32 requests / 100 us, never an anticipated next close.

Default ACL inheritance now prepares native metadata before name publication,
including promotion to hardlinks. Full runtime receipt
`oci-services-8037c67ff6544f9ba8b31e474a2768d8` passes inherited modes, EMFILE
without name/events, exact CREATE/OPEN/CLOSE, cancellation, sequence rollback,
and the existing race/storage/FD ownership assertions.

### Ordinary Metadata Notifications

The same read-only catalogue now selects kernel USER_NOTIF routing and
interrupted-SVC restart eligibility. Removing duplicate dead TRACE entries keeps
the base BPF program smaller despite the broader route. No application filter is
interpreted in userspace or bypassed.

Full runtime `oci-services-f65671cee5174713bf72ecd9cc336fec`, production watches
`watch-runtime-1f7e5cb3f06745159ac5b57e8da036f7` (including 515 stacked filters),
133 fs-buffer checks and 62 fs-signals checks pass. The latter adds all 14
metadata calls under continuous signals, dumpability changes, SA_RESTART and an
argument-dependent seccomp denial. An initial combined parent alarm expired
after its child assertions passed; each mode now has a separate invocation with
the original per-mode limit and unchanged load/assertions.

Five interleaved rounds `oci-services-19b9821045874069a36597bed03892f4` use the
same previous ABI 6 reference as above. No build or other test ran during timing:

| Workload | Native | PRoot | Kernel | Entry | Previous kernel | Paired kernel new/old |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32768 access | 22.20 | 1230.78 | 1104.64 | 240.07 | 5680.91 | 0.193 |
| 8192 getxattr | 9.91 | 325.02 | 455.08 | 298.85 | 1676.67 | 0.270 |
| 32768 absolute stat | 48.54 | 2021.75 | 1100.46 | 160.92 | 1072.41 | 0.995 |
| 32768 fstat | 11.31 | 1479.58 | 917.56 | 73.40 | 968.09 | 1.030 |
| 4096 opens | 7.46 | 276.81 | 454.56 | 51.17 | 489.43 | 0.969 |
| 4096 CLOEXEC opens | 6.94 | 284.10 | 454.68 | 50.91 | 449.38 | 1.025 |
| 65536 native IO pairs | 74.45 | 77.85 | 85.39 | 84.13 | 85.87 | 1.003 |

The substantial access/xattr gain is available without a modified libc. Other
kernel workloads remain near their controls. Opens meet the <=52 ms target in
this series, not in every previous series; paired entry/reference ratios are
0.925 and 0.927. This receipt predates the separate xattr pin experiment.

### Retained Xattr Selection

Path xattrs now reuse the exact O_PATH selection and its membership proof.
Ordinary reads project live metadata/ACLs from that pin; promoted objects still
use the catalogue, and writes still acquire their mutation/watch context.
There is no cached permission decision or second pathname selection. Native
leaves do not query catalogue-owned overlay attributes when listing xattrs.

Five-round receipt `oci-services-ee55189583c04c8da106236788ee9c2a` compares with
`cooperative-before-xattr-pins`, which already includes expanded metadata
notifications. For 8192 getxattr calls, entry median falls 325.57 -> 108.43 ms
(paired ratio 0.338), kernel 467.93 -> 348.66 ms (0.747). Native is 13.41 ms,
PRoot 344.90 ms. Open/CLOEXEC medians 55.45/64.49 ms vary in opposite directions
despite unchanged open code; this is not evidence of a stable open improvement.

`oci-services-de805e69496c4d499ae647d6fc0d69f3` passes live ACL permission denial,
hidden-private-attribute exclusion, hardlink promotion and an unlinked open FD.

### Catalogue Birth Publication

The same prepare/effect/commit owner now handles host-permission parent
directories without converting their permissions or physical directory layout.
Its private staging name never enters the catalogue. A final backing rename
and catalogue commit publish the accepted creation; kernel move cookies and
the existing CREATE journal produce exactly one CREATE/OPEN pair. The commit
receipt transfers ownership before fallible notification/sync retirement.

Full receipt `oci-services-e6f1293bdb1d411684fdbc75c10cd901` passes native and
catalogue birth cancellation/EMFILE with no name/events, ACL and mode-zero
creation, conflicts, retained hardlinks, SIGKILL before/after commit and a
post-commit watch-marker failure that must not discard the published file.
An initial standalone host test terminated on its injected SIGUSR2 because
the handler belonged to a different fixture; handler setup now belongs to the
common test entry, with unchanged cancellation/event assertions.
Final entry receipt `oci-services-0d7b238e47464bda8a080556c1ac5ee8` additionally
passes concurrent catalogue births against two independent metadata readers;
publication closes any foreign read window before its write admission.
Production watch receipt `watch-runtime-f15683c629924ad6b63ea6132bced618` passes
native/logical events, signals, protected readers, 515 stacked selectors,
SCM_RIGHTS, independent owners and writer rollback.

### Final Paired Baseline And Filtered Routes

Seven rounds `oci-services-af3307eec5df44f79fafa2bcc57aa35e` compare the retained
exact `baafc2a6` runtime and its ABI-4 libc with the current ABI-6 fixture.
Native/PRoot controls use the same workload. No concurrent build/test ran:

| Workload | Native | PRoot | Kernel | Entry | HEAD entry | Paired entry/HEAD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4096 opens | 6.28 | 285.51 | 451.39 | 53.37 | 98.05 | 0.514 |
| 4096 CLOEXEC opens | 7.30 | 292.50 | 450.02 | 54.30 | 109.10 | 0.483 |
| 32768 fstat | 10.48 | 1525.32 | 920.83 | 84.50 | 638.77 | 0.137 |
| 2048 file cycles | 59.60 | 435.91 | 518.97 | 256.22 | 307.31 | 0.833 |
| 65536 native IO pairs | 77.11 | 78.93 | 88.86 | 86.93 | 86.10 | 1.020 |

This establishes the requested 1.5x open improvement against HEAD in this
paired experiment, not a universal 48 ms latency bound. Creation cycles improve
less, and native IO remains within a few percent of the previous entry route.
The subsequent foreign-read-window closure fix affects birth publication,
not these existing-open paths.

Five-round filtered receipt `oci-services-125e277894c94024ac9777817db18493`
retains a real argument-dependent kernel filter in every timed process.
Against `cooperative-before-burst-limit`, access median is 1031.38 vs 4787.87 ms
(paired 0.217); getxattr 311.10 vs 1437.57 ms (0.221). These are ordinary
notification gains: installed filters revoke direct execution, as confirmed
by entry/kernel timings and counters. Other calls do not inherit those ratios.
In particular, the existing sandbox-wide PROC FD selector still traces ordinary
pread/pwrite (3024.92 ms vs native 77.92 ms); its paired ratio to the old filtered
route is 0.982, not a new regression or native-IO acceleration. It protects
future typed/received descriptors after applications deny filter installation.
Replacing that selector needs its own admission/custody design, not removal.

### Final Regression Coverage

All final checks use isolated runtime helpers under shell UID 2000. They do not
install an APK or replace a distribution's libc. The libc integration remains
opt-in; stock browser checks verify the ordinary syscall route, not a patched
Chromium libc or strict security isolation.

| Check | Result | Receipt |
| --- | --- | --- |
| Full runtime and storage models | Pass, including pre/post-commit crash and publication-error ownership | `oci-services-e6f1293bdb1d411684fdbc75c10cd901` |
| Final entry and concurrent catalogue births | Pass, including two readers across birth completion | `oci-services-0d7b238e47464bda8a080556c1ac5ee8` |
| Production watches | Pass, including independent owners and 515 stacked selectors | `watch-runtime-f15683c629924ad6b63ea6132bced618` |
| Buffers and signals | 149 checks pass; includes all 14 metadata families | `resource-fs-buffer-results.json`, staging `407669c83b6f4338bf427df966319a5d` |
| Event fairness | 16 checks pass | `resource-event-fairness-results.json`, staging `f3de8cc0ab4045fa95c98f8d034b23d4` |
| Final glibc static/dynamic | Pass, native controls and kernel/entry routes; cancellation, unwinding, FIFO, signals, fork/exec and filters | `oci-services-3c6dd337551e428396e6fe219116fe60` |
| Stock Chromium automatic sandbox | 4/4 pass; rendered JS and PNG | `browser-stage-results-256d91dbd1ae448ead6bc4c972d76b2f` |
| Stock Chromium set-ID sandbox | 4/4 pass; includes expected rejection of the unadmitted helper | `browser-stage-results-4389263b51c64017b3fbc87bc17f3e55` |

The final full-runtime model run precedes only the foreign-read-window closure
at birth completion; the final entry and all subsequent regressions include it.
Seven-round paired musl checks and the filtered series above also run their
static/dynamic correctness controls before timing. No test helper or browser
process remains after final cleanup. Kernel minimum 5.15 and storage family 17
are unchanged.
