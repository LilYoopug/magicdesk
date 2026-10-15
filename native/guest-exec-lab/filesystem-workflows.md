# Filesystem And OCI Fixtures

[Fixture guide](README.md) | [Native architecture](../shroot/README.md)

OCI images, mount views, storage semantics and file-watch workflows. Use disposable environments for mutation and failure-injection tests.

- [OCI And Filesystem View Checks](#oci-and-filesystem-view-checks)
- [Native Names And Publication](#native-names-and-publication)
- [Watch Transport Controls](#watch-transport-controls)
- [Production Watch Checks](#production-watch-checks)

## OCI And Filesystem View Checks

Transient-store checks retain a journal across SIGKILL at object publication,
namespace staging and commit. Reconnect and transferred custody preserve the
temporary durability policy and exact final cleanup. Persistent-store checks
assert WAL with synchronous NORMAL and explicit durability barriers independently; retained-directory journal access also
survives renaming the store while two connections remain open.
Checks include pre-checkpoint wakeup for namespace-only changes, bounded WAL
reuse, descriptor-cache admission across foreign writes, and bounded SQLite FD
retention with exact release after the final connection.

`test_resources.py BUILD --case durability` runs inode-owner and real guest
checks under the selected shell UID. It covers data/WAL sync failures, allocation
reserve publication and reuse, four concurrent writers, directory-watch events,
snapshot-local inventory and modeled loss of uncheckpointed WAL. Guest calls run
with ordinary and nondumpable/seccomp-filtered processes, including retained
unlinked FDs, O_SYNC, tmpfs, writable-overlay remounts and native attachment
barriers. Native attachments do not acquire guest hardlink/FIFO permissions.
The same checks run in `--case all`; `--case stores` includes the inode-owner
part. Process kills and the WAL-loss model do not simulate physical power loss.

### Native Names And Publication

`test_resources.py BUILD --case stores` includes the production native-leaf and
publication owners. These checks use the default representation, not a feature
flag or an alternate provider. Ordinary eligible creation under a guest-owned
virtual-permission directory must perform zero SQL writes, xattr operations and
forced synchronization. Non-root creation and exceptional initial modes use
native names with one synced sparse-metadata preparation before publication,
still without SQL writes. Physical-permission import directories, default ACLs
and overlay projections retain catalogue allocation.

The matrix covers mixed directory enumeration and transferable offsets, retained
and unlinked FDs, O_PATH metadata, ACL/capability updates, Landlock inode pins,
native and mixed watch streams, hardlink promotion, sealing, snapshot COW,
overlay admission and portable backup/restore. Publication tests interrupt each
durable phase and recovery itself, inject IO errors, and check both cold and
already-open owners. Sparse-metadata transitions get separate interruption and
error injection, including private preparation before publishing non-root names.
Stable O_PATH nofollow sources must preserve the same inode after guest
rename/unlink; the buffered-open runtime fixture uses a guest-created parent
and forbids hidden socket RPC. Format-17 revision admission must preserve existing data and
reject a metadata upgrade while another owner holds the old revision.

`test_execfd.c`, built by `build-libc-fixtures.sh`, additionally copies a fresh
ELF, executes its O_PATH/CLOEXEC descriptor before and after unlink, closes all
inherited descriptors and reads the image through local and foreign proc paths.
It checks metadata, inode identity, writable-open rejection and proc-image
reexec. `test_landlock_guest.c` denies execution of attached and unlinked fresh
copies through preopened descriptors. Run both as guest `0:0` and `2000:2000`;
both exercise native-name allocation. These run under the same real shell UID,
not Android root. The fixture executable must belong to the selected guest user
for its sticky-directory link/unlink controls.

These are process-death and injected-error checks, not physical power-loss tests.
Chromium's separate browser workflow verifies the application-filter path with
its sandbox enabled; it is not replaced by filesystem component assertions.

`--case fs-buffer` also compares stopped-task path invocation with native control:
ordinary/nondumpable tasks, installed application filters, guard-page path strings,
invalid unlink flags, file/directory umask, descriptor flags and native host delegation.
It covers relative cwd and explicit dirfd, mixed rename operands, renamed directory
anchors, close/reuse, closed-dirfd EBADF and absolute names ignoring an invalid dirfd.
Component invocation tests require missing origins to decline before execution and
release both ordering turns; an already captured anchor survives descriptor reuse.
The worker transport fixture installs the production typed-control factory and
checks live mount-table contents and logical metadata, not the carrier inode type.
Diagnostics must show successful direct open, status delivery and assembly-gate
FD admission, not only fallback execution.

`test_resources.py BUILD --case mount-policy` checks the attachment-policy owner
without running Desktop or replacing the APK. Local policy creates no descriptor;
explicit publication shares live flags through a size/write-restricted memfd.
Checks cover malformed imports, writer/observer permissions, failure rollback,
full-FD-table reads/updates, independent exec receivers using the filesystem
engine, source teardown, and queued state received after writer exit. These
checks also run with the regular mount models; namespace copies retain
independent policy. This does not transfer a complete mount topology or authorize
an imported state as an application's mount origin.

`test_resources.py BUILD --case mount-graph` checks sealed attachment-graph
publication and consuming import. It covers empty/maximum graphs, nested mounts,
native aliases with distinct policies, receiver-local IDs, repeated import into
the same view, forwarding, copied-view rejection and retained dirfd traversal.
Faults cover malformed manifests/rights, allocation/mapping failure and FD
exhaustion including partial export. Independent exec peers exercise actual
SCM_RIGHTS transfer, source-path replacement, live readonly changes, sender
teardown and queued rights received after publisher exit, with exact FD balance.
It also runs in the regular mount models. The fixture explicitly supplies the
same store: it does not implement cross-launch store/layer lease transfer,
application-origin authentication or production message framing.

`test_resources.py BUILD --case inode-custody` checks portable store/lower leases
without SQLite or application data descriptions in the parcel. Real layered
stores cover source connection closure, queued rights after sender exit,
forwarding, root/lower rename and replacement, COW/unlink, receiver death and
discarded or partially received parcels. Import rejects malformed manifests,
wrong store/FD identities, descriptor types and missing seals. Allocation and
partial-FD-exhaustion failures retain original locks and exact descriptor counts.
Empty, sparse and maximum 255-source catalogues include a 512-right transfer to
an independent exec receiver, with every lease held until final release. The
maximum catalogue uses distinct real directory/lock pairs, not downloaded OCI
images. An exclusive source lease remains exclusive after import; 10,000 local
pins allocate no descriptors. These checks also run in the regular mount models.
They verify custody independently, not its integration with application-origin
authentication or production cross-launch framing. The harness rejects child
assertions even if another process subsequently prints a success marker.

`test_resources.py BUILD --case origin-transfer` checks their composition into
message-origin parcels. A 253-entry vector includes unknown/repeated origins,
lower objects, nested/aliased native attachments and copied views with distinct
readonly policies. Checks cover live updates, interned IDs, ordinary FD-table
batch/fork/exec publication, forwarding after sender/SQLite/cache teardown,
COW/unlink and final maintenance admission. Malformed manifests/rights, foreign
stores, stale routes, every import allocation boundary and partial export FD
exhaustion must leave no partial destination or leaked resources. An independent
exec sender exits before receipt; actual queued SCM_RIGHTS preserve usable
origins even after replacing an attachment's old source pathname. An all-unknown
vector has one manifest and invents no mount/store owner. The fixture supplies
the expected route out of band; it does not substitute that for production peer
authentication, application framing or actual guest ancillary publication.
This suite also runs with the regular mount models.

The same `origin-transfer` case checks self-contained authenticated capsules:
an independent exec publisher exits before a fresh receiving authority opens;
the queued carrier retains its IPC epoch and exact data/metadata rights.
Checks cover 253 mixed/all-unknown origins, copied readonly views, repeated and
concurrent peeks, shared offsets, native/wrong-binding rejection, copied and
cookie-tampered headers, allocation rollback and five partial FD limits.
Discard without import must release both data pipe writers and maintenance
leases. Interrupted key construction and last-owner key retirement are checked.
The immutable queue-tree fixture separately covers 253/600 rights, malformed
shape and partial construction cleanup. No ordinary guest framing is enabled.

`test_resources.py BUILD --case ipc-origins` exercises the asynchronous capsule
service on real filesystem workers. Source capture contains the actual socket
and 253 data rights with mixed/repeated/unknown origins. Replacing its original
socket number before worker execution must not retarget the prepared send.
The test sends the capsule over the captured socket with unchanged application
bytes, closes the source worker, and checks repeated receiving custody and shared
offsets. Inputs may be released immediately after asynchronous admission.

Eight cancellation cases cover prepare/receive while queued, running at the
metadata gate, computed but undispatched, and completed. Two join cases reclaim
undispatched results without callbacks. Seven failures cover worker/admission
allocation, injected in-flight quota failure, annotation allocation, wrong side,
native binding and an unregistered socket. A blocked-worker burst verifies the
16-request limit, mixed cancellation and independent successful results with
exact FD balance.

The actual rights then use `received_fds` and production annotated `fd_return`
after source workers and importers close. Nine protected CLONE_FILES
receiver cases exit without acknowledgement. Retained kernel output publishes
full, truncated and peeked vectors while a competing table mutation stays
queued; zero delivery releases all preparation. Checks include regular-file
offsets, O_PATH/flags, reordered/repeated/unknown entries, final maintenance
admission, receiver-local zero/three-slot limits, pipe EOF and exact FD balance.

Independent exec publication exits before the receiver worker is created.
A second exec receiver exits with an untaken result and live worker: all data
writers and maintenance leases must be released by process/queue ownership.
The setup channel transfers custody, not authentication; the capsule's store
epoch key and actual directional socket binding remain authoritative.
These are production-component checks, not enabled guest ancillary framing.

`test_resources.py BUILD --case ipc-ancillary` also runs 28 actual guest capsule
receive cases. A fixture declares the connection format, queues the capsule,
closes its workers and passes the socket through the runner's stdin; production
authorities retain their NATIVE offer. Protected/unprotected receivers check
253 mixed/repeated rights, logical openat using imported origins, offsets,
peek, recvmmsg, truncation, partially writable control data, unwritable headers
and zero/three free table slots. Credentials before/after the carrier are
checked with SO_PASSCRED enabled/disabled. A native-format socket leaves a
capsule opaque. A reduced in-flight limit must fail explicitly with
ETOOMANYREFS, not leak caller FDs or retry the message. Final EOF, FD balance
and maintenance admission verify complete release.
Seven additional `ipc-origins` cases exercise the buffered decoder's result
take, untaken completion, queued/computed cancellation, worker join, wrong
direction and partial allocation failure independently of a guest launch.
No Desktop or APK installation is needed.

`test_resources.py BUILD --case ipc-ancillary` runs the existing credential and
ancillary fixtures in an isolated minimal store with Linux root/tmp permissions.
It covers the actual adapter's native/protected send and receive lifecycle,
credentials after UID changes, peek, batching, truncation and descriptor custody
after fatal filters, with native-shell controls. It needs no installed Linux
distribution; staging and the store are removed by the common harness. These
checks also run in the default resource suite.

`test_resources.py BUILD --case fd-observation` checks native direct-to-user
control output through the common annotated return owner. A same-TGID helper
with a private file table captures `/proc/<receiver tid>/fd` without a caller
scratch descriptor. The supervisor observes actual installations at the
receiver's ptrace exit stop, including unwriteable control/message headers,
partially writable FD words, zero control capacity, RLIMIT_NOFILE, peek and
SIGKILL before/after receive. The 96-case matrix combines 253-FD vectors,
protected/unprotected receivers, shared/private tables and both CLOEXEC modes.
It verifies origin ordering, queued mutations, exact FD balance, pipe EOF,
non-prefix rejection, invalid acknowledgement, preserved native output errors
and explicit failure after reaping. The ordinary resource
model additionally checks allocation-free observation/publication and queued
cancellation before admission. A second fixture uses the production task-helper
manager and its real ptrace/notification lifecycle. Twelve cases cover protected
callers, quota exhaustion, repeated capture, open rejection, fatal filters and
cancellation before/after directory export. It checks unchanged caller tables,
once-only completion, returned stack leases, final pipe EOF and FD balance.
Delayed owner-interrupt cases force a pending PTRACE_INTERRUPT before helper
admission, including protected callers, a 254-descriptor export and a
253-descriptor send. They require exactly one acknowledgement, unchanged
caller tables and exactly one delivered message.
These are component checks, not enabled guest message framing. No Desktop, APK
install or distribution is required.

Twenty-six captured-send cases use socket/right custody created after the caller
forks, unavailable by its original FD numbers. Admission retains that owner even
after the caller releases it. The production helper clears its private table,
installs both descriptions, patches its control slot and sends unchanged bytes.
Protected/unprotected callers cover full tables, zero/one helper slot, clone/send
rejection, fatal filters, native peer closure and actual versus filter-generated
SIGPIPE. Cancellation is injected before/between installations and after native
send; committed bytes remain committed. Exact reaping must restore stack leases,
close every private descriptor and leave the caller's table unchanged.

The same production-helper fixture adds 24 explicit source-export cases with
1/254 entries, repeated/reordered descriptors, ordinary/protected callers, full
caller tables, unavailable helper slots, clone/send rejection, fatal filters and
cancellation before or during either packet. Origin snapshots and actual FD
capture share a source-table turn, released at clone before export. A real
CLONE_FILES sibling then replaces a descriptor with another open of the same
inode; exported rights retain the original offset and snapshot after source
metadata teardown. It checks copied input arrays, O_PATH/access flags, exact
descriptor counts, stack-lease return and pipe EOF. The fixture creates its
temporary source in the harness-owned staging directory and unlinks it before
capture. These are source-capture checks, not transport selection or framing.

`test_resources.py BUILD --case fd-messages` includes 29 creation-time ancillary
transport cases: mixed runtime-owner declarations, stream/seqpacket connect and
accept in either order, socketpairs including datagrams, listener replacement,
independent sender exit, immutable dup/SCM aliases and atomic pair rollback.
Connection identity and transport selection are read from the same authority;
ordinary payload and FD transfer remain unchanged. These fixtures opt into the
candidate format explicitly; production owners still declare native traffic.

`test_resources.py BUILD --case ipc-peer` stages the private runtime peer
agreement, launch-registry, origin-transfer and worker admission fixtures under the
selected shell UID. Build `test_ipc_peer`, `test_launch_registry` and `fs_dispatch`
with `MAGICDESK_GUEST_FIXTURES=ON`.
Checks cover fresh-process discovery/negotiation, connection/epoch ownership, protocol
rejection, saturated control queues, cancellation during metadata admission,
allocation rollback and worker join with undelivered completions, without
touching application payloads. Discovery checks reject foreign/replaced stores,
dead owners, same-UID endpoint/caller impersonation and full queues; retained
store directories survive rename. A fresh exec peer obtains its control channel
through verified launch IDs, not an inherited socketpair.
Message-route checks read a queued header without installing its 253 rights,
including with a full FD table, and reject malformed headers, foreign stores,
wrong connection sides and stale nonces after same-carrier replacement. A
separate exec receiver discovers the live custodian from that header after the
socket creator exits and the application socket changes processes. Source-side
claims pin the exact local vector and its IPC epoch through SQLite/registry
closure; final release checks maintenance admission and pipe EOF.
Native-format connections reject carrier reading, binding and claim before
touching application packets. Origin-service checks also reject publication and
admission after a successful private ORIGINS agreement on such a connection:
control negotiation cannot change its application format.
This is not end-to-end application mount-origin
transfer, custodian-supervisor death or Desktop coverage.

Configure `native/shroot` with `-DMAGICDESK_GUEST_FIXTURES=ON` and build
`bootstrap supervisor run service image test_snapshot test_mounts`.
`test_mounts --path-walk NEW_DIRECTORY` isolates logical path traversal and its
depth-independent FD/transaction bounds. The full mount suite includes it.
`fixtures/path-workloads.py` runs deep-path reads, existing writable opens and
create/rename/unlink, hardlink/unlink and repeated metadata updates in a disposable guest directory,
checking contents and inode identity while reporting timings. Bind its containing directory into
the same prepared guest for both runtime versions; use `--statistics` separately
for work counts. Timings are observations, not pass/fail thresholds.
The offline importer tests require Python and the `zstd` CLI:

```sh
python native/guest-exec-lab/test_oci.py BUILD_DIRECTORY -v
```

The importer must run in a native environment that permits its syscalls.
Android app-domain seccomp can terminate it on `faccessat2`; Termux execution
is not a substitute for the selected shell executor. Signals fail even negative
import tests. On-device shell import and launch checks use the MCP runner below.

`fetch_oci_fixture.py REPOSITORY REFERENCE NEW_DIRECTORY` downloads a public
Docker Hub ARM64 image into a local OCI layout. It is a development fixture,
not an installed registry client. Preserve the returned manifest digest for
reproducible inputs. Run independent Alpine and Debian layouts through actual
shell UID 2000:

```sh
python native/guest-exec-lab/test_oci_runtime.py BUILD_DIRECTORY ALPINE_LAYOUT DEBIAN_LAYOUT
```

The runner stages production helpers, tests snapshot and mount contracts, then
imports each layout and creates two instances. It checks copy-on-write,
concurrent independent launches, readonly attachments, cross-boundary symlinks,
working directories, PATH execution from an attachment and release after launch.
It retains exact commands, results, digests and device/build identity, without
starting Desktop or changing privileges. Uploaded layouts and stores remain for
inspection. The installed CLI additionally needs ordinary Shell-console checks;
standalone helper coverage alone does not verify APK packaging and dispatch.

The installed named manager has a separate workflow:

```sh
python native/guest-exec-lab/test_environment_cli.py --apk app/build/outputs/apk/debug/app-debug.apk
```

It downloads public Alpine and Debian images through the APK's registry client,
exercises independent names, run/exec/login, directory attachments, backup/restore
and explicit prune under UID 2000. A guest HTTP request holds a real launch open
while removal and backup are required to fail. The fixture's Python controller
is development tooling, not an installed runtime dependency; guest acquisition
and execution use no Termux command or service. Reports retain the exact APK,
image configuration, storage paths and command results.

Stock service-image workflows and development tools:

```sh
python native/guest-exec-lab/test_oci_services.py BUILD --nginx NGINX_LAYOUT --redis REDIS_LAYOUT --postgres POSTGRES_LAYOUT
python native/guest-exec-lab/test_oci_services.py BUILD --python PYTHON_LAYOUT --node NODE_LAYOUT --httpd HTTPD_LAYOUT --memcached MEMCACHED_LAYOUT --java TEMURIN_JDK_LAYOUT
python native/guest-exec-lab/test_development_runtime.py BUILD --debian DEBIAN_LAYOUT --install
python native/guest-exec-lab/test_service_runtime.py BUILD DEVICE_STORE OTHER_DEVICE_STORE --installed
```

The first two commands use packaged helpers by default; `--build BUILD` explicitly
stages a native build. MariaDB and Caddy have corresponding image arguments.
PHP, Ruby and .NET SDK images have separate arguments as well. Staged runs record
each native helper's SHA-256 and verify it after upload.
Each image gets a disposable writable instance, loopback ports and owned process
trees. Readiness comes from service events and is followed by actual requests,
shutdown and, where supported, restart/readback. `--NAME-instance` reuses an
explicit disposable instance; PostgreSQL/MariaDB initialization checks require
a fresh instance. Control overrides are never default-entrypoint passes.

The development check installs packages only with explicit `--install`, in its
selected disposable Debian store. Compiler and live-debugger results are separate;
reading symbols is not a debugger pass. Reports preserve failures, image digests
and exact commands. Current coverage and unsupported requirements are in
[image checks](../shroot/images.md#checks).

`test_proot_debugger.py REPORT.json --distribution ubuntu` runs the same GDB
sources, commands and assertions in an installed Termux PRoot distribution with
GCC, libc headers and GDB already available. It checks both default PRoot and
`PROOT_NO_SECCOMP=1`, without root or package installation. Each case has a bounded
process lifetime; temporary sources and binaries are removed afterward. The
report records versions, output, exit status and timeout failures separately.

`test_debugger_runtime.py OUTPUT --instance STORE [--build BUILD]` runs raw
debugger lifecycle checks and real GDB attach, LLDB, gdbserver, strace, gprof,
Callgrind and perf-event checks. `--proot ubuntu` selects the same cases in an
installed Termux PRoot distribution; `--case NAME` restricts a run. The
`gdb-attach-threads` case checks all 41 target threads, backtraces, a memory write,
detach and normal target exit. `gdb-active-io` requires repeated breakpoints and
normal exit while eight peer threads create, write, read, reopen, rename and
unlink files, exercising
all-stop delivery across internal adapter operations. `syscall-exec` checks image-entry ordering and
paired syscall stops across exec. `syscall-edit-close` changes the descriptor
argument at a syscall-entry stop, with continued tracing and immediate detach;
native close and virtual FD ownership must both follow the changed argument.
Strace checks decoded arguments and fork
events without stray-exec recovery. The prepared
userspace needs GCC, Python 3, GDB, LLDB, gdbserver, binutils, strace and Valgrind.
No package is installed by the test. `--diagnostics` enables supervisor diagnostics
for Shroot only. A denied perf event is recorded as unavailable, never as working
profiling. Device capability and debugger compatibility are separate results.

`--gdbserver-binary FILE` explicitly stages a standalone Linux ARM64 binary under
`/tmp`, retaining its hash in the report without replacing the installed package.
This permits a current gdbserver control when an older distribution package has
an upstream ARM64 register bug. Timeouts fail their cases and the launch owner
cancels remaining descendants. Shroot fixtures persist only in the explicitly
selected disposable store. See the [debugger contract and measured coverage](../shroot/debugging.md).

`test_kernel_contract.py OUTPUT --fixture BUILD/libmagicdesk_guest_kernel_contract.so
--instance STORE [--build BUILD]` compares normalized observations from the same
static executable directly under shell and inside Shroot. Cases cover wait and
ptrace contracts, signal delivery, descriptor lifetime, openat2 and concurrent
rename confinement. The `debug-wait{4,id}-{signal,restart}` cases compare EINTR
and SA_RESTART for idle inferiors with SIGCHLD masked. The debugger fixture's
`--case strace-detach` checks SIGINT detach from 41 idle threads and subsequent
target input/exit; `probe_podman_runtime.py --trace --exercise-ports` also detaches
from live aardvark-dns and repeats named-container exchanges before cleanup.
The ancillary cases cover SCM_RIGHTS peek, truncation,
253 descriptors, batch delivery, source addresses and partial publication faults;
pipe EOF checks descriptor cleanup. `rights-socket-error` covers a kernel
payload-copy fault, poll/epoll readiness and shared one-shot error consumption
through SO_ERROR/read/recv, duplicated FDs and a forked peer.
`rights-watch-fault` checks received inotify descriptors after late message,
control, source-address and timeout publication faults, with fresh receivers
that cannot inherit an already installed watch filter.
`rights-batch-fault` is an unresolved
comparison: private recvmmsg headers allow later packets to be consumed before
a user-header fault, without the kernel's deferred socket error. It remains a
failing default case, not a skipped or expected-pass check. `--case NAME` selects
a focused comparison. Native capability gaps are recorded separately from guest
assertions. Build the `kernel_contract` and `test_elf` CMake fixture targets;
the latter runs malformed ELF, page-size preflight and actual BSS mapping checks.

`test_sysv_runtime.py OUTPUT --instance STORE [--build BUILD]` compiles the focused
SysV fixture with the prepared distribution's GCC and checks semaphore/message
semantics, protected copying, independent launch traffic and owner-death recovery.
`test_sysv_apps.py` accepts the same arguments and tests stock fakeroot-sysv,
PHP with sysvsem/sysvmsg/pcntl, Symfony Lock and Apache prefork. These packages
must already be present; the tests do not install software. `--case NAME` selects
individual workflows. See the [SysV contract](../shroot/sysv-ipc.md).

`test_resources.py BUILD [--compare-installed]` stages a disposable minimal
store and runs the same `resource_guest` executable natively and through Shroot
under UID 2000. It checks independent FS/FD sharing, unshare failure rollback,
exec and semaphore-undo lifetime. The optional comparison measures identical
metadata and spawn workloads without compiling guest packages. It records the
installed app identity, separate timings and opt-in runtime counters. Fixtures
are removed unless `--keep` is explicitly selected. Build `resource_guest` and
`test_task_resources` with `MAGICDESK_GUEST_FIXTURES=ON`; run the latter directly
for the resource-owner unit contract. See [process resources](../shroot/process-resources.md).

`--case kernel-baseline` runs exact-task descriptor/lifetime checks with
`PIDFD_THREAD` disabled, the resource model under that same restriction, and
production private-thread proc capture plus mapped descriptor/data/import cases.
It also exercises launch admission with missing mandatory operations and ADDFD
permission/ABI errors; independent shell execution must remain available.
This subset is included in the default resource suite. Kernel dependencies and
coverage are recorded in [kernel compatibility](../shroot/kernel-compatibility.md).

The same runner checks ordered FD-origin vectors and native `SCM_RIGHTS`
handoffs of up to 253 descriptors: distinct mount origins for one inode,
sender exit, repeated `MSG_PEEK`, truncated delivery and pipe EOF. Model checks
cover allocation-failure rollback and atomic batch publication under concurrent
readers. The controlled native fixture supplies the source/message association;
it does not establish general application-message origin transfer.
Filtered socket IO covers the inline/staged boundary at 0, 1, 65535, 65536 and
65537 bytes with actual rights transfer, CLOEXEC and pipe EOF after final
receipt cleanup, both natively and inside a nondumpable guest.
Retained receipt checks cover capacities 1-253, malformed input beside a guard
page and vector publication after a CLONE_FILES receiver exits without an ACK.
RPC and controlled native handoffs use the production `fd_delivery` owner. Its
lifecycle checks cover failed preparation, empty-receive retry, malformed input,
partial once-only publication, task-owner loss and disposal without closing
installed application FDs. Publication is tested with allocation disabled.
Receiver-local FD limits check exact prefix publication with zero or partially
available slots, combined with peeks and control-buffer truncation. Select these
native checks with `--case fd-handoff` without importing a store.
The same fixture runs the production `fd_install` primitive against real seccomp
notifications, covering protected receivers, zero/one free slot, both CLOEXEC
choices, exact origin publication, queued cancellation and receiver death before
atomic installation. Signal handshakes also force live syscall restart before
and after retirement of the expired installation turn. No installed result is
reclaimed by guessing a guest FD.

`--case event-fairness` runs sixteen continuous identity-syscall or native
descriptor-mutation producers beside
task-affine proc reads that need worker completion. The reads must finish before
the producers' failure deadline, not after they stop. Native, virtual-root and
ordinary guest-user cases use the selected shell identity. The default resource
suite includes the same regression.
It also runs `test_task_wait.c`: directed TID selection, stale/coalesced hints,
hint deduplication, overflow and wraparound,
interruption, exact status/rusage propagation, drained-queue invalidation and
the mandatory general-wait budget under continuous activity.
`test_task_wait_live.c` collects over six thousand real syscall stops from 24
concurrent tracees using blocked SIGCHLD/signalfd. Repeated reads of a drained
collector must perform no wait syscall, and all children must exit with their
expected status. It reports directed/general call counts, misses and elapsed
time without timing assertions. Both fixtures run in the default resource suite.
`test_pending.c` checks allocation-free continuation queues: duplicate admission,
bounded dispatch, cancellation of a queued peer, record reuse during dispatch,
and explicit recursive-dispatch rejection. Blocked continuations are exercised
through the resource, FD-custody and private-memory suites as well.

`--case mapping-task` is an explicit kernel feasibility check, separate from the
default runtime suite. It tests private-FD CLONE_VM helpers under UID 2000:
60 lifetime/mapping combinations, caller-thread death, nondumpable memory and
full inherited/helper tables. The tracer checks syscall and terminal observations against
actual mapping contents. A fatal fixed-mmap filter can leave success-like address
registers, including a misleading exit stop for a single-thread process. A
separate filter control permits ordinary shared-FD threads but rejects the private
helper. A helper-opened maps FD permits exact backing observation at terminal
stops, including death after mmap before userspace acknowledgement; ordinary
text reads pass while PROCMAP_QUERY returns EACCES on the tested shell policy.
A helper-only abort gate checks cancellation with surviving peers and an
exit-denying ERRNO filter. The reader is the production `mapping_observation`.
The separate SysV runtime cases cover private-helper admission, full caller
tables, fatal filters, competing mappings/fork, caller death and exec. Stock GDB
and strace checks verify internal helper event exclusion; see
[shared-memory ownership](../shroot/shared-memory.md).

The default suite also checks relative RPC with a retained cwd, including mixed
explicit/cwd bases, two cwd bases and a protected caller. A real guest filter
rejects the temporary O_PATH directory open, without preventing these operations.
`--case fd-custody` checks production buffered O_PATH delivery with a surviving
CLONE_FILES peer. KILL_THREAD filters on connect/recvmsg no longer interrupt that
path; a filter on its internal result-delivery openat does kill the caller.
All six guest cases leave the peer's FD baseline unchanged, including protected
callers. Native controls never enter the internal delivery gate. These checks
also run in the default suite and have a focused `resource-fd-custody-results.json`.

`--case fd-custody-dirfd` selects explicit known dirfd input, including protected
callers and death at native delivery; all six guest cases retain the original
shared-table baseline and also run in the default/buffer suites.
`--case fd-custody-nofollow` uses stable backing names for inode-owned objects;
all six guest cases also pass and run in the default suite. The surviving peer
checks its baseline after waitpid. Reports use
`resource-fd-custody-dirfd-results.json` and `resource-fd-custody-nofollow-results.json`.
Arbitrary native/anonymous nofollow sources are outside this coverage.

`--case restricted-descriptors` checks typed SCM_RIGHTS receipt after an
application denies `prctl`, `seccomp` and `prlimit64`, through both filter-install
interfaces. It retains the denials and checks typed dup, reused ordinary/pipe
slots, offsets, flags and close_range after a restricted proc-root change.

`--case rpc` selects the filesystem transport fixture, including exchange
retirement with a deliberately open client socket. Cancellation before/after
reply publication must release service-owned endpoints, receipts and contexts
without waiting for client EOF or peer expiry. Watch reservations preserve their
copy-acknowledgement policy and final host FD counts match baseline. This is not
reclamation of a private FD left in a surviving guest table.

`--case fd-lifecycle` stages the separate native `fd_lifecycle` fixture. It
checks live versus terminal ptrace cleanup, actual seccomp close denial and
proc-based O_PATH delivery of deleted files, directories and symbolic links.
The register request/reply prototype creates no private receiving FD, including
in a nondumpable task with zero/one free slots and socket/connect/recvmsg forbidden.
Protected-provider denial and independent reopened data offsets are explicit
boundaries, not bypassed restrictions. The fixed-size prototype is not a runtime
transport and does not establish exact O_NOFOLLOW flag semantics. Its exact report is
`resource-fd-lifecycle-results.json`; it leaves default results untouched.
Private-table helper controls cover terminal cleanup, inherited close/clone
filters and the unwanted retention of unrelated pipe writers. The same fixture
probes exact Unix socket peers through NETLINK_SOCK_DIAG, recording creation or
query denials explicitly. These probes do not enable an alternate runtime path.

The same fixture has 17 export-channel/queue cases: a table-owned send endpoint
with a supervisor-owned rights queue, repeated protected sends, cancellation
before send/before dequeue/after capture, late ADDFD_SEND admission, zero/one free
slots, kernel sender credentials with forged-PID rejection, fork/unshare/exec,
descriptor replacement and SCM_RIGHTS quota exhaustion. Actual shared offsets,
flock conflicts and pipe EOF check open-description ownership. A retained receive
endpoint can discard queued rights; peer close or shutdown cannot do so alone.
Six reverse-direction controls cover protected receive, zero/one result slots,
receiver death before/after receiving, queue discard and pipe EOF. These are
kernel controls; the production registry and request-lifetime checks below test
the runtime integration. The channel costs one infrastructure descriptor per
admitted table and retains native in-flight limits. It is not a zero-extra-FD
solution or a replacement for all RPC input/output paths.

`--case fs-dispatch` connects scalar control and shared request buffers to the
production filesystem worker and inode engine. Its 504 O_PATH cases check
authenticated context retention, registry replacement, long pathname snapshots,
deleted objects, protected receivers, FD-limit failure, ordered origin publication
and caller death before/during/after execution. They cover a surviving CLONE_FILES
peer and real exec with fresh mapping setup through ADDFD_SEND; the setup FD is
closed before receiver entry. Terminal checks kill at openat entry/exit, through
a real KILL_THREAD filter, and immediately after syscall resumption. Both ABI
spellings of AT_FDCWD use the production result decoder and mutation publisher;
the surviving peer checks descriptors without a receiver ACK. The race records
its observed result, not all possible interleavings. Direct proc reopening of the memfd is recorded
separately and is not required. Buffer unit tests check pinned lifetime, stale
generations, bounded capacity, failed setup and allocation-free reuse. A 96-record
failure test verifies typed completion dispatch and queued-work retirement.
Production buffered service checks cover cwd, validated O_PATH input snapshots,
malformed fields/lengths, ordered explicit-base capture, close/reuse before and
after capture, unannotated kernel inputs, transferred result ownership, queued cancellation and submitted-open cancellation
with an event-held worker. Removed task/resource owners cannot recycle pinned
output or receive a late callback; cancelled results close and final FD counts
match baseline. The report is `resource-fs-dispatch-results.json`.
Watch cases use the production mapped reservation and worker acknowledgement:
successful/rejected copies, invalid acknowledgements, and cancellation before or
after offering the result. Cancelled requests retain their slots until worker
completion; unconfirmed delivery is never replayed.
The 504-case O_PATH control loop remains fixture-owned, without coverage of
concurrent shared-table mutations, protected input-FD capture, exact O_NOFOLLOW
flags or all operation payloads.

`--case fs-buffer` selects the mapped-output checks also included in the default
resource suite. They run native controls and the real bootstrap/syscall adapter.
Signal-stress cases create, write, stat and remove 2,000 exclusive files while
also inspecting a native descriptor, with and without SA_RESTART and with both
ordinary and nondumpable callers. Native controls use the same fixture. A
cancelled notification must not execute after entering the signal handler or
turn a restarted exclusive creation into EEXIST.
Known-cwd getcwd must succeed at EMFILE while real KILL_THREAD filters deny
socket/connect/sendmsg/recvmsg, including nondumpable processes, fork, exec and
48 simultaneous callers. Output-error checks require ERANGE/EFAULT without cwd
changes. Memory-owner unit tests check CLONE_VM, fork's shared allocator, fresh
exec mappings, mapping validation and worker pins outliving owners. O_PATH cases
cover absolute/cwd long paths, files/directories/followed symlinks, protected
receivers, zero/one free FD slot, exact status flags and caller-selected CLOEXEC,
with all four RPC syscalls forbidden. Path/metadata cases cover mkdir, symlink,
chmod, timestamps, stat, readlink, two-dirfd rename, unlink, open-unlinked metadata
and output EFAULT at a full FD table, dumpable and protected. O_NOFOLLOW cases
check inode/type/flags with the same zero/one-slot matrix for owned files,
directories and symlinks. The custody cases also run here. The report is
`resource-fs-buffer-results.json`.
`--case fs-results` isolates native/guest mount-table and executable-image delivery, including
read/seek, CLOEXEC on/off, protected callers, zero/one free FD slot and all four
RPC syscalls forbidden. Unannotated SCM_RIGHTS dirfds and real socket/watch input
descriptions also run with those syscalls forbidden after setup. Capturing a real
description is distinct from authenticating arbitrary transferred mount origins.
Directory seeks at a full FD table check shared dup offsets, independent opens
and negative-offset rejection. The worker fixture separately replaces an input
number after capture and verifies the original OFD's position, plus O_PATH rejection.
Guest FIFO checks forbid socket/connect/sendmsg/recvmsg, require exact zero/one
result-slot behavior and cancel protected CLONE_FILES openers without private FD
retention. `--case open-job` separately checks supervisor-side deferred completion,
ENXIO, EOF, cancellation before/after result queuing and exclusion of unrelated FDs.
These checks also run in the default suite; mapped cases also run in the buffer suite.
Group-exit cases race 24 groups of eight active peers against buffered calls,
including nondumpable processes. Pipe acknowledgements precede exit_group;
observed terminal recovery after ESRCH is diagnostic, not timing-based readiness.
An outer deadline bounds supervisor cleanup, and the runner persists an error
report even if console execution or closure fails.
`--case launch-cancel` isolates parked and continuously active groups, ordinary
and nondumpable, including ignored TERM. It requires the explicit launch deadline
diagnostic, exit 125 and disappearance of every recorded native tracee. Internal
supervisor errors, incomplete cleanup and outer-timeout recovery fail the test.

`--case fs-export` runs native controls and the production protected-input
transport. It forbids guest socket/connect/recvmsg, fills RLIMIT_NOFILE before
and after channel admission, checks exact shared directory positions, kills
sixteen CLONE_FILES senders with seccomp and verifies fork/unshare/exec/dup/close
ownership without FD growth. Shared-table exec also checks prepared-image
retirement in the surviving parent. Cold EMFILE is required, not concealed by
raising limits. Restricted metadata checks require the same bounded channel,
full-table fstat, one-slot proc directory results and shared-table sender death.
Reports use `resource-fs-export-results.json`; these checks also
run in the default and buffer suites. Infrastructure unit checks cover malformed
and truncated rights, queue destruction and pipe EOF, not only descriptor counts.
The production service also rejects wrong tokens, duplicate/wrong-sized vectors
and wrong senders, and drains rights after cancellation or a reported send error.
All eight cases require pipe EOF and matching descriptor counts.
Channel reconciliation checks cover matching/replaced/closed sockets, CLOEXEC,
malformed and denied observations, resumed export/return and cancellation before
observation completion. The mapped export fixture uses a protected actor with
a real getsockopt-denying filter and requires exact FD balance.
Input-lease checks use independent consumers and channels with reverse delivery,
duplicates, wrong senders/counts, retired tokens and cancellation. Allocations
are disabled during admission/delivery/release; EOF checks verify actual release.

`--case exec-custody` compares native and production shared-table exec. It checks
ordinary and nondumpable callers killed by a pread filter, 64 failed execs per
caller with an invalid environment, and successful exec with all filesystem-RPC
socket calls forbidden. The surviving CLONE_FILES peer must retain exactly its
original FD set. It also runs in the default resource and buffer suites.
Foreign proc-exe cases cover native control, ordinary/anonymous images,
absolute/symlink/relative-dirfd paths, nondumpable callers and O_NOFOLLOW.
A private PID namespace repeats them through its mounted proc with logical PID 1.

`python native/guest-exec-lab/test_anonymous_exec.py BUILD STORE` uses a disposable
Debian store with Python. It executes ordinary and sealed memfd ELF images,
including a nonleader exec, closes inherited descriptors and checks executable
identity, seals, independent open/shared dup positions, readonly and private
mappings, rejected writes, foreign child inspection and nested self re-exec.

`--case proc-custody` checks ordinary/nondumpable CLONE_FILES callers with
write/read kill filters, then large argv snapshots with forbidden RPC, zero/one
free result slots, O_PATH/CLOEXEC, read-only access, seek and rejected copying.
It also checks mount-table snapshots and retained snapshot metadata, path
chmod/chown/utimens/statfs, regular-file/FIFO mknod, chdir and truncate without
free FD slots, caller RLIMIT_FSIZE/SIGXFSZ, and proc reopening of unlinked
files, directories and native devices with only the result slot available.
Foreign executable readlink runs with a full FD table, read/RPC kill filters,
ordinary/protected callers, short output, zero capacity and EFAULT.
Current executable metadata, xattrs and watches also run with full FD tables,
including protected callers. Worker object operands are checked after unlink,
with modified input after admission and queued cancellation; all provider FDs
must return to baseline. Native RPC checks the same identity-only contract.
Imported cwd checks receive a directory via SCM_RIGHTS, fill the FD table and
repeat fchdir/relative metadata for ordinary and protected tasks. The worker
fixture checks ordered FS/file-table publication, rejected descriptors, native
errors, pre-entry denials and cancellation before or after entry.
Native nondumpable auxv EACCES is recorded as an unavailable comparison, not a
guest exemption. The worker fixture cancels snapshot construction at every stage
and checks its own descriptor count. Both suites include these checks by default.
The result-FD suite checks watch registration with a full table after protected
queue-transport admission, including symlink selection and unchanged FD counts.
The buffer/default suites also check xattr with full FD tables, path and FD
forms, ordinary/protected callers, nofollow, binary values and rejected copying.
Guest path calls additionally set/get/remove a maximum-sized logical ACL with
socket/connect/sendmsg/recvmsg forbidden. Protected FD calls first admit their
table-owned export channel. Native RPC verifies the same maximum-sized value
contract; mount checks require readonly rejection and no intermediate FD leaks.
Buffer reuse tests require header-only clearing without bulk payload writes.
ABI fixtures install with explicit logical root, then execute as their configured
numeric guest account (2000:2000 by default); fixture ownership/modes and the
required data file are part of the archive, independent of the build host's umask.

`--case fs-return` checks native controls and production nofollow O_PATH opens
on an explicit native attachment with protected callers and socket/connect
forbidden. Cold admission needs the channel slot and a result slot; admitted
channels preserve exact zero/one-result-slot limits. Twelve forked receivers
each perform 32 opens through one inherited channel. Sixteen CLONE_FILES
receivers die at recvmsg without leaking a private socket or retaining queued
rights. Caller-selected CLOEXEC and exact FD counts are checked. These cases run
in the buffer/default suites and write `resource-fs-return-results.json` when
selected alone. The native handoff fixture additionally tests the production
`fd_return`/mapped receipt in 16 cases with pipe/O_PATH, denied receive, terminal
receipt publication, separate table/channel turns and real pipe EOF.

`--case fs-directory` compares native and protected guest directory reads.
The production broker fixture uses real seccomp notifications and exact
pidfd descriptor capture. A test-only write wrapper synchronizes a signal after
copying and before kernel reply. Both inode and attached native directories
must retain all 96 entries after cancellation, bad output and partial copies,
with no duplicate names, delegated calls or leaked descriptors.
Rejected user copying must preserve the shared position; an admitted channel
works with zero free guest FDs and forbidden socket/connect. Four forked readers
mix broker and protected adapter paths over the same OFD without duplicates or
missing names. The worker fixture controls copy acknowledgement, queued alias
seeks, independent opens and cancellation on either side. RPC uses the same
copy/commit and OFD-ordering contract. `--case ofd-order` runs the ownership
model separately, including number reuse and namespace-owner teardown. These
mechanisms order active operations only, not every application FD or ordinary IO.

`--case fs-capture` checks unknown native cwd and kernel-path operands through
the private-table helper. Ordinary/protected full-table callers exercise native
fchdir, proc metadata, watches and reopen with one result slot. A thread with
private files/FS distinguishes `/proc/thread-self` from the group leader's
`/proc/self`. Clone/close-range denials and fatal helper open/send filters leave
the surviving shared table unchanged. Worker checks retain two-source capture
through success, error and cancellation, including overwritten input frames.

`--case pidfd-table` is an opt-in native feasibility check requiring
`PIDFD_THREAD` (Linux 6.9+), not a production dependency or default-suite case.
Sixteen combinations exercise same-group private FD tables, ordinary/protected
callers, zero to three free result slots and normal/fatal-filter helper exit.
Checks retain exact OFD offsets, O_PATH identity, CLOEXEC and pipe EOF. The parent
pre-admits its pidfd infrastructure slot; the test does not establish zero-cost
admission or production ancillary publication/cancellation. Its report is
`resource-pidfd-table-results.json`. See
[kernel compatibility](../shroot/kernel-compatibility.md).

`--case fd-parcel` separately measures a socket-carried FD-list candidate,
including O_PATH, sender exit, peeks, read discard, queue closure, failed sends
and Unix GC cycles. It records the measured extra receiving-slot requirement
under RLIMIT_NOFILE as a limitation, not a resource-equivalence pass. A pidfd_getfd
probe records provider/receiver dumpability boundaries without changing identity.
The preconnected relay variant frees the envelope's receiving slot before
delivery and checks the issued endpoint cookie, protected receivers, terminal
receipts and pipe EOF. Direct controls deliver 253 queued rights at the same
available-slot counts. Reverse relay exports can instead hit ETOOMANYREFS at low
RLIMIT_NOFILE because queued rights count against the real UID's in-flight quota;
reports keep these limitations separate from admitted-delivery checks. Channels
and receipts are prepared before pressure, not claimed to be lazily available
at a full descriptor table.
The receiver-local variant parks the endpoint in a preallocated slot and needs
no reverse export. It checks terminal phases, reused FD numbers, protected
receivers and exact available prefixes through the retained receipts. A slot
above a lowered FD limit is unusable; general private-slot ownership is not
implemented. Sender-side controls separately compare direct and two-stage sends
of 253 rights under low limits, including failed-export cleanup. An isolated
io_uring capability probe records denial without making it a runtime prerequisite.
This experiment is not enabled in the guest adapter or the default suite.
Focused reports use `resource-fd-handoff-results.json` and
`resource-fd-parcel-results.json`; they do not replace `resource-results.json`.
Protocol and lifetime limits remain in the process-resources contract.

Distribution and emulator workflows use the same runner and per-instance policy:

```sh
python native/guest-exec-lab/test_distribution_runtime.py BUILD --build BUILD ubuntu --layout UBUNTU_LAYOUT --install
python native/guest-exec-lab/test_distribution_runtime.py BUILD --build BUILD centos --layout CENTOS_LAYOUT --install
python native/guest-exec-lab/rootfs_oci_fixture.py --help
python native/guest-exec-lab/test_qemu_runtime.py --help
```

The rootfs wrapper retains an unchanged official Arch Linux ARM tarball as one
OCI layer. Verify its detached signature before importing; wrapping alone is not
authentication. Arch package commands retain pacman's configured sandbox and
signature checks. Shroot supplies ABI 1 filesystem restrictions even when the
host lacks Landlock; `test_isolation.py` measures native availability separately.
`--arch-without-landlock` explicitly selects only pacman's filesystem-sandbox
opt-out for package checks; signatures and syscall filtering remain enabled.

`test_arch_runtime.py` is the separate **as-is** acceptance check. It rejects
effective sandbox opt-outs, retains `DownloadUser=alpm`, checks the stock account
transition, runs the filesystem restriction contract, then synchronizes pacman's
databases. `--install-package` also installs and runs `tree`, removing it only
when it was not installed before the check. Use a disposable instance with initialized signing keys and DNS;
synchronization changes its package databases. Neither missing Landlock nor a
failed synchronization counts as a pass. It compares the ABI probe with native
UID 2000, but does not mistake that probe for enforcement coverage.

```sh
cmake --build BUILD --target bootstrap supervisor run image landlock_guest vm_init
python native/guest-exec-lab/test_arch_runtime.py BUILD ARCH_STORE --install-package
python native/guest-exec-lab/test_kernel_vm.py BUILD --kernel ARM64_KERNEL \
  --fixture BUILD/libmagicdesk_guest_landlock_guest.so
```

The static `landlock_guest` fixture uses ABI 1 rights: permitted/denied paths,
symlinks, hardlink aliases, same-directory rename, rejected cross-directory
rename/link, preopened data FDs versus proc-FD reopening, ruleset-FD duplication
and mutation, stacked intersections, fork/exec, thread-local policy and retained
directory identity after rename/replacement. `--setup-only DIRECTORY` validates
only fixture setup and cleanup; it never reports enforcement success.
The same assertions run inside Shroot and under an unprivileged UID in a Linux
QEMU control VM. Native Android shell cannot create the fixture's hardlinks;
only its ABI probe runs outside Shroot on that device.

`test_kernel_vm.py` requires local `qemu-system-aarch64` and `cpio`. It creates a
minimal initramfs and records kernel/fixture/init hashes and the serial log.
The VM has no network, host filesystem attachment or Docker service. Its init
runs the contract as UID 1000 and powers off only that VM; it does not reboot
Android. A process deadline kills a hung emulator. This control is a reference
Linux implementation, not a Shroot pass or a new runtime kernel requirement.

XZ rootfs archives are transcoded without changing tar contents, including device
entries. The production importer retains logical device metadata and rejects
unsupported objects. Verify source signatures before
conversion; wrapping or transcoding alone does not authenticate a rootfs.
The QEMU fixture checks an x86-64 program's file IO and fork/wait through the
distribution's user-mode emulator, not KVM or full-system virtualization.

`test_qemu_docker.py` separately boots Alpine with QEMU TCG and exercises actual
Docker Engine inside the VM, including container/volume reuse and shutdown.
`prepare_astra_userspace.py` prepares official ARM64 packages for
`test_astra_userspace.py`; its repository checksums over HTTPS are not a pinned-GPG
authentication claim. `test_gentoo_runtime.py` checks stage3 userspace and GCC;
`--packages` adds repository synchronization and a GNU hello source-build,
installation and removal without disabling Portage's sandbox FEATURES.
`test_rootfs_oci_fixture.py` checks conversion digests, exact unfiltered tar content
and hardlinks without running an image. `test_oci.py` checks logical device import/backup,
lower-layer replacement, guest SHM, strict path/metadata handling and concurrent
inspection while another participant writes the same store.
Its helper-owner-death control needs a native FIFO: hosts denying native mkfifo
report that one fixture unavailable, not passed. Logical guest FIFO and device
checks remain required under the actual shell runtime.

## Watch Transport Controls

```sh
sh native/guest-exec-lab/build-watch-fixture.sh build/watch-fixture
python native/guest-exec-lab/test_watch.py build/watch-fixture
```

These standalone Bionic controls require the already selected UID 2000. They do
not install an APK or enable directory watching in the guest runtime. CMake's
`MAGICDESK_GUEST_FIXTURES` also builds `watch_queue`, `watch_read` and
`watch_activation`; none is installed into the APK.

The single-owner queue retains whole inotify records, adjacent coalescing,
bounded overflow and rejected-delivery state. Its stream socket carries readiness only.
Tests cover poll/edge-triggered epoll, short buffers, descriptor flags, dup,
SCM_RIGHTS lifetime, and a stolen marker failing without blocking the owner.
The owner does not retain a guest read end between operations. Record storage
is recycled up to its high-water mark; reads use caller-owned scratch memory.

The tracer fixture compares lazy process-wide and FD-selected read interception.
It checks zero ordinary-read stops before activation, short-record errors,
notification cancellation, EINTR, SA_RESTART and the application's signal context.
The FD-selected control additionally checks zero stops on unrelated reads after
activation, and validates the retained kernel-object identity after descriptor-number
reuse. Its microtimings describe this native fixture only, not GUI latency or
production-runtime overhead. Output memory is fixture-owned shared memory;
protected memory transfer and concurrent buffer mutation are not certified.

Two blocking transports have separate limits. A predeclared notification gate
uses the existing listener, but a filter admitting only the original read site
rejects it. The native same-site read control preserves that filter and signal
context, but is single-reader only: it restores a consumed readiness marker before
reading the queue. It does not implement production concurrent-reader ownership
or empty zero-length reads. Native inotify controls establish that an empty
nonblocking zero-length read returns EAGAIN, and that a record cannot span two
short readv vectors on the tested kernel. The mediated readv fixture exercises
only error/short-result completion within the first vector.

Activation controls explicitly observe EBUSY for a second USER_NOTIF listener,
ENOSYS rather than listener inheritance for a listenerless notification filter,
and TSYNC rejection after a peer diverges its filter chain. These are verified
limitations, not successful runtime workarounds. Production integration and
its ownership limits are described in the [watch contract](../shroot/watches.md).

## Production Watch Checks

Configure `native/shroot` with `-DMAGICDESK_GUEST_FIXTURES=ON`, then build
`bootstrap supervisor run service watch_guest watch_launch watch_store`.
`test_watch_runtime.py BUILD_DIRECTORY` stages immutable production binaries
through the configured MCP server, requires actual shell UID 2000, imports a
fresh disposable store and checks real guest libc inotify calls.
It neither installs an APK nor changes Desktop or access settings.
`--user 0:0` selects guest root, including the independent watcher/writer
launches, so newly created regular files exercise native names. The default
`--user 2000:2000` is the non-root catalogue control; neither changes Android UID.

The suite covers directory/name events, rename cookies, file-data events,
read/readv/FIONREAD boundaries, concurrent readers, dup/fcntl, queued SCM_RIGHTS
through recvmsg/recvmmsg, descriptor reuse, EINTR/SA_RESTART and 64 execs with
constant filter count. The complete glibc/musl suite runs again with dumpability
disabled. The filter-count observer retains its own proc FD across exec, avoiding
new selectors introduced by the measurement itself. `receive-filtered` forbids
further seccomp installation and rejects MSG_PEEK with an application filter:
the denial must preserve both the queued message and descriptor table. An allowed
receive then publishes all three rights with no filter growth, checks watch/pipe
IO, closes every alias and verifies pipe EOF and exact retained-channel ownership.
Churn checks 7,680 distinct duplicate targets without unbounded filter
growth. An aggregate interception counter detects accidental ordinary-read tracing
in the unsaturated case. Two independent observers receive a third launch's
mutations. Store controls verify rollback after SIGKILL, last-reader retirement
and journal-overflow notification. Reports retain exact uploads, identities,
commands and results; a timeout is a failure, not completion evidence.

`build-watch-libc-fixture.sh glibc|musl SYSROOT OUTPUT` builds the same guest
fixture with that userspace's libc. Pass its `rootfs.tar.gz` as `--rootfs`.
Use `--contracts` with the additional CMake targets `test_inodes test_import
test_rpc` for namespace/import/RPC regressions under the same shell identity.
Host-policy exclusions in the import fixture remain reported as LIMIT.

The GIO fixture links the stock Linux library and requires its inotify backend,
not a fallback poller. Its readiness follows successful registration; a separate
writer creates, renames and deletes the file. The D-Bus check registers ordinary
session-config watches and completes a bus request. It checks the named
`WATCH_PATH` counter, not a hardcoded operation number. The prepared NSS files
contain both guest users. A guest-root D-Bus warning about raising the host hard
FD limit to 65536 is retained as an explicit report limit; watch and bus failures
are not ignored. Build-only prepared inputs:

```sh
node native/guest-exec-lab/prepare.mjs build/watch-gio-sysroot --package libglib2.0-dev
sh native/guest-exec-lab/build-watch-gio.sh build/watch-gio-sysroot/sysroot build/watch-gio
python native/guest-exec-lab/prepare-watch-userspace.py PREPARED_DEBIAN_ROOTFS build/watch-userspace.tar.gz
python native/guest-exec-lab/test_watch_runtime.py BUILD_DIRECTORY \
    --userspace build/watch-userspace.tar.gz --gio build/watch-gio --contracts
```

Native fixtures and Linux libraries are not shipped in the APK. These focused
checks do not certify arbitrary application filters, cross-supervisor FD
transfer, all GUI workflows or performance against PRoot.

`test_watch_apps.py BUILD --store STORE --runtime FIXTURE_DIRECTORY
--keyboard-directory HOST_XKB --recipes RECIPE_CLASSES` uses the installed APK
and a prepared Debian/Alpine system containing Mousepad, Thunar, fonts and a
session bus. The fixture directory supplies `md-await-exit`; the recipe classes
are the existing app-side `GraphicalRecipe` fixture. On its own virtual display,
the test changes a document from another launch, accepts Mousepad's reload and
checks actual clipboard text. It creates a file externally in an open Thunar
folder, renames the visible selection, verifies the file from another process,
then moves the current folder and checks Thunar's parent navigation. Both clients
must exit with status zero. It never starts Desktop.

The guest fixture's `aliases DIRECTORY` command prints data-event attribution
before/after rename, unlink and last close with two hardlink names. It is a
characterization, not an assertion of exact Linux dentry history. Native controls
must report host hardlink permission denial rather than substituting copies.
