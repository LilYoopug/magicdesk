# Guest Runtime Fixtures

Opt-in development tools and reference fixtures for
[`native/shroot`](../shroot/README.md). Runtime sources live only in
that native component; this directory is not packaged into the APK.

## Namespace Clients

`test_systemd.py --build BUILD --store STORE` runs stock systemd as guest PID 1
under actual UID 2000. The disposable Debian-like store needs systemd, bash and
util-linux including `script`; optional `--trace` also needs strace. It creates private namespaces,
proc, `/run`, a private `/dev` with a PTY console, sysfs and cgroup2, then boots a dedicated target without distro
hardware units. Assertions cover system/user managers, oneshot/notify services,
TCP socket activation, stop and normal manager exit. The supervised deadline
bounds failures; it never invokes a host reboot or shutdown target. This is not
a default-target boot or GNOME login test.
`--property KEY=VALUE` extends the tested oneshot's service restrictions.
The combined `StateDirectory=md-init-probe` and `SetCredential=md-probe:hello`
case covers filesystem metadata ioctls, read-only tmpfs reconfiguration and
Arch 262's nosymfollow credentials mount. A diagnostic `MountFlags=slave` case
can isolate other namespace policies, but does not certify default propagation.
The combined hardening case also covers `ProtectProc=invisible` and `ProcSubset=pid`.

`test_proc_policy.py BUILD STORE` checks mounted proc visibility with stock
Python/util-linux: all four hidepid modes, primary/supplementary exception groups,
fsuid, native dumpability, retained directory FDs, zombies, subset filtering,
fsconfig, bind aliases and namespace copies. Invalid creation options and
unsupported option remounts must fail, not silently relax a policy. The native
resource-owner fixture checks allocation-free credential snapshots before and
after task retirement, with exact descriptor cleanup.

`test_os_boot.py --build BUILD --store STORE` boots the packaged default target
and asserts a non-degraded result. Its observer waits for systemd's startup
jobs and collects only this invocation's journal, failed units and service state.
Debian, Ubuntu, Arch and Fedora default boots currently fail or remain degraded;
the fixture does not whitelist them. `--trace` includes pathname lookup, metadata,
both mount APIs, process/exec boundaries, application seccomp installation and
epoll creation/registration/waits, using the same syscall set as the manager
fixture. `--init openrc` uses Alpine's real
`openrc-init`, stock container service policy and a private runlevel selection.
It checks the default services, restart/stop and exact launch-registry cleanup.
The device transport is closed only after that launch has terminated.
`init_fixture.py` owns the shared private-filesystem/console setup; OpenRC's
in-guest observer does not import host-side transport dependencies.

`test_resources.py BUILD --case control-event` runs source and virtual-interest
model fixtures as UID 2000. They cover generation coalescing, concurrent
publication/subscription/retirement, duplicate event data, open-description
identity, level/edge/one-shot delivery, bounded fairness and failed admission.
Weak authority checks race final release against temporary acquisition for
10,000 rounds. Expiry remains observable without retaining the target, and
disabled one-shot interests retire without inventing an application event.
Mixed native/virtual collection performs 100,000 rounds with allocation guards
and exact FD cleanup. This is an internal collector test, not a guest epoll
notification test. The same case runs real native and Shroot wait loops and
requires zero interception counters for `ppoll`, `pselect6`, `epoll_pwait`,
`epoll_pwait2` and registration, both before and after an application
filter denies further seccomp installation. Timings are diagnostic, not a
stable performance benchmark. Native and guest runs also retain epoll identity
through dup, forked registration changes and queued SCM_RIGHTS after all source
aliases close; both received aliases observe the same kernel interest set.
Epoll creation alone retains its expected observation count. A BPF interpreter
checks selector classes, FD argument positions, collisions, gate addresses and
native wait decisions. The native remote-admission fixture installs that same
filter through a stopped task and compares its continuation with an unmodified
ptrace-interrupt baseline, for dumpable/protected processes and allowed/denied
seccomp. Pipe reads restart; epoll reports the kernel's EINTR. Signal masks and
application filter errors must survive either outcome. This proves the cold
syscall mechanism, not guest readiness or admission across all owners. Two-thread
checks require successful TSYNC to reach both callers, and an incompatible
sibling to reject synchronization without changing either caller's filter.
The same task-filter module additionally runs at syscall-entry, seccomp and
completed-exit stops: the original pipe write must execute exactly once, with
the restored syscall-info boundary. Restart-code exits must reject admission
without changing registers or signal masks, then complete native signal restart.
Real task-filter calls borrow their stop from the common quiescence owner;
synthetic interruption and deferred syscall events retain separate resume
ownership. Model checks reject premature release, event replay and double return,
and preserve the original event's rusage.
Production proc/watch installation also uses this supervisor-owned task-filter
call. The buffer fixture fills its IO pool while admitting a reserved control
loan in the same mapping. Filter construction leaves delivery bytes unchanged;
pin/release and reuse allocate no memory or extra guest descriptor. Guest selector
regressions exercise this path through opens, dup and prepared sandbox filters.
The `ofd-order` case checks typed sysctl masks, read independence, independent
opens/shared references, UTS copies, constant providers and concurrent lazy
carrier publication. It also exercises the typed epoll authority through the
actual file-table and queued-message owners: publication failure, dup/reuse,
fork/unshare, exec CLOEXEC, transfer after source-table teardown and final
transport cleanup. Empty authorities have no wake FDs; completion and retirement
run under allocation-failure guards. Watched targets also traverse dup/fork,
queued transfer and final CLOEXEC release without manual collector retirement.
The cold admission inventory checks shared/copied tables and thread groups,
masked-selector collisions, late owners from an in-flight fork, queued table
mutations, allocation failure, positive TSYNC rejection and partial-installation
retry. Unobserved close/dup outcomes must invalidate virtual admission, including
unknown duplicate numbers, and wake a retained collector with an explicit error.
The live fixture joins that inventory to the task-filter and quiescence modules:
three real processes share one epoll through two aliases, with CLONE_FILES and
forked tables. Dumpable and protected variants require installation in every
holder. Partial application denial must abort virtual activation, retain only
confirmed selectors and allow native waits through those residual filters.
These checks do not whitelist default-boot
failures or establish guest virtual-subscription admission.

`test_journald.py --build BUILD --store STORE --probe-only --trace` starts a
private systemd target and runs a selective TSYNC-filter probe in the same
process that execs stock journald. The service retains its distribution security
policy. The probe changes only an invalid epoll descriptor's error result;
successful native waits remain native. Probe-only success establishes filter
admission, not journald readiness. Without `--probe-only`, a failed journal
service fails the fixture. Trace output uses the shared init syscall set.

The native `fd-lifecycle` case checks `KCMP_EPOLL_TFD` identity across duplicate
descriptors and queued SCM_RIGHTS, automatic removal after final release and FD
reuse. Its private observer does not retain the target OFD, but adds a nesting
level: a valid maximally nested application epoll rejects it with ELOOP. This
is a diagnostic boundary, not a production ownership mechanism. The fixture
discovers the native depth rather than requiring a particular kernel's limit.

`test_openrc.py --build BUILD --store STORE` needs an Alpine store with openrc
and util-linux. It runs stock sysinit/boot initialization and dedicated runlevels
inside private mounts/PIDs, checks dependency order and daemon status/restart,
then verifies stop and process cleanup. It neither creates a fake OpenRC boot
marker nor invokes reboot/shutdown. The fixture shell owns PID 1; this does not
test the separate `openrc-init` program or default distro hardware services.

`test_resources.py BUILD --case mount-namespace` includes offline network
namespace identity/authority, inherited IPC, private devpts membership and
controlling terminals, logical cgroup membership/readonly policy and native
anonymous-memfd statx. Cgroup namespace cases exercise captured roots for both
hierarchies, relative paths through existing and mounted proc, clone/setns,
retained namespace handles, removal, user-namespace authority and fsopen capture.
Namespace-file binds cover path and O_PATH sources, nsfs metadata, setns and
related ioctls, exited owners, recursive binds, independent namespace copies,
mount-cycle rejection, readonly controls and repeated lazy-unmount retirement.
The remaining mount/user/PID/UTS/IPC cases run in the same suite. Open and detached
mount descriptors also compare fdinfo mount/inode fields with statx.
`test_mount_api.py` covers tmpfs superblock reconfiguration with live/unlinked
writers, retained shared mappings, bind aliases, namespace copies and separate
per-mount restrictions. The transient-store native fixture checks independent
process connections and policy invalidation, as well as exact descriptor cleanup.
The mount-API fixture also checks nosymfollow on detached/native/proc mounts,
per-alias remount, retained origins and namespace copies. Initial-root remount
and propagation use identical pathname/proc-FD assertions; a chroot into an
ordinary directory must not turn that directory into a mount root.
Removed-mountpoint cases synchronize independent namespace views, remove and
recreate a covered directory, then read mountinfo, recursively clone or copy the
namespace. Nested mounts disappear while retained root/child FDs remain usable.
Graph tests also check native/logical deletion, rename, independent store writers,
foreign-reader authority, published revisions and exact descriptor cleanup.
Storage fixtures exhaust the native FD table during database open, journal
creation and mount copying; they require EMFILE, rollback and recovery after
descriptors are released, not a generic IO error or a partially published view.
Filesystem-attribute ioctl checks cover regular files, directories, bind aliases,
detached tmpfs, dup/fork/SCM_RIGHTS and a seccomp-filtered caller, without exposing
Android storage attributes. Native readonly attachments and pipe ioctls retain
their distinct semantics. Mount-graph checks cover local provider publication,
explicit foreign rejection, restored synchronization and allocation rollback.
File binds cover non-link readlink errors and exact mount-root paths for
hardlinked sources. Proc directory suffix tests exercise two-path rename/link,
nofollow and followed symlinks, mixed dirfd/path operands, readonly and EXDEV
rejection through direct, symlinked and bind-mounted proc views.
Pivoted non-base roots retain proc/dev providers across namespace copies.
Mounted-store image tests retain exact hardlink and symlink names alongside
per-mount executable identities.
Native storage tests bind both names of a hardlinked file, recursively and
non-recursively, with an unrelated locked mount present. They check shared
contents, independent readonly policy and exact descriptor cleanup.
Socket binds retain the selected endpoint through hardlink aliases and unlink;
readonly mounts allow connections while socket write permissions remain enforced.
Tmpfs cases cover permissive capacity requests, malformed options, native writes
and shared mappings, aliases and detached ownership. Key-service absence checks
cover protected callers, fork/exec, namespaces, chroot and application filters.

`test_namespace_apps.py BUILD STORE --case split-root` runs stock Bubblewrap
with separate `/etc` and `/usr` binds, merged-usr links, proc/dev mounts and
private tmpfs. Its guest checks realpath and atomic replacement through proc-FD
paths. The prepared store supplies Bubblewrap and ordinary shell utilities.

`test_mount_api.py BUILD STORE` checks descriptor-based mounts with stock
util-linux consumers. It covers filesystem-context lifetime and authority,
SCM_RIGHTS, detached IO, recursive mount attributes and all-or-nothing rejection
of locked policies. ABI checks include empty paths, nofollow, versioned
structures, shared openat2 validation, protected callers and explicit errors
for unsupported attributes. The prepared store needs Python and util-linux.

`test_mount_capacity.py BUILD STORE` checks 192 simultaneous guest bind mounts,
distinct mountinfo identities, namespace-copy isolation, detached directory FDs
and slot reuse. The native mount-graph fixture also checks all 512 slots, copies,
exact FD cleanup and graph transport beyond one SCM_RIGHTS message.

`test_mqueue_mount.py BUILD STORE` checks the limited IPC-owned mqueue filesystem:
mount/fsopen capture, shared metadata, isolated owners, setns, copied/bound mounts,
readonly policy, detached descriptors and explicit unsupported queue operations.
It requires Python, util-linux and strace, but no compiler or host mqueue support.
The native resource-owner fixture separately checks final-owner tree/FD cleanup.

`test_device_bind.py BUILD STORE` checks EPERM for device creation without
CAP_MKNOD, proc-FD bind targets, native rdev/IO, nodev and detached FD lifetime.
Regular-file/FIFO creation and non-root denial remain covered. It requires
Python and util-linux. `/dev/full` binding and metadata are required even when
Android denies data access; the bound path must preserve that denial.
Native `/dev/full` IO is conditional on Android shell
access; a denied source is reported separately, not counted as successful IO.

`test_cgroup_bpf.py BUILD STORE` checks permissive cgroup2 device-program
load/info/ID lookup, multi-attach, detach, inherited queries and removed-group
lifetime. Coverage includes dup/fork/protected exec, SCM_RIGHTS, readonly
targets, full FD tables, ENOSPC/EFAULT, versioned attributes and repeated exact
warmed FD cleanup. It verifies that return-zero programs do not enforce device
restrictions and that network hooks/maps/BTF remain unavailable. The store
needs Python and util-linux, not host BPF permission or a compiler.

`test_network_sysctl.py BUILD STORE` checks namespace-owned IPv4 parameters,
bounded parsing, coordinated port ranges, namespace isolation and writer
authority. It includes retained FDs across unshare, shared dup offsets, positional
IO, O_PATH metadata and readonly remount/detach enforcement. Host sysctls are not
written. The prepared store needs Python and util-linux.

`test_routed_network.py BUILD STORE` exercises opt-in routed IPv4 with stock
iproute2: bridge/veth topology, namespace-FD moves, routes, TCP/UDP, addressed
messages and teardown. The native resource-owner tests cover atomic netlink
mutation/ACK rollback, port conflicts, credentials and endpoint ownership.

`probe_docker_runtime.py BUILD STORE --profile routed --cgroup v2
--storage-driver overlay2 --image python:3.13-alpine --exercise-ports` runs stock
Docker/containerd/runc under the selected executor. It requires those packages
in a disposable Debian store. Assertions cover two containers with identical
internal ports, bidirectional peer exchange, outbound DNS/HTTP, TCP/UDP `-p`
publication from an observer outside Shroot, conflict rejection, port release
and daemon shutdown. VFS is selectable independently. Diagnostic profiles
without `--exercise-ports` record capabilities, not passing port coverage.

`test_proc_mount_policy.py BUILD STORE` checks omission of unsupported host-kernel
controls in namespace-mounted proc, consistent lookup/enumeration, ordinary proc
binds and readonly remounts. It never writes host control files.

`test_sysfs.py BUILD STORE` checks the logical offline sysfs provider through
legacy mount and stock util-linux's descriptor API. Coverage includes live
netlink/ioctl agreement, namespace capture and authority, namespace copying,
file/directory binds, detached descriptors, cgroup nesting, metadata and
unsupported mutation errors. It also checks that native truncate cannot modify
the carriers of sysfs or cgroup controls. The prepared store needs Python,
util-linux and strace.

`test_glycin_runtime.py BUILD STORE --library libglycin-2.so.0` invokes the real
distribution loader with Bubblewrap and its original seccomp filter. It asserts
the decoded RGB pixels, not just process startup. The explicit
`--fixture-deb PATH` option extracts additional packages only into the selected
disposable test store; `--trace` retains diagnostics and strace output. It must
not be used against a user's installed environment. Glycin 1.2.1's ARM64 filter
can reject the libc uname call used for SVE detection; Glycin 2.x includes the
upstream correction. Selecting a newer loader does not disable sandboxing.
`--format png|svg` selects exact pixel checks; Fedora 44's stock Glycin 2.1.5
passes both formats under UID 2000.

`test_proc_root_runtime.py BUILD STORE` checks foreign proc-root traversal,
retained roots after target exit, credential rejection, protected readers,
live fdinfo position/flags/close state and logical pidfd fields. Foreign FD
stat/statx/readlink cover sockets, pipes, deleted files, namespace handles,
close/reuse and target exit; cwd and executable metadata select guest objects.
It runs with
implicit proc and with stock `unshare --pid --fork --mount-proc`.
Its selector fixture checks proc/watch/native reuse in both filter orders,
fork/exec retention, and typed netlink duplication through dup, dup3 and both
fcntl commands. Independent child cases check flags, source closure, inherited
aliases, native-width command decoding and actual netlink response readiness.

`test_thread_identity_runtime.py BUILD STORE FIXTURE --debuggers` uses the glibc
`md-thread_identity-fixture` built by `build-libc-fixtures.sh`. Ordinary and
nondumpable callers exercise recursive pthread mutexes, shared-memory clone
parent/child TID fields and kernel child clearing. Optional installed strace/GDB
must observe normal completion inside a PID namespace.

`test_desktop_services_runtime.py BUILD STORE` checks a stock system D-Bus daemon,
authentication from the `developer` account and PipeWire's real `pw-cli info 0`
request. It creates a private PID/proc/run view and waits on daemon output;
no systemd boot or host bus is required.

`test_gnome_runtime.py BUILD STORE` runs Fedora 44 GNOME devkit in that private
service arrangement with PipeWire/WirePlumber and llvmpipe. The disposable store
needs GNOME Shell, GNOME Text Editor, the `developer` account and their ordinary
distribution dependencies; the host needs ImageMagick. It creates its own virtual
display, checks rendered content and Alt+F2, launches the editor and verifies
both its bus registration and visible window. Screenshots and the exact launch
recipe are retained in the report. Cleanup stops the graphics session and removes
the display. `--trace` adds strace diagnostics. This is not a GDM login, booted
systemd session or GPU test.

`browser/test_browser.py --build BUILD --store STORE` checks stock Chromium's
sandbox-enabled user/PID route and JavaScript execution. These application
checks do not certify kernel-equivalent confinement or Docker Engine support.

`test_native_reads_runtime.py BUILD STORE` checks inode, bind and native reads
under shell, including protected callers and managed proc-FD observations.
Bind aliases retain the opened descriptor's exact mount provenance.
Process credentials, kernel dumpability and logical namespace handles retain
their respective access rules. The filesystem directory suite also checks
direct worker observations against FD reuse, occupied table turns and typed
provider fallback, including exact descriptor cleanup. Authenticated native
service owners use native inspection rather than guest-table admission;
nondumpable owners retain the caller-side permission check.

## Holo ARM64 Userspace

### Executable Private Memory

`test_jit_memory.c` covers the native policy matrix, private-memory preparation,
replacement transactions and automatic mprotect repair. Build the native
`jit_memory` and `task_quiesce` CMake fixtures. The matrix takes one writable
directory; `--automatic` and `--automatic-threads` require a Shroot launch.
`test_resources.py BUILD --case private-memory` checks memory ownership and runs
the backing-lifetime regression: independent opens, 32 exec images and 256
mappings share one file source, with fork, failed mmap, status flags and final
unmap checked against exact FD counts. It runs the JIT policy fixture natively
and in an isolated Shroot store. It asserts supervisor
proc/backing capture, independent protected-child memory, FD exhaustion cleanup,
and noexec preservation after optional provenance loss. Worker-pause checks cover
acknowledgement, queued work, independent workers, cancellation and shutdown
without allocating another transport or retaining database locks. Compare actual UID 2000
execution with execution inside the guest; a virtual guest UID is not the host
executor identity.

The matrix compares anonymous, private/shared memfd and regular-file mappings.
It detects why unconditional anonymous/shared/backed-snapshot substitutions
violate file reload or fork semantics. A separate single-threaded private-view
prototype executes generated ARM64/x86-64 code, retains the original description,
checks W^X, fork isolation, kernel IO, backing reload, relocation and failed
preparation. Its explicit reload operation models logical `MADV_DONTNEED`;
it does not transparently intercept arbitrary application syscalls. Native
private-COW execution denial is reported independently of those assertions.

The file-backed preparation checks use `native/shroot/src/private_memory.c`
directly, without interposition. They copy only private COW pages into a clean
executable view, retaining native DONTNEED and clean-page file coherence. The
fixture also covers repeated compilation, nonzero offsets, partial and PROT_NONE
views, stale provenance and retained proc access after PR_SET_DUMPABLE=0.
Fresh-candidate soft-dirty admission is checked through pagemap with smaps
deliberately unavailable, for ordinary and nondumpable callers.
The 513-page fixture crosses pagemap batch boundaries with dirty and clean pages,
checking exact copy counts and continued visibility of clean-file updates.
Contiguous COW runs cross copy-buffer boundaries; incremental copying returns to
its caller after at most 256 page entries, without copying clean gaps.
`memory_replace.c` is exercised at every cancellation boundary, with failed
reserve/save/install/restore/cleanup and missing terminal observation. Native and
guest checks execute its commands, including rollback after a simulated fixed
move removes its destination before failing. Both original COW data and native
DONTNEED survive rollback; completed transactions retain no scratch mappings.
The same suite tests the automatic supervisor path with ordinary application
`mprotect`, closed input FDs, generated code, backing reload and repeated RX.
Four concurrent JIT writers run alongside namespace IO with both ordinary and
nondumpable credentials, including proc-FD closure and immediate number reuse
for memfds. Protected source capture uses the production SCM_RIGHTS
helper. `test_task_quiesce.c` checks preserved resume modes, deferred signals and
rusage, pending syscall/debugger interrupts, both birth-event orders, helper ownership and a new barrier before all
previous events are replayed. Stock SteamOS Plasma QML also has device coverage
with this runtime, without preload or a disabled JIT; compositor GPU coverage
is separate.
Barrier coverage also includes repeated 4,096-participant generations, hash
collisions and exact readiness after the final stop.
An independent process performs namespace IO during 8 MiB repairs; diagnostics
must show events serviced inside the address-space barrier. Remote process-memory
writes and inherited proc-memory descriptions check data preservation and selection
of the conservative exposed-memory barrier. Proc-memory variants cover direct
opens, `openat2` and writable reopening of O_PATH descriptors. Exposure follows
CLONE_VM ownership, not a fork copy or the next exec image. Both `vfork` and
ordinary CLONE_VM children compile code before exit/exec; their parent continues
compilation afterwards.
Worker completion admission holds one result while another completes on the same
worker, produces no repeated wake while held, and publishes exactly once on release.

### Audio Continuity

Run `fixtures/audio-continuity.py --env-pid DESKTOP_PID --target NODE --seconds 90`
inside the selected guest session. Use a desktop/client environment rather than
PipeWire's server-only configuration. The fixture records stereo 48 kHz PCM,
reports all-zero 10 ms blocks after warmup and delivery gaps over 80 ms, and
retains monotonic observation times. `test_audio_continuity.py` checks fragmented
input, warmup, trailing bytes and quiet but nonzero samples.
For one continuous idle/motion/idle recording, replace `--seconds` with
`--phase idle-before:30 --phase motion:30 --phase idle-after:30`. Phase events
report both the intended PCM-frame boundary and its actual observation time;
the external input driver records when it starts and stops. No recorder is
reconnected between phases. Tests cover late delivery across phase boundaries.

Use a continuously sounding source. Zero spans during intentional silence are
not underruns; zero graph/xrun counters are not evidence of continuity. For a
game workload, verify pointer capture, then repeat identical relative movement.
Correlate source/sink PCM with the audio threads' scheduling, without tracing
every supervisor syscall during the measurement. Recording ends after receiving
the requested frames and sending SIGINT: pw-cat can return 1 for this intentional
stop because it reports success only for drained playback. Unexpected early EOF,
missing frames, stderr and other termination codes remain failures. See
[pw-cat](https://github.com/PipeWire/pipewire/blob/master/src/tools/pw-cat.c).

`fixtures/jit_workload.qml` measures repeated function compilation through stock
Qt QML, checking the numerical result without a machine-specific speed threshold.
Run `QT_FORCE_STDERR_LOGGING=1 QT_QPA_PLATFORM=offscreen qml --apptype core
jit_workload.qml` with JIT enabled. Alternate runtime builds against the same
userspace and compare multiple samples; this is not a compositor frame-rate test.
The automatic JIT fixture also holds a `CLONE_VM|CLONE_VFORK` child at a pipe
rendezvous while another thread compiles, then checks both child exit and exec
and subsequent parent compilation. Readiness and release use pipe events; the
alarm bounds a deadlocked writer barrier.
`test_debugger_runtime.py --case gdb-jit --case strace-jit` repeats private-file
compilation under a guest debugger. GDB observes all four generated-code versions
without helper threads; strace sees successful application mprotect calls without
the internal replacement syscalls or helper births. The same harness covers
ordinary and multithreaded attach, detach and shared-memory helpers.
`test_resources.py BUILD --case fd-handoff` also checks expired queued ADDFD
admission, notification restart before queue readiness and retained-carrier
cleanup with ordinary/protected receivers and both CLOEXEC modes.

### Steam Client

`test_steamos_runtime.py BUILD STORE [--archive HOST_TAR]` imports a prepared
Holo rootfs into a new store and checks guest identity, SysV IPC, FIFO,
user/PID/mount namespaces and HTTPS as `steamlab`. Archive ownership is retained;
the executor must be UID 2000. It does not boot SteamOS or alter Android partitions.
`--socket-owner` checks stock `lsof` discovery for a loopback listener and an
established connection between parent and child. Queries by the client's port
must retain both owner PIDs, guest UIDs and parent PIDs; command durations are
reported separately. Neither `lsof` output nor Steam's peer verification is
replaced. Small-fixture success does not establish discovery latency in a
large graphical process tree.

`test_steamos_graphics.py BUILD STORE --client steam|glx|vulkan|gles` uses ordinary
shell graphics sessions and private virtual displays. The prepared store needs
the ARM Steam bootstrap in `/home/steamlab/client`, XKB data in
`/usr/share/xkeyboard-config-2`, Turnip in `/opt/mesa`, and the glibc-compatible
Freedreno bundle in `/opt/mesa-debian`. Steam also needs its Holo GUI dependencies
and the ARM64 GTK2 libraries from Valve's Steam Runtime in `/opt/steam-gtk2`;
Holo's `gtk2-compat` package provides build metadata, not those shared libraries.
The build directory supplies
`recipe-classes` from `GraphicalRecipe.java` and the `md-await-exit` completion
fixture. `--timeout` bounds the entire launch, including Steam's own updates;
no sandbox-disable flags are supplied. `--window-title` requires an exact native
window title so an updater cannot stand in for the login UI. Bounded pixel
observation rejects a blank frame and Steam's small initial loading indicator;
visually inspect the captured form. GPU probes capture changing frames.
Steam mapping/capture is reported separately and is not a successful login,
game execution or complete SteamOS session. Cleanup cancels the owned runtime
and observes its exit before releasing the graphics session and display.

`test_debugger_runtime.py OUTPUT --instance STORE --build BUILD --case clone-untraced`
checks copied/shared file tables, zero/SIGCHLD exit signals, guest filesystem
access and guest-debugger non-inheritance for `CLONE_UNTRACED` children.

## Named Environment Workflows

`test_environment_workflows.py --tag NAME --stage all` installs fresh public
Debian and Alpine images through the installed APK's shell-owned catalog. It
checks package installation, account login, concurrent cancellable operations,
authenticated file import/export and cleanup, then simultaneous X11/Wayland
editors with keyboard input, bidirectional clipboard and saved-file readback.
Backup checks remove the original instances, restore new storage identities and
relaunch graphical clients against the restored files.

The fixture uses a virtual display without Desktop and retains its two named
environments and archives for inspection. `--stage prepare|accounts|files|graphics|backup`
can run a focused phase against the same tag. `--dns system` is the default;
an explicit address opts into that resolver for the test stores when Android's
network uses Private DNS or a VPN. `--apk PATH` installs through the normal MCP
update protocol; `--lease ID` reuses an existing wake lease without releasing it.
Reports and screenshots live under `build/environment-workflow-*` and
`build/check-*`. No Termux executor, Android root or HOME lease is required.

The file phase invokes debug-only `GuestFilesInstrumentation` with an exact
store. It exercises production shell admission, the selected-guest static helper,
Android import, independent guest read, SCM_RIGHTS export and owner-loss cleanup,
without creating a graphical session.

`test_environment_catalog.py --names NAME NAME` uses prepared named Debian and
Alpine environments with Python 3 and Mousepad. It checks independent catalog
identities, rendered X11/Wayland windows, shared terminal ownership, and exact
CLI/MCP stop without cancelling a peer. Test-only desktop entries are added to
the selected guests and removed after successful checks. The owned virtual
display and graphical sessions are released on exit.

`test_environment_recovery.py --help` documents an opt-in process-death check.
Its `--kill-app` mode terminates MagicDesk during a native restore and reopens
the exported launcher, interrupting any other work in that app process. Run it
only on an idle device. It uses a private library, preserves the default catalog,
verifies helper termination, then recovers staging and retries the restore.
Neither fixture reboots the device or requires a Desktop session. Reports are
`build/environment-catalog.json` and `build/environment-recovery.json`.

## Prepared Runtime Fixtures

`prepare.mjs` authenticates Debian archive metadata and packages, then extracts
an isolated test rootfs without maintainer scripts or host installation.
`build.sh` builds the same CMake runtime as the APK and separate Bionic/glibc
fixtures. It requires the Termux development toolchain and JDK; installed guest launches
do not require Termux. Exact inputs are retained in the build's `manifest.json`.

```sh
node native/guest-exec-lab/prepare.mjs build/guest-fixtures --gtk
sh native/guest-exec-lab/build.sh build/guest-fixtures
python native/guest-exec-lab/test_device.py build/guest-fixtures --packages
python native/guest-exec-lab/test_graphics.py build/guest-fixtures
python native/guest-exec-lab/test_graphics.py build/guest-fixtures --gtk
```

For real application workflows, use a separate prepared build:

```sh
node native/guest-exec-lab/prepare.mjs build/guest-applications --applications
sh native/guest-exec-lab/build.sh build/guest-applications
python native/guest-exec-lab/test_device.py build/guest-applications --packages
python native/guest-exec-lab/test_graphics.py build/guest-applications --application mousepad --network
python native/guest-exec-lab/test_graphics.py build/guest-applications --application galculator
python native/guest-exec-lab/test_graphics.py build/guest-applications --application mousepad --routed
python native/guest-exec-lab/test_graphics.py build/guest-applications --application mousepad --routed --protocol x11
python native/guest-exec-lab/test_shortcuts.py build/guest-applications --protocol wayland
python native/guest-exec-lab/test_shortcuts.py build/guest-applications --protocol x11
```

For Qt text-input-v3, prepare the newer Debian userspace separately:

```sh
node native/guest-exec-lab/prepare.mjs build/guest-qt --qt --suite trixie
sh native/guest-exec-lab/build.sh build/guest-qt
python native/guest-exec-lab/test_device.py build/guest-qt --packages
python native/guest-exec-lab/test_qt.py build/guest-qt
```

Bookworm is the default suite; trixie uses the same pinned signature and package
hash verification, including the signed Release's exact codename. Qt packages
belong only to the prepared fixture store, not the APK. The Qt driver temporarily
selects the debug Android IME and restores the prior keyboard on completion or
failure. It retains a protocol trace and separate strict-correction and
`--skip-correction` reports; the latter cannot establish correction support.

Application checks require a current debug APK with the guest CLI installed.
Routed checks use the production guest connection/session wrappers and keep one
protocol session across successive clients. The X11 case also verifies rejection
of an incorrect MIT cookie. Receipts retain protocol and connection mode; pixel
capture, input, process exit and cleanup remain separate assertions.
They use its runtime and the production Java graphical-session wrapper.
The fixture-only `md-prepare-applications` configures real shell NSS identity,
toolkit caches, CA certificates and an explicit public DNS resolver in the owned
test store. `--network` opts into DNS and certificate-verified HTTPS checks.
Mousepad coverage includes editing, saving, fresh-process file readback and
reopening; both applications must exit normally, not merely lose their window.
Settings checks exercise real D-Bus activation and persistence, not a substituted
keyfile backend. Application logs and hashed screenshots accompany the JSON report.

`test_shortcuts.py` encodes the shortcut editor's real `LinuxLaunchRecipe` through
a debug-only Java fixture and launches the resulting `.desktop` files through
the ordinary launch service. It checks bidirectional Unicode clipboard exchange,
guest file saving, file-dialog cancellation, opening another file, Save As,
overwrite confirmation, directory creation and inaccessible paths. It also checks
concurrent applications in one store, recipe reuse and actual process exit after
protocol close. Catalog events identify Wayland dependent windows; native-family
events identify X11 transient dialogs and Wayland subsurfaces without guessed IDs.
Inotify receipts identify
the exact command's start and exit. Screenshots are point-in-time observations,
not synchronization barriers. Input requires the selected native window's
Android host and focus acknowledgement. Opening a file awaits the exact client
title and verifies the document contents independently through the clipboard.
The test restores an existing plain-text clipboard
and refuses to replace non-text contents. Launchers and their receipts remain in
the prepared test directory for inspection; their launches participate in Recent.

The default calculator workflow checks `7+8=15`. An additional
`--repeat-digit` check sends `2+2` without a pacing delay and requires `4`.
It currently reads `2` on the tested Wayland stack and retains a separate failing
`*-shortcuts-repeat-digit-results.json`; it must not be treated as passing
input coverage or hidden by a sleep. `--trace-wayland` retains the calculator's
client-side protocol log. Both key press/release pairs arrive before Galculator's
[100 ms toggle reset](https://github.com/galculator/galculator/blob/v2.1.4/src/ui.c#L748-L760):
the second click deactivates the button and its
[digit handler](https://github.com/galculator/galculator/blob/v2.1.4/src/callbacks.c#L95-L107)
ignores it. The Debian binary has the same logic. Mousepad's repeated-digit
control passes; production input is unchanged. Calculator configurations are
unique to each run, so another run's saved notation cannot affect the result.

Device checks use the configured MagicDesk MCP connection and require selected
shell UID 2000. They do not change identity, install an APK or start Desktop.
Graphical checks use a private virtual display and clean up their own sessions.
Results retain exact device/build identities, commands, failures and known limits.
Prepared shell-owned test stores remain at the recorded path for inspection.

Capability fault injection checks that missing kernel calls reject only guest
execution. Process fixtures cover concurrent distinct stores, cancellation and
orphan ownership. These checks do not emulate an old kernel or prove compatibility
with every distribution. See the native component's coverage and limits.
The native prepared-command fixture runs under the selected shell identity and
checks interpreter descriptor pinning across name replacement, borrowed/unlinked
executables, argument identity and descriptor cleanup. It is not run in the
Termux app domain, whose syscall restrictions differ from the guest executor.

## Libc, IPC And Desktop Checks

`build-libc-fixtures.sh glibc|musl SYSROOT OUTPUT` builds the same execution,
thread/signal and IPC tests against the selected libc, without libc-specific
runtime branches. The musl fixture uses the official Alpine 3.23 ARM64 minirootfs
and its matching `musl-dev` headers/CRT. Prepare the distribution's ordinary
dependencies and toolkit caches before importing the tree; the ELF loader does
not install packages or create accounts. `fixtures/md-prepare-alpine` configures
only disposable GUI-test data for the real shell identity. Fixtures require the
current runtime's store schema; incompatible stores are rejected without modification.

`test_ipc.c local NEW_DIRECTORY` checks namespace socket names, permissions,
SCM_RIGHTS, unlink/rebind, rename and stale listeners. `paths` checks `/dev/shm`
through absolute paths, dirfd and a host-directory cwd. The separate static
Bionic `md-ipc-launch RUNNER STORE [OTHER_STORE]` starts independent supervisors
and filesystem services, checks shared memory, file-data inotify and unlinked
lifetimes, and optionally verifies name isolation from another store.
These are not directory-inotify or abstract-socket isolation tests.

`build-static-fixtures.sh glibc|musl SYSROOT OUTPUT` additionally builds static
ET_EXEC and PIE programs at 64 KiB and 2 MiB alignment. The glibc sysroot requires
its matching `libc6-dev` and GCC 14 static support libraries; musl requires its
matching development archive and compiler builtins. `build.sh` also builds a
freestanding raw-SVC ELF without libc or mapped program headers.

```sh
python native/guest-exec-lab/test_abi.py BUILD \
  --libc glibc --libc-build BUILD --static-build STATIC_BUILD \
  --store DISPOSABLE_HOST_STORE --runtime IMMUTABLE_STAGED_HELPERS
```

Repeat with the musl outputs and Alpine store. These checks include descriptor
and dirfd exec, open-unlinked/name-reused executable identity, bounded shebang
parsing, 64 successive execs, thread/signal stacks, vfork, spawn file actions,
process-image snapshots, Unix sendmmsg partial batches and SCM_RIGHTS.
They install fixture programs only into the explicitly selected disposable store.

## Distribution Packages And Applications

`fixtures/md-import-debian-rootless` prepares a copied official Debian rootfs
for the real shell UID before import. It does not fabricate package records.
`md-package-debian`, `md-package-alpine` and `md-package-upgrade` exercise real
signed repositories, dependencies, scripts, HTTPS, removal and updates in
disposable stores. Preserve the official image hash and package-manager logs.
The Debian ucf preparation explicitly enables real configuration-file updates
in that fixture; the normal non-root dry run is not a configuration pass.
These scripts are not a product distribution installer or a container manager.

```sh
python native/guest-exec-lab/test_distribution_app.py BUILD \
  --store DISPOSABLE_HOST_STORE --runtime IMMUTABLE_STAGED_HELPERS \
  --keyboard-directory HOST_XKB --protocol wayland --application writer
```

The prepared store supplies its normal packages and caches. `writer` and `calc`
edit/save ODF documents, check clipboard text, close normally and read saved XML
in a new guest process. Both pass on Wayland; Writer also passes on X11 with
`--x11-manager`. Calc's X11 insertion check remains failing, and Writer startup
without the manager remains unverified. The fixture retains these failures,
including the expected cell contents, rather than weakening its assertions.
`gimp` checks a dialog and closure. `blender` uses its
viewport fixture; the tested Debian build requires `--protocol x11 --x11-manager`.
`gtkgl` checks actual colored pixels and an input-driven frame; `--software`
selects the llvmpipe control. `--gpu-prefix` selects an explicitly staged test
driver directory. Reports retain build identity, output, screenshots, process
status and cleanup. A trace/event acknowledgement is required where a client
publishes readiness; a screenshot or delay is not a readiness barrier.

Browser acceptance uses the [production browser fixtures](browser/README.md),
including stock Chromium JavaScript/PNG output without sandbox-disabling flags.
No completed workload establishes full isolation. `md-notification-test` is
a separate USER_NOTIF/remote-memory/FD-injection feasibility probe, including
guest signals and longjmp. It is not an alternative installed runtime.
`md-notification-lifecycle-test` adds native mask/altstack/TRAP/ERRNO/TSYNC,
thread/fork/exec, listener lifetime and cancelled-request checks without ptrace.
It deliberately asserts the shell's protected-process denials as boundary
checks, not successful access: pre-opened memory is not a capability for a fork
child or replacement image. ADDFD and explicit SCM_RIGHTS still work after
dumpable is disabled. The fixture never enables it again. Execute these native
controls separately from the guest runtime:

```sh
python native/guest-exec-lab/test_notifications.py BUILD
```

The runner checks the selected UID, stages fresh binaries, retains hashes,
kernel/build identity and exact results, and closes its console. It does not
install an APK or start Desktop. `test_process_context.c` separately checks
independent command-line/auxv snapshots and identical socket names routed by
different explicit contexts, without a process-global route fallback.

The separate [sandbox boundary fixtures](sandbox-research.md) compare native
seccomp precedence, cooperative signals and direct filesystem RPC with the
current guest adapter. They deliberately reproduce policy failures: a completed
run is not successful browser sandboxing. Build and execute them independently:

```sh
sh native/guest-exec-lab/build-sandbox-fixtures.sh BUILD
python native/guest-exec-lab/test_sandbox.py BUILD \
  --runtime IMMUTABLE_STAGED_HELPERS --store DISPOSABLE_GLIBC_STORE
```

`test_hybrid.py` separately exercises selective TRACE plus USER_NOTIF, protected
processes, register-only exec, guest-side bounded memory copying and fresh
same-site notification replay. It traces only its native fixture children and
does not alter the installed adapter. The same research note records positive
controls and unresolved security/lifecycle requirements.

```sh
sh native/guest-exec-lab/build-hybrid-fixture.sh BUILD
python native/guest-exec-lab/test_hybrid.py BUILD
```

The [browser fixtures](browser/README.md) build the production runtime, including
its supervisor, and distinguish startup from a rendered artifact. The separately
labelled renderer-only experiment uses an unsandboxed parent/zygote; it cannot
replace the stock-browser check. Filesystem broker authorization and full
isolation remain separate from application compatibility.
The [native isolation fixture](chromium-isolation.md#measured-boundary) tests
namespace, chroot, credential and Landlock availability without loading a guest
or enabling ptrace/seccomp mediation. Unsupported capabilities are observations,
not passing browser tests.

The [external domain fixture](chromium-isolation.md#external-domain-fixture)
checks read-only file admission for two independent roots, default-deny syscall
confinement, inherited-FD leakage, application seccomp precedence and fail-closed
memory/listener errors. It uses no ptrace and is not virtual chroot or browser
support:

```sh
sh native/guest-exec-lab/build-domain-fixture.sh BUILD
python native/guest-exec-lab/test_domain.py BUILD --repeat 10
```

The [helper/context control](chromium-isolation.md#helper-and-protected-memory-control)
combines shared root/cwd state with protected-memory copying and original-site
kernel replay. It compiles the matching Chromium helper source without edits;
the optional full-main mode executes the stock entry point and a native fixture
client, not the browser. Source hashes and license are retained under BUILD.
The explicit namespace fallback, fixed-image exec scope and remaining set-ID/
guest-ELF gates are documented with the results:

```sh
python native/guest-exec-lab/build-suid-context.py BUILD
python native/guest-exec-lab/test_domain.py BUILD --fixture suid-context --repeat 10
python native/guest-exec-lab/test_domain.py BUILD --fixture suid-context --suid-main --repeat 10
```

`md-exec-policy-test INTERPRETER` compares executable memfd scripts under the
native shell and guest. X_OK succeeding does not override a kernel exec denial.

For a prepared GUI store:

```sh
python native/guest-exec-lab/test_userspace.py BUILD \
  --store HOST_STORE --runtime STAGED_HELPERS --recipes BUILD/recipe-classes \
  --keyboard-directory HOST_XKB --protocol wayland --installed
```

Run again with `--protocol x11`. `--installed` selects the APK's lazy
`shroot` command; omitting it selects immutable staged test binaries.
`STAGED_HELPERS` also supplies the exact-process exit watcher. Checks require
real pixels, keyboard editing, saved-file readback and process exit, not only a
mapped native window. Host/user HOME and Desktop ownership must remain unchanged.

The whole-desktop fixture uses the same connection and execution contracts:

```sh
node native/guest-exec-lab/prepare.mjs build/guest-desktop --desktop --suite trixie
sh native/guest-exec-lab/build.sh build/guest-desktop
python native/guest-exec-lab/test_desktop.py BUILD \
  --store HOST_STORE --runtime STAGED_HELPERS --keyboard-directory HOST_XKB --installed
```

Import and prepare the generated rootfs explicitly before running. Xfce readiness
has separate X11 WM/panel/desktop and D-Bus Idle acknowledgements.
`test_x11_desktop.c` checks WM activation/resize; `test_xfce_session.c` subscribes
before querying state. No sleep substitutes for readiness. Xfce uses an isolated
configuration, software GL and a retained root viewer; logout must return zero.
The fixture does not boot systemd, logind or a complete GNOME session.

## Linux GPU Fixture

`build-mesa.py SOURCE SYSROOT OUTPUT` builds an unmodified Linux Mesa Turnip ICD
with KGSL and DRM WSI, not an Android driver. The sysroot needs matching C/C++,
libdrm, Vulkan, Wayland, X11/XCB, xshmfence, expat, zstd, zlib and libelf development
packages. Supply them with repeated `prepare.mjs --package NAME`; signatures and
hashes are checked as for the base profile. Host Meson, Ninja, Python generators
and a `wayland-scanner` matching the target libwayland are build tools only.
Use a fresh output directory when changing Mesa/configuration.

Zink additionally needs `libwayland-egl-backend-dev`, `libxcb-glx0-dev` and
`libxxf86vm-dev` in the authenticated SDK. Build it with `--driver zink`.
`--wayland-zink` explicitly applies the repository's Mesa 26.2.3 non-DRM
Wayland and KGSL timestamp patch exported by `scripts/install_linux.sh --print-mesa-patch` to a
private source copy and records its hash; the original source
tree remains unchanged. Keep patched and unmodified prefixes separate, and run
the unmodified control. A patched fixture result is not upstream compatibility.

Install `libvulkan_freedreno.so` at `/opt/md-gpu/lib/` and
`fixtures/turnip.json` at `/opt/md-gpu/turnip.json` in the owned test store;
its distribution supplies `vulkan-tools`. Do not replace Android libraries.
`test_gpu.py BUILD --store HOST_STORE --runtime STAGED_HELPERS
--keyboard-directory HOST_XKB --protocol wayland --installed` checks the hardware
ICD, changing Android pixels, 600 frames and zero exit. X11 is a separate
`--protocol x11` run with Xfce's window manager: the unmodified XCB cube does not
publish an ICCCM name/class, and the manager supplies its `WM_STATE`.
A software compositor or successful `vulkaninfo` alone
does not establish guest GPU rendering. `--trace` accepts the optional static
`md-trace-fault` observer. The production supervisor already owns ptrace for its
guest tree; a second observer cannot attach concurrently.

`test_gpu_timestamps.c` checks calibrated CPU/device clocks against actual queue
timestamp queries. Build it inside a prepared guest with `cc -O2 -Wall -Wextra
-Werror test_gpu_timestamps.c -lvulkan -o test_gpu_timestamps`. With the private
Turnip ICD selected, run without arguments for EXT and with `khr` for KHR.
Both require 16 successful GPU submissions and calibration brackets. Run the
unmodified driver as a negative control, not as an expected success.

`test_glx_loader.c`, built with `cc -O2 -Wall -Wextra -Werror test_glx_loader.c
-lGL -lX11 -o test_glx_loader`, checks advertised swap-control callbacks, GPU
readback and exact X11 pixels after a swap. Run through the graphical socket
route with the installer's private Mesa selected and `GALLIUM_DRIVER` unset:
`LIBGL_KOPPER_DISABLE=false ./test_glx_loader 1` exercises Zink/Kopper;
`LIBGL_KOPPER_DISABLE=true ./test_glx_loader 0` exercises its software alternative.
Also run with explicit software rendering. A bounded pixel probe permits
asynchronous Vulkan presentation; expiry fails, and each invocation needs an
outer process timeout for driver hangs. With unmodified Mesa, explicitly selected
Zink plus disabled Kopper can advertise a missing callback and crash the query.
Forcing `GALLIUM_DRIVER=zink` into the software loader is not a working fallback:
GPU readback can succeed while the X11 window remains black.

Build `fixtures/kgsl_no_calibration.c` with `cc -shared -fPIC -Wall -Wextra
-Werror kgsl_no_calibration.c -ldl -o kgsl_no_calibration.so`. Its test-only
`LD_PRELOAD` denies the calibrated timestamp ioctl with `ENOTTY`; run the patched
driver's timestamp fixture with `disabled`. Both extensions must be absent and
ordinary GPU timestamp queries must still succeed. This simulates an unavailable
ioctl, not complete coverage of an older kernel.

`test_egl_dmabuf.c`, linked with `-lEGL -lGLESv2 -lwayland-client`, connects to a
retained Wayland session through the production guest socket route. It requires
the matching EGL/GLES, Wayland, libdrm and Linux development headers. It checks
no-config/surfaceless EGL, linear ARGB8888 DMA-BUF import, exact input pixels and
64 alternating GPU frames written back to the same allocation. Each frame uses
an EGL native fence plus DMA-BUF sync-file export/import; exact CPU pixels are
checked after a bounded fence wait, without `glFinish`. The DMA heap is opened read-only; the
allocated buffer FD is read/write. Run with an outer process timeout to bound a
driver hang. This fixture verifies backend building blocks, not a nested KWin
desktop or frame-presentation timing.

`fixtures/dma_heap_unavailable.c` is a test-only `LD_PRELOAD` control for the
nested KWin allocator. Build it with `cc -shared -fPIC -Wall -Wextra -Werror
dma_heap_unavailable.c -ldl -o dma_heap_unavailable.so`. It rejects opening
`/dev/dma_heap/system` without blocking ordinary file access. Forced OpenGL must
fail explicitly; a separately selected QPainter session must still render.
Do not install this control in a guest login profile.

For the nested Plasma check, build the exact `--print-kwin-patch` from the
installer against its pinned archive in a private prefix. Use the installer's
`magicdesk-desktop-session plasma-wayland` launcher under an ordinary guest account and the
production graphical socket route. On an owned virtual display, verify actual
desktop pixels, Dolphin, launcher input, Overview and resize. KWin's D-Bus
`supportInformation` must report OpenGL and the intended GPU; the session bus
must be accessed as the same guest user. An inner EGL client must advertise the
same hardware renderer, submit v3 DMA-BUFs (`WAYLAND_DEBUG=client`) and produce
different rendered frames. Scope traces and timeouts to test processes; a
timeout is not a successful startup or shutdown.

`test_userspace.py --environment NAME=VALUE` records explicit guest-client
driver controls; `--software` selects llvmpipe. For an isolated Turnip prefix,
use `--environment VK_DRIVER_FILES=/opt/md-gpu/turnip.json`. Installing that
manifest in the test store's `/usr/share/vulkan/icd.d` exercises ordinary loader
discovery without a driver override. These controls do not change Android or
APK drivers.

`test_installer.py --distro ID --name TEST_NAME --gui MODE` exercises the public
installer through MagicDesk's shell executor. It checks package setup, locale,
timezone, an ordinary guest account and settings persistence across resume.
GUI checks verify shared launcher syntax, PipeWire tools and SDL/libudev libraries.
The named test environment is retained. `--resume` continues that fixture.
`--library PATH` isolates its stores and cached images from other test environments.
The test uses explicit guest DNS, not Android's encrypted resolver.

`test_installer_audio.py --names TEST_NAME ... [--library PATH]` starts the
installed audio wrapper, checks its private default sink and volume/mute changes
during silent playback, then releases its processes. It does not change Android
volume. Stream activation and property changes are observed through Pulse events.

`test_installer_graphics.py --names TEST_NAME ...` launches the installer's
catalog entries on an owned virtual display without Desktop. It records actual
native windows, Android hosts, screenshots and launch failures, then releases
its sessions and display. `--entry TEXT` filters desktop-file names. An optional
`--lease ID` retains an existing phone awake lease; otherwise the test owns a
virtual-display lease. Package installation alone is not a passed graphics test.

To check the Debian installer's actual login profile, use
`test_distribution_app.py BUILD --store HOST_STORE --runtime STAGED_HELPERS
--keyboard-directory guest:HOST_STORE --user root --home /root
--protocol wayland --application gtkgl --installed-profile turnip`.
Repeat with X11, Blender on X11, and `--installed-profile software` after switching the
installer profile. This mode injects no driver overrides and asserts the actual
renderer. GTK checks four color regions, an input-driven frame and zero process
exit. The test holds its virtual display awake; release any separately held MCP
awake lease before the run. `--user` selects a guest account, not Android root.

The Debian Mesa 25.0.7 fixture can block in GTK's initial GLX probe when there
is no discoverable Vulkan ICD. Its [Zink initialization](https://sources.debian.org/src/mesa/25.0.7-2%2Bdeb13u1/src/gallium/drivers/zink/zink_screen.c/)
jumps to `zink_destroy_screen` after a failed `zink_create_instance` while
holding `instance_lock`; destruction locks it again. The native stack waits in
that mutex, and `VK_LOADER_DEBUG=error,driver` reports no drivers. Supplying the
prepared Turnip manifest passes the same workflow. Keep this distribution
failure distinct from the guest syscall mechanism or Android frame transport.

Exact successful device coverage and unsupported ABI surfaces belong in
[Guest runtime](../../docs/shroot.md#coverage-and-limits), not a general
claim of distribution or driver compatibility.

## OCI And Filesystem View Checks

Transient-store checks retain a journal across SIGKILL at object publication,
namespace staging and commit. Reconnect and transferred custody preserve the
temporary durability policy and exact final cleanup. Persistent-store checks
assert synchronous EXTRA independently; retained-directory journal access also
survives renaming the store while two connections remain open.

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
paired syscall stops across exec; strace checks decoded arguments and fork
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
rename confinement. The ancillary cases cover SCM_RIGHTS peek, truncation,
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

`--case event-fairness` runs sixteen continuous identity-syscall producers beside
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
entries. The production importer owns omission/reporting for native `/dev` and
rejection of unsupported objects elsewhere. Verify source signatures before
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
and hardlinks without running an image. `test_oci.py` checks native-device omission,
lower-layer replacement, guest SHM, strict path/metadata handling and concurrent
inspection while another participant writes the same store.

## Guest Credential Checks

CMake's `MAGICDESK_GUEST_FIXTURES` builds `test_credentials` for the identity,
account resolution, registry and inode contracts, plus `credentials_guest` for
intercepted calls. The device runner accepts a prepared device-side OCI layout:

```sh
python native/guest-exec-lab/test_credentials_runtime.py BUILD DEVICE_LAYOUT --packages debian
python native/guest-exec-lab/test_credentials_runtime.py BUILD DEVICE_LAYOUT --packages alpine
```

The runner requires actual UID 2000 and creates its own preserved-ownership image
and instance. It checks independent root/non-root launches, chmod/chown/access,
hardlinks, group copying and EFAULT, nondumpable processes, per-thread raw IDs,
libc set-ID coordination, fork/exec, auxv and irreversible credential drops.
Access checks include real/effective IDs across the whole path, empty-path
descriptor/current-directory access, fchdir and inotify registration permissions.
`--fixture ELF` additionally runs a glibc/musl build of `test_credentials_guest.c`
against the matching image. Bionic's raw set-ID wrappers are intentionally
thread-local; glibc/musl coordinate the same calls between threads.
`--packages` exercises ordinary package install/reinstall/remove scripts without
force-not-root flags. Kernel privilege remains separate from virtual guest root.
Reports retain every command and exact image/build.

`test_ipc_credentials_runtime.py BUILD DEVICE_STORE` stages the native helpers
and exercises connection/group snapshots, queued SCM_CREDENTIALS, credential
drops, forgery rejection, MSG_PEEK, recvmmsg, truncation, FD passing and an external
native endpoint. Peer queries cover full ordinary/protected FD tables, empty
and maximum 65536-group snapshots, short buffers and output-copy faults.
The native RPC fixture separately checks large segmented replies, rejected
delivery and malformed/missing continuation packets without leaking FDs.
The selected prepared store supplies stock D-Bus and a root NSS
entry. Independent root clients share its bus; a different guest user is rejected.
`--installed` uses the APK's CLI/bundle instead of staging execution helpers;
only the test programs are uploaded. `--gdbus` adds a stock GIO client.
`--custody` adds strict native/guest comparisons for terminal adapter death with
a surviving CLONE_FILES peer, both ordinary and nondumpable. Guest send/receive
cases currently expose retained identity or unpublished message descriptors;
native controls release them. This opt-in reproducer remains a failing ownership
check, not a passing baseline or evidence of complete ancillary custody.
For Debian's activation/FD workflow:

```sh
sh native/guest-exec-lab/build-ipc-dbus.sh PREPARED_SYSROOT BUILD/ipc-dbus
python native/guest-exec-lab/test_ipc_credentials_runtime.py BUILD DEVICE_STORE --gdbus --activation BUILD/ipc-dbus
```

The activation fixture installs/removes only its own service file in the disposable
store. It checks a stock daemon's GetConnectionUnixUser, service activation and
usable descriptor delivery in both directions, under guest UID 0 and actual
UID 2000. No Android Desktop, real elevation or authentication override is used.

`test_guest_accounts_runtime.py BUILD DEVICE_STORE [--installed]` uses a disposable
Debian store with the stock passwd and D-Bus packages. It creates, modifies and
removes fixture-owned users/groups, verifies named-launch NSS/group resolution
and home ownership, and checks that a denied non-root groupadd leaves group files
unchanged. Pending package configuration must finish with both D-Bus packages
installed, a messagebus account and a clean dpkg audit. Package service-start
policy is not replaced. The runner's native/guest controls compare Unix, IP and
other netlink results while audit is explicitly unavailable in the guest.
CMake builds `guest_interfaces`; it checks raw calls, protected tasks and
application ERRNO/TRAP/KILL precedence under root, nobody and shell guest IDs.

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

The suite covers directory/name events, rename cookies, file-data events,
read/readv/FIONREAD boundaries, concurrent readers, dup/fcntl, queued SCM_RIGHTS
through recvmsg/recvmmsg, descriptor reuse, EINTR/SA_RESTART and 64 execs with
constant filter count. The complete glibc/musl suite runs again with dumpability
disabled. `receive-denied` rejects watch-filter installation and checks that the
published FD prefix stays live while unpublished FDs are released, using pipe
EOF and the receiver's descriptor count. Churn checks 7,680 distinct duplicate targets without unbounded filter
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
session-config watches and completes a bus request. Build-only prepared inputs:

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

## Developer Workflows

`prepare_vscode.py` stages official ARM64 VS Code and the Microsoft C/C++ VSIX
in an explicitly selected disposable Ubuntu store. `test_vscode_runtime.py`
opens the sandbox-enabled editor on an owned virtual display and drives stock
GDB through the extension's Debug Adapter Protocol. Its default transport is
the integrated terminal with named FIFOs; `--debug-transport pipe` separately
checks stdio transport. It verifies a breakpoint, stack/locals, step, value
change, inferior exit, editor exit and graphics/display cleanup. It does not
claim a complete Linux security sandbox.

`test_developer_workflows.py BUILD --store STORE` checks authenticated loopback
Git/SSH clone and push, CMake/Ninja/CTest with install and incremental rebuild,
npm install/ci plus worker/child/watch/HTTP behavior, and pip venv/PEP517 C-extension
wheel build/install/use/removal. Ubuntu needs Git, OpenSSH client/server, CMake,
Ninja, GCC, Node/npm and Python venv/pip/development packages and the fixture's
`mdcode` user. `--case` selects an individual workflow. Each uses a unique private
directory; SSH retains key authentication and strict ownership checks.

`test_fifo_runtime.py BUILD --store STORE` checks independent launches sharing
FIFO streams and repeated ownership lifetimes. The service fixture covers
single-launch FIFO semantics; the [FIFO contract](../shroot/fifos.md)
lists readiness and watch limitations rather than treating these as certified.

`prepare_blender_gpu.py` stages explicitly supplied, hash-recorded Zink/Turnip
assets in a disposable Blender store. `test_distribution_app.py` with
`--application blender --protocol x11 --x11-manager --gpu-prefix /opt/md-gpu`
checks renderer identity, viewport drawing, captured pixels and normal closure.
The result concerns viewport acceleration, not Cycles GPU support.

## Runtime Benchmarks

`benchmark_watches.py BUILD --store STORE --baseline BUNDLE --current BUNDLE`
uses the `runtime-workloads` glibc fixture in `BUILD`. It compares metadata
traversal and process spawning with no watches, a same-process observer, and a
concurrent child observer. Warmup is excluded, sample order alternates, and
separate counter-enabled launches do not contribute timing samples. Monotonic
workload timing excludes watch registration/draining and launch preparation;
the report retains thermal/power snapshots and verifies events without overflow.
It measures neither compilation nor PRoot.

`benchmark_compile.py` compares the same Debian GCC toolchain and SQLite
amalgamation under native chroot, Termux PRoot and the installed guest runtime.
It builds the standalone CLI and PIC shared library with `-O3 -flto`, serial
`make -B -j1`, no compiler cache and a fixed compiler random seed. GNU time
runs inside each environment around make, excluding rootfs preparation,
transport, environment startup and subsequent SQL validation. Both generated
program/library paths must execute successfully; output hashes are recorded.

`--workload metadata` checks 4,096 stat/open/fstat/read operations over a prepared
tree, including actual inode identity, link count and bytes. `--workload spawn`
checks 128 fork/exec/wait cycles of the same `/bin/true`. Fixture compilation and
tree preparation remain outside timing. The native tree is prepared as the Termux
owner so sequential chroot and PRoot runs can reuse it without ownership changes.
Use `--modes guest-baseline guest --baseline-runtime REFERENCE_BUNDLE` for an
interleaved comparison of two immutable guest bundles under the same shell UID.
The reference bundle must support the same store and command contract.

Prepare a new build-only sysroot with the authenticated package helper:

```sh
node native/guest-exec-lab/prepare.mjs build/guest-compile \
    --suite trixie --package gcc --package make --package time --package coreutils
python native/guest-exec-lab/benchmark_compile.py build/guest-compile \
    --sqlite PATH_TO_SQLITE_AMALGAMATION --runtime INSTALLED_GUEST_BUNDLE
```

The default is one excluded warmup and three measured builds per mode, with
rotating order. Root is explicitly used only for chroot; its bind mounts live
in a private mount namespace and disappear on exit. PRoot uses the current
Termux UID with seccomp acceleration enabled and no fake-root extension. Guest
requires the existing MCP command service to be UID 2000 and imports its own
store from identical source bytes. Neither the APK nor its access setting is
changed. The phone must remain awake throughout the comparison.

The JSON report retains tool/package/source/runtime identities, process CPU
affinity, wall/CPU times, thermal and CPU-frequency samples, power source,
all outputs and artifact hashes. Keep charging state unchanged; a detected
change leaves the report incomplete rather than mixing power conditions.
Caches are warmed, not globally dropped; governors and CPU affinity are not
changed. Wall time is the comparable end-to-end build metric. GNU time's child
CPU accounting does not include every external supervisor/filesystem service.
The compile workload does not establish metadata-intensive performance; use
the separate workloads rather than generalizing one result. None establishes
GUI latency or cross-device speed claims. Very short native runs can reach
GNU time's output resolution; do not infer precise ratios from those values.

Use `--guest-statistics --modes guest` for a separately labelled diagnostic run
with aggregate syscall/ptrace/stop counters, filesystem/SQLite elapsed costs,
broker handling/delegation counts and supervisor/namespace-worker CPU usage.
The worker's thread CPU is included in the supervisor process total; do not add
them together. Clock sampling is enabled only in that diagnostic mode.
Keep it separate from ordinary timing series. Frequency caps
and scheduling groups can differ between these executor
identities even without changing the power source; retain the individual samples
and ranges rather than attributing every wall-time difference to interception.

Configure the native CMake build with `-DMAGICDESK_GUEST_FIXTURES=ON` to build
`libmagicdesk_guest_benchmark_namespace.so`. Run it under the same shell identity
with the prepared benchmark store as its sole argument. It executes the metadata
workload directly through the namespace engine, retaining inode/content checks
but excluding syscall interception and RPC. Its first sample warms the store;
the next three isolate engine cost. This diagnostic is not another guest runtime
or a replacement for end-to-end timings, and is not packaged in the APK.
