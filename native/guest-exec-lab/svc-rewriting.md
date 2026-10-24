# Lazy SVC Entry

This guide describes the current machine-entry contract and its regression
fixtures. Superseded predecessor/call-edge, hardware-breakpoint, mirror-loader
and source-built-libc experiments are removed; Git retains their history.

- [Product Boundary](#product-boundary)
- [Regression Commands](#regression-commands)
- [Admission Limits](#admission-limits)

## Product Boundary

The ordinary bootstrap/supervisor enables lazy entry by default for inode-store
launches. `--env SHROOT_MACHINE_ENTRY=0` selects Base. It does not launch a
discovery debugger. Bootstrap allocates private frames and near-code pools;
`interception_memory` owns the registry across CLONE_VM, fork and exec.
First observed execution can publish a single SVC replacement without a peer
stop, predecessor witness or hot-site threshold. Observed syscall numbers at
one instruction share a chain of immutable guarded entries.

`svc_machine.c` owns logical signal contexts, deferred siginfo, checkpoint return
and cold replay at the original instruction. It uses the existing interception
filter, not a filter per pool or exec. Broker notifications from resident gates
return to this owner rather than being sampled as guest code. Machine entry
uses the common per-thread channel and channel reentry guard; explicit API
fixtures exercise the same transport independently of patch discovery.
Memory changes retire overlapping entry points; resident continuations remain
until address-space teardown. Debugger ownership disables machine admission.

Seccomp stops share one register snapshot between checkpoint recovery, executed
site discovery and ordinary dispatch. Discovery precedes compact Base handlers:
an inexpensive first `close` must not prevent later calls from using lazy entry.
The `--case fd-discovery` cooperative fixture uses ordinary SVC instructions,
not the explicit entry API, and checks close/dup/fcntl/lseek completion counters
as well as descriptor flags and EBADF. Base runs assert that these counters stay
zero. Calls which already go straight to the kernel need no discovery stop.

Broker discovery uses a bounded recent-address cache only to suppress repeated
cold attempts. A cache miss always delegates, evicting an older address if
needed; cache capacity is not an admission limit for new SVCs. An evicted,
unpatchable site can be sampled again. The supervisor registry separately owns
patch eligibility and resident code capacity. `--case site-discovery` checks
32 executed sites; the broker fixture also checks warm suppression, eviction,
exact-address resampling and fresh discovery after task-record reuse without
installing any patches. Eligibility refreshes retain the same owner's cache.

Recovery of an unexecuted entry restores its original SVC before delivering a
deferred signal. The retry observer republishes only after that syscall enters
the kernel. A handler's unrelated syscall leaves the site suspended until later
observed execution, and its stop still reaches the normal syscall owner. This
invalidates that address's cold broker sample for the sharing address space,
so subsequent notification calls can republish it instead of remaining on Base.
This prevents signal storms from repeatedly cancelling the same native plan or
consuming an adapter's cancellation acknowledgement. It requires neither peer
stops nor a timer/backoff on ordinary calls.

Standard asynchronous signals share the Base adapter's queue and exact-siginfo
delivery protocol. They never acquire replay carriers, which can coalesce with
real arrivals and leave a blocked SIGTRAP absent from the kernel pending set.
Realtime instances retain ordered replay: an earlier held instance precedes a
newer kernel arrival of the same signal. Both policies wait for reconstruction
of the guest context, including the cancelled checkpoint's syscall-exit stop.
Retry observation runs only in guest execution, never inside adapter allocation
or another owner's native protocol.

`test_cooperative_runtime.py --machine-entry` runs the existing complete entry
contract. `test_svc_patch.py` and `test_svc_libc.py`
run the stock assembly/Go/libc fixtures directly, without the laboratory tracer.
`test_cooperative_libc.py` compares stock-libc workloads under native, optional
PRoot, Base and lazy entry. Explicit API callers remain correctness fixtures,
not measurements of rebuilt libc. Source-built libc is not a supported launch mode.

The normal writer uses ptrace against private RX mappings. Bootstrap
registers the initial program and interpreter mappings with `interception_memory`
while it still owns their exact source descriptors. Device/inode and offsets,
not a later pathname lookup, identify those ranges. The existing private-memory
repair then handles a later NONE/R to RX transition if Android rejects the
ptrace-created COW page. Failure to retain the initial provenance leaves Base
entry selected; no writable-text permission is silently substituted.

Before an application filter or `PR_SET_DUMPABLE(0)` commits, machine admission
is revoked. The existing cold task barrier, scoped to the affected address
space, recovers resident entries or requests their return checkpoint. Peers
then run to complete admitted calls under the old filter.
The original event is replayed only after those machine entries
and their syscall-exit continuations have drained. This barrier is for these
kernel transitions, not patch publication or ordinary accelerated calls. The
dumpability transition restores source instructions before the kernel removes
remote-memory access; it does not falsify the application's protected state.
Cooperative channel revocation remains in the common owner: one caller for a local
filter, its thread group for TSYNC. A blocked callback which does not drain in
five seconds rejects the transition with EBUSY; it is not applied and
entry remains revoked. Failure to establish the initial task barrier retains
the supervisor's fail-closed cancellation behavior.

Application-filter preflight requires the complete common descriptor-selector
set. The first published PROC selector is not evidence that the remaining
epoll/poll selectors are ready: concurrent local filter installs could otherwise
make their later TSYNC preparation fail. The adapter and supervisor share the
same selector mask. This preparation remains outside ordinary syscall paths.

The integrated mapping fixture compares native, Base and lazy entry across
repeated NONE/R to RX changes of the initial ELF text and a fork child.
Its filter race runs four live UID/open/close callers through 24 TSYNC installs.
The new filter kills gettid (an entry helper), denies UID/open calls and must
take effect for every peer. The fixture requires observed accelerated
completions, revocation and actual resident-entry drains, not merely successful
installation. Signal-boundary and full cooperative tests remain separate checks.
The protected-state race repeats the same live callers across 24 dumpability
transitions and verifies the state and syscall results in the parent and child.
Arbitrary externally mutable backing is not certified by this coverage.
Source-built libc and its loader registry are removed; current fixtures compare
stock programs under native execution, Base and default lazy entry.

An interrupted kernel notification can restart at a newly published SVC gate.
Only a registered gate's exact post-SVC PC is normalized to the original call;
syscall number, architecture and all arguments must still match. The retained
worker result owns completion, including any opened FD. If the restart first
reaches the shared channel, recovery declines that unexecuted request so the
kernel continuation can consume the retained result. Both worker scheduling
and wait preparation use the same serviceability predicate. This avoids a
duplicate filesystem effect, a recovery deadlock and a ready-but-unserviceable
busy loop. Ordinary calls do not scan the site registry for this recovery.

Protected-process discovery also exposed an independent Base proc bug:
`cmdline` was gated by ptrace credentials and remote-memory reads, although
Linux keeps it public after `dumpable=0`. The adapter now checks the actual proc
open under caller authority, and the supervisor uses its existing exact-mm
retained memory description for the live argument bytes when necessary.
Guest capabilities or differing IDs no longer turn public `cmdline` into
`auxv`; private image views retain their inspection checks. No new memory-FD
cache or dumpability override is introduced. The process-image fixture verifies
post-protection argument edits and denied `auxv` natively, with Base and lazy
entry, plus a differing guest-identity control.

## Regression Commands

Build with `MAGICDESK_GUEST_FIXTURES=ON`. Tests use the normal native artifacts,
not an alternative proof build. They run through the configured MagicDesk MCP
connection under the selected executor and retain exact receipts in `build/`.

```sh
cmake --build BUILD -j4
python native/guest-exec-lab/audit_svc_payload.py BUILD
python native/guest-exec-lab/test_cooperative_runtime.py BUILD --base
python native/guest-exec-lab/test_cooperative_runtime.py BUILD --machine-entry
python native/guest-exec-lab/test_svc_direct_signal.py BUILD
python native/guest-exec-lab/test_svc_patch.py BUILD STOCK_GO --rounds 5
python native/guest-exec-lab/test_svc_libc.py BUILD STOCK_LIBC_PROBE --checks-only --signal-storm
```

`build_svc_go.py` builds stock Go/cgo fixtures; run the same SVC suite with
each artifact. `build_svc_glibc.py` compiles a small test program against a stock
sysroot, not libc itself. The libc runner also accepts a stock musl probe.
Use its `--dynamic-loader`, `--dynamic-libc`, `--interpreter` and
`--dynamic-extra` arguments for dynamic libc checks.

| Fixture | Required evidence |
| --- | --- |
| Cooperative runtime, Base and machine entry | Existing filesystem, FD, namespace, channel, memory, signal and debugger contracts |
| SVC direct signals | Every executed gate instruction, logical register/stack state, negative controls and eight queued-RT scenarios |
| SVC patch | Branch limits, original call identity, adjacent fault PC, raw assembly, mapping replacement, protected proc views, TSYNC and dumpability races, stock Go with/without filters |
| Stock libc | ABI/contracts, 256 retired thread owners, optional asynchronous/blocked signal storms, dynamic loader variants |
| Payload audit | Actual bootstrap driver has no hidden relocations; object bytes equal linked bytes |

Do not weaken assertions when removing an obsolete experiment. In particular,
the live filter/protection races require 24 transitions and nonzero resident
drains; a successful filter install alone is not sufficient.

### Performance Controls

The libc runner compares native, Base and lazy entry with identical warm-up,
CPU affinity and rotated launch order. `--workload opens` measures 4,096
open/close pairs; `--workload metadata` measures 32,768 metadata calls.
Completion counters are verified in a separate untimed run. Timed runs all
disable runtime statistics, whose clocks would otherwise bias the comparison.
`--threaded` first enters libc's threaded mode. `--sandbox` measures the
current original-SVC fallback after a filter, not acceleration inside it.

`test_cooperative_libc.py` also includes optional PRoot and reference-build
controls. Explicit API callers belong to the separate correctness suite, not
the stock-libc timing comparison. Record kernel, artifact hashes, device load
and thermal conditions with measurements; historical numbers are not
performance guarantees for a new build.

### Desktop and Container Acceptance

Beyond focused tests, the integration matrix uses stock distribution libc and
ordinary installed recipes on virtual displays:

- SteamOS Plasma, Dolphin, terminal, Steam login window and normal logout.
- SteamOS Flatpak Chromium/Firefox and VS Code.
- Ubuntu systemd, Snap Chromium/Firefox and VS Code.
- Alpine musl/OpenRC boot, service lifecycle and cleanup.
- Docker and Podman bridge networking, TCP/UDP publications, DNS, peer traffic,
  local outbound IO, binds, exec, conflict rejection and released ports.
- Traced resolver/socket detach and mixed epoll workflows, with Base controls.

Browser checks require input, download, portal chooser, WebGL output and normal
close; VS Code checks editor/save, watchers, terminal, debugger and reload.
The corresponding workflow owners are in [desktop workflows](desktop-workflows.md)
and the [fixture guide](README.md). A passing native unit suite does not
substitute for these application workflows.

The pre-removal matrix recorded Chromium ANGLE/Zink/Turnip output; Firefox's
privacy-masked renderer string did not establish GPU identity. Steam reached
its login window, not authenticated gameplay. Silent PCM counters verified
audio transport, not audible quality. Snap used snapd's degraded mode without
AppArmor. These limitations still apply; this document is not a claim that a
new source change has rerun that entire matrix.

## Admission Limits

Arbitrary self-modifying code, externally writable aliases, simultaneous
debugger ownership, 64 KiB pages and SVE/SME/MTE/PAC/BTI are not certified by
these tests. The guard layout supports 4/16 KiB pages; device coverage is 4 KiB.
There is no claim of general instruction rewriting or unwind metadata.
Unsupported sites retain Base. Removing old experiments does not broaden
production admission or relax sandbox checks.
