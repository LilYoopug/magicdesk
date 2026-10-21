# Lazy SVC Rewriting Experiments

[Fixture guide](README.md) | [Cooperative entry](cooperative-entry.md) |
[Runtime contract](../shroot/cooperative-entry.md)

The normal native runtime now includes an opt-in single-SVC entry owner; see
[Product Boundary](#product-boundary) for its admission, commands and coverage.
Source-built libc remains selectable for comparisons. Neither mechanism is
selected by default during this transition.

The earlier laboratory approaches below remain controls, not prerequisites of
the single-SVC runtime. Forwarding coverage, real engine completions, correctness
and elapsed time are separate measurements.

## Earlier Predecessor And Call-Edge Admission

The earlier `svc_patch.c` approach classifies instructions by opcode masks and
register dependencies, not library names or symbols. Recognition alone never
authorizes a predecessor or call-edge patch:

1. Observe an actual syscall, then witness execution of the candidate predecessor
   or BL edge with a temporary hardware execution breakpoint.
2. Stop participants through the existing `task_quiesce` owner. Validate the exact
   bytes and private executable, nonwritable mappings again.
3. Publish immutable code before replacing one aligned instruction. Restore the
   borrowed debug registers, detach the discovery debugger, and run through the
   actual cooperative API v6. There is no second host ptracer.

Two general entry forms are implemented:

- A nonfaulting overwrite of x1..x29 can supply temporary scratch storage.
  Instructions reading their old destination or x0, faulting loads, MOVK and
  destinations x0/x30/SP are not admitted by this rule.
- A witnessed BL provides a known return address. Its bounded callee prefix can
  contain supported MOV/load operations before SVC, without stack writes,
  branches or PC-relative addressing. This handles Go's load-only wrappers
  without a Go-specific ABI assumption.

A word that happens to encode an instruction is not sufficient evidence. The
raw fixture includes an adjacent MOV-encoded literal and an incoming edge that
bypasses the predecessor. The literal stays unchanged; the bypass stays native.
Writable/shared executable mappings, unsupported prefixes and unreachable
trampolines remain unmodified. No success is fabricated for those cases.

The payload uses a private frame pool, not memory below the application's SP or
pthread TLS. SP hashing only selects a slot; it is not thread identity. A busy
slot falls back before effects. The C path compiles with
`-mgeneral-regs-only`; all GPRs, NZCV, SIMD and FP state have runtime preservation
checks. All 29 overwrite-register variants execute real engine requests in tests.
The zero-TLS, guard-page test retains the failing guest-stack gate as a negative
control and verifies the private-frame gates.

The runtime's `thread_identity` callback selects opaque per-thread cooperative
clients. Guest-visible gettid is not an identity key: separate PID namespaces can
both return 1. Exit stops retire the exact native client before TID reuse. A
repeated PID-1 fixture and a 256-thread sequential churn test exercise
more owners than the bounded 128-client table can retain simultaneously.
`audit_svc_payload.py` rejects relocations in the copied driver and verifies that
the linker did not change its bytes. This complements, rather than replaces,
instruction/state tests.

## Earlier Signal Owner And Shared Fixes

The optional supervisor owner `svc_signal.c` defers asynchronous signals until
the original architectural boundary. It saves/restores the real signal mask,
siginfo and borrowed hardware breakpoint state. It does not deliver a Go signal
handler with a temporary x28 or private C stack. Relocated prefix faults restore
the original PC and release their frame; tests check old destination registers,
LR, fault address, handler edits and successful retry.

Stress work also exposed two independent Base defects: a second asynchronous
signal could interrupt metadata restart in an internal context, and an
application-blocked SIGTRAP could escape a temporary shield. The shared
`signal_delivery.c` owner retains standard asynchronous signals, then returns
their siginfo to the kernel before guest instructions resume. A supervisor-owned
single-step on a bootstrap NOP supplies each delivery stop. Registers and the
original mask are restored before the application resumes. No synthetic SIGURG
or other application signal is sent, including under queue exhaustion. Tests cover handlers,
sigwait/signalfd, coalescing, preexisting SIGURG, blocked SIGTRAP and exhausted
RLIMIT_SIGPENDING, including simultaneous real SIGURG/TRAP and a separate native
exhaustion control. The original TRAP disposition is checked too. Real-time
signals remain queued by the kernel; libc stress requires every sent real-time
signal to arrive, without coalescing. The ordinary no-retained-signal path does
not enter this requeue protocol. Queue exhaustion can discard siginfo in the
native kernel as well; retained and kernel-pending signals use kernel coalescing,
not a stronger exactly-once ordering guarantee.

Nested owners save a logical mask through `save_signal_mask`, not the private
entry's effective blocking overlay. Setting that mask updates the lower owner
while retaining the overlay until its architectural exit. A completed inner
owner cannot deliver a retained signal while metadata restart still owns the
boundary. This fixes both premature SIGTRAP delivery and observing a signal
handler's rt_sigreturn in place of the restarted metadata call. The repeated
blocked-TRAP/real-time stress reproduced both failures before the fix.

The machine-entry prototype conservatively revokes cooperative admission for
the whole address space before an application filter commits. It executes
filtered operations at their original SVC, including filters that kill gettid.
The synthetic source/gate tests also cover mixed thread filters, original-PC
checks, ERRNO/TRAP and TSYNC. **Passing sandbox tests is not evidence of direct
acceleration after revocation.** Filtered measurements report zero cooperative
completions. The source mechanism's finer admission is not silently claimed by
the prototype.

Stock musl, static/dynamic glibc, pure Go and cgo have real completion checks.
Go runs with asynchronous preemption, GC, growing/migrating stacks and profiling
enabled. Libc checks include cancellation/FIFO blocking, EINTR/SA_RESTART,
signal longjmp, descriptor ownership, fork/exec and seccomp.

## Code Lifetime And Debuggers

`svc_lifecycle.c` is a cold, event-driven retirement transaction. Membership
comes from the supervisor's existing address-space identity, not a shared
receipt or an assumption that FORK means an independent mm.

Before an overlapping destructive VM operation or debugger attachment it:

1. Quiesces tasks using the existing barrier and restores the original word.
2. Arms architectural exits for invocations already in private code, including
   saved adapter continuations; no new invocation can enter the restored site.
3. Releases peers to their ordinary event owners and waits for those invocations
   to finish. Only then does it replay the caller's exact original stop.

This does not add a per-syscall generation lookup. The prototype deliberately uses
a global cold barrier; production admission should narrow that barrier using
the existing mm/helper ownership and account for external writers.

The executable lifecycle fixture covers mprotect, mremap, munmap/address reuse,
MAP_FIXED replacement, MADV_DONTNEED, private fork, CLONE_VM with SIGCHLD, vfork,
leader and nonleader exec, and guest debugger attach/inspect/detach. A deterministic
test holds an actual API invocation in its private frame and proves that mapping
completion waits for it, including a blocked Base SysV adapter and process death
during the wait. Writable/shared code has explicit negative controls.
Fork retirement restores the child's COW code without changing the parent's
patch; CLONE_VM retirement is visible to both.

`test_svc_signal` injects an exact stopped boundary in a generated, faulting
prefix while signal deferral or retirement drain is pending. It checks original
PC/LR, old destination registers, fault address, edited retry, frame release,
nested mask restoration and an unrelated hardware breakpoint. The fixture
uses a native SET/GET round trip for the initial debug-register image: the
kernel canonicalizes control words of previously unallocated disabled slots.

The debugger replay test caught repeated retirement of a running target. Replay
now carries an exact one-use completion marker, instead of treating a failed
PEEKTEXT on a running task as a new request. Quiescence also marks internal poll
wakeups as service work, preserving pending IPC/readiness/debugger operations.
The ordinary JIT repair fixture checks this without machine entry enabled.

The lab-only build also observes mprotect without PROT_EXEC and madvise. Normal
Shroot retains its existing filter. Code may not be published without these
retirement observations. Debug-register permission and sufficient free slots are
actual capabilities, not kernel-version assumptions.

## Reproduction

Configure the existing native fixture build with
`MAGICDESK_GUEST_FIXTURES=ON` and, for the earlier breakpoint-based signal/lifetime tests only,
`MAGICDESK_GUEST_SVC_SIGNAL_PROOF=ON` (default OFF).

```sh
cmake --build BUILD --target bootstrap supervisor run image service \
  test_svc_patch trace_svc_patch test_svc_gate test_svc_raw \
  test_svc_fault test_svc_mapping test_svc_lifecycle test_svc_signal test_signal_delivery -j4
python native/guest-exec-lab/audit_svc_payload.py BUILD
python native/guest-exec-lab/test_svc_lifecycle.py BUILD
python native/guest-exec-lab/test_svc_patch.py BUILD build/svc-go --checks-only --entry-only
python native/guest-exec-lab/test_svc_patch.py BUILD build/svc-go --edge-only --signal-proof --rounds 4
python native/guest-exec-lab/test_svc_patch.py BUILD build/svc-cgo --edge-only --signal-proof --rounds 4
python native/guest-exec-lab/test_svc_libc.py BUILD STOCK_MUSL_PROBE SOURCE_MUSL_PROBE \
  --syscall 56 --threaded --workload opens --rounds 8 --signal-storm
```

`test_svc_libc.py --signal-rounds N` repeats the signal acceptance scenarios.
`--sandbox` times original-SVC fallback after an argument-dependent application
filter is installed following warmup. It requires witnessed publication and
revocation, so an unpatched child under the discovery tracer cannot pass as a
machine-entry measurement. Pre-filter completion counters are not reported as
filtered acceleration.

Reconfigure with `MAGICDESK_GUEST_SVC_SIGNAL_PROOF=OFF`, rebuild bootstrap,
supervisor and cooperative_guest, then run `test_cooperative_runtime.py BUILD`
to verify the ordinary runtime separately. Machine-entry receipts from the
enabled build do not substitute for this check.

`build_svc_go.py` accepts the SHA-256-pinned official Go 1.27.2 Linux/arm64
archive; `--cgo-environment` selects a prepared GCC environment for the cgo
fixture. No Go runtime assembly or preemption option is changed.
`build_svc_glibc.py` builds small workload fixtures against existing stock and
source-hook sysroots; it does not rebuild glibc.

`trace_svc_patch` modes observe/forward/count measure discovery and forwarding,
never direct acceleration. Edge mode publishes one selected hot site and
detaches before the timed workload. `MD_SVC_NUMBER` selects the discovery syscall,
not the set of calls the generic entry can dispatch. Reports include actual
selected-syscall completions, not just the existence of a patch.

Runners use disposable stores, record binary hashes and command output, and
remove their exact private device directory on success. Failed runs retain that
directory for diagnosis. Local JSON receipts are not shipping prerequisites.

## Evidence

Device: nubia NX809J, Android 16, shell UID 2000, Linux 6.12.23, 4 KiB pages.

| Proof | Local receipt (oci-services suffix) |
| --- | --- |
| Original forwarding census, including raw literals and fault PC | 59a6a33d18744ebe9bbfb25abc2005ec |
| Pure Go, actual completion, four plain/TSYNC runs | 02177f05fd3046cf890d3c4b169ae372 |
| cgo, actual completion, four plain/TSYNC runs | da4ca7ba06e44d998c362e93ca73abe8 |
| Dynamic glibc, churn and both signal storms, including real-time | 7802657da2694bce983c920b3cb7aeea |
| All register gates, stack guard, fault and sandbox checks | 82e91a93604e44d39d60a841e7267b47 |
| 17 lifecycle cases, prefix fault during pending drain/signal, nested masks | 01300dad25514b07bf9d713d40be2d03 |
| Eight blocked-TRAP repeats, 8192 real-time deliveries in each | 7281352b07d24cf38620d25299f71477 |
| Full runtime/models, default-OFF build, JIT/IPC and FD publication | e447620558794585866b92f8ef8dbc4d |

The original Go census saw 67926 actual trampoline visits out of 69014 syscalls
(98.4%). That remains forwarding evidence only. Later detached Go/cgo runs
record thousands of real cooperative completions and balanced signal deferral.

Eight-round real-libc measurements (milliseconds, medians):

| Workload | Native ms | Base ms | Source libc ms | Stock libc + machine entry ms |
| --- | ---: | ---: | ---: | ---: |
| glibc, 32768 stat | 20.096 | 807.712 | 107.886 | 113.944 |
| glibc threaded, 4096 open/close | 9.427 | 330.663 | 52.848 | 40.563 |
| musl threaded, 4096 open/close | 9.298 | 387.017 | 48.872 | 36.916 |
| glibc threaded, 4096 open/close after application filter | 10.713 | 361.873 | 363.440 | 357.049 |

Stat receipt: 3a586a8ade674cd6829e2942946a0384 (final nested-mask owner).
Its median paired machine/source ratio is 1.025; the ratio of independent
medians is a different statistic. Open/close receipts, in table order:
cd3b8bc7f97c4e1d8c6854e8f67cb47d, 10a8ab05628a48bbbaaf3de811b008d7,
34fe4a635eff4878a8b507018e022c11. Their median paired machine/source ratios
are 0.738, 0.810 and 1.053, respectively. Every filtered machine run reports
revocation and the same 125 selected completions from pre-filter warmup; the
4096 timed operations use the kernel path, not cooperative acceleration.
Modes rotate and reverse on CPU mask 3. The timed region excludes cold discovery.
These support steady-state parity for these workloads, not a universal bound;
device activity and thermal conditions still require raw samples.

## SVC-Only Publication Without Peer Stops

`test_svc_live` is a separate experiment, not an activation of the earlier
global-barrier lifecycle owner. It changes exactly the four-byte `svc` to `b`
and leaves both neighboring instructions intact. No predecessor witness,
peer interrupt, signal rendezvous or patch-epoch acknowledgment is used.

The generated gate first checks all 64 bits of x8 with TBZ/TBNZ. These
instructions preserve the general registers and NZCV. A matching gate can
then borrow x8, use the existing private-frame template, and restore x8 from
its known literal. This does not assume a libc calling convention, writable
guest stack or TLS. The current gate is 792 bytes. A mismatched number, busy
frame or declined engine reaches a cold exit with the original state intact.
The original fixture restores SVC and resumes at its exact address. The later
`cold-*` experiments below replace that trap-based retirement with a copied
syscall plus explicit logical-address handling.
It retires the whole site on a miss; dynamic-number caching and rearming are
not implemented by this fixture.

Immutable gates are completed and cache-synchronized before publication.
The publisher alternates SVC and two different gates with four-byte pwrite
to `/proc/self/mem`, while peers keep executing the site. Gates remain mapped
until process exit. Architectural concurrent modification permits either
old or new eligible instruction to execute, not a globally acknowledged
instantaneous switch. See Arm's
[threaded self-modifying code explanation](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/caches-self-modifying-code-working-with-threads).
This is not permission to replace arbitrary MOV instructions concurrently.

The four-byte writer is a separate portability condition. Linux 5.15 arm64
[memcpy](https://raw.githubusercontent.com/torvalds/linux/v5.15/arch/arm64/lib/memcpy.S)
uses aligned word stores for this size, and
[copy_to_user_page](https://raw.githubusercontent.com/torvalds/linux/v5.15/arch/arm64/mm/flush.c)
performs executable-page cache maintenance. The device experiment confirms
this path on its kernel. Neither pwrite's userspace API nor a passing stress
test alone certifies atomic instruction publication on arbitrary firmware.
Do not turn this into an unconditional production assumption.

Reproduce with the normal, signal-proof-OFF fixture build:

```sh
cmake --build BUILD --target bootstrap supervisor run image service test_svc_live -j4
python native/guest-exec-lab/test_svc_live.py BUILD --rounds 3
python native/guest-exec-lab/test_svc_live.py BUILD --benchmarks --rounds 5 --cpu-mask 3
```

Unpinned correctness runs cover native execution and actual Shroot API
completion, complete GPR/NZCV/FP/SIMD comparisons, a guard-page SP with zero
TLS, nonzero upper x8 bits, forced frame collision, exact-IP seccomp fallback,
and concurrent publication. The seccomp fixture explicitly withdraws payload
admission before installing its filter; this proves the cold fallback, not
automatic production revocation or acceleration under arbitrary filters.
Its signal variant retains the application's TRAP handler while installing
64 filters under ordinary asynchronous SIGTRAP traffic.

Receipt `782b1187ff904d5ba58172a748e0f0e2` passed three repetitions of all
15 native/guest cases: 90 positive executions and 24 expected-negative
controls. Each steady publication run performs 30001 actual writes
with seven peers, zero cold misses and progress from every peer. This uses
eight engine channels including the main thread. A separate eight-peer case
exhausts that existing capacity and verifies safe retirement, without counting
Base fallback as sustained accelerated publication. Private-frame hash
collisions also remain a supported cold fallback, not an accelerated outcome.
The concurrent lifetime/mapping proofs deliberately select distinct SP hashes,
so a random frame collision does not retire the site being measured.
`check` and `collision` separately retain arbitrary/guard SP and forced-busy
coverage; this is not a claim that the production frame hash cannot collide.

### Text Backing and Protection

The `protection` counterfactual found a real problem with the forced writer.
Native `PROT_NONE -> RX` succeeds on the pristine private file mapping, but
returns EACCES after a forced write, including a write of the **same bytes**.
Restoring SVC or discarding the private page does not restore that permission;
creating a fresh mapping does. This is consistent with the file/anon_vma
execmod check in
[Linux 5.15 SELinux](https://github.com/torvalds/linux/blob/v5.15/security/selinux/hooks.c#L3664-L3700).
The device receipt proves the behavioral difference, not a captured AVC.
Shroot's existing memory-repair path hides this difference, which is why a
guest-only test would have been insufficient.

`svc_text.c` tests a different owner:

1. Prepare an immutable/pristine source range in a per-mapping memfd.
2. Retain a MAP_SHARED RW alias; seal future writes, growth and shrinking.
3. Give the application a MAP_PRIVATE RX view of the same backing.
4. Publish only aligned SVC/B words through a release atomic 32-bit store to
   the RW alias, with writer and executable-alias cache maintenance.

The patch creates no private COW and therefore no patch-induced execmod
transition. Native `PROT_NONE -> RX` works without replacing the inaccessible
page. `mirror` repeats 160 mapping/body transitions with running peers:
protection loss/restoration, DONTNEED, fixed replacement, unmap/reuse, and
movement. Instructions are restored before discard or movement.
`mirror-live` repeats the full context/publication stress with this writer.
The supervisor's actual `quiesce_interrupts` and `memory_repairs` counters,
not just the fixture's own `peerStops`, remain zero.

Admission and publication are different operations. `map_new` uses
MAP_FIXED_NOREPLACE and never destroys an occupied destination. This is the
route for loader-owned, not-yet-published executable mappings; instructions
can still be selected and patched lazily afterwards.
Live `MREMAP_FIXED` replacement remains a lab experiment: it is **not**
failure-atomic under arbitrary allocation failure. Linux
[mremap_to/move_vma](https://github.com/torvalds/linux/blob/v5.15/mm/mremap.c#L730-L815)
can remove the destination before a later allocation fails. Production must
not assume that a failed replacement preserved executing code.
`mirror-denied` verifies bounds, source-read failure, rejected instruction
types, seals, early seccomp-denied replacement cleanup and EEXIST preservation;
it also installs a new mirror while mremap remains forbidden. It does not
simulate a late kernel allocation failure.

Before fork, the serialized publisher prepares a separate backing. The child
activates it before returning to application code; the parent releases its
unused prepared references. Running parent peers are never parked.
`mirror-fork` verifies 32 children per execution, independent parent/child
publication and native protection restoration. The `mirror-fork-shared`
negative control detects the otherwise real cross-process publication leak.
This fixture does not yet integrate child activation/failure with the
production clone owner, nor certify arbitrary signal continuations at fork.

The mirror's retained writer also permits cold retirement after a sandbox
denies pwrite/mmap/mremap/mprotect/memfd/ftruncate. `mirror-filter` revokes
direct admission, restores SVC through the alias and replays at the original
seccomp IP; a copied syscall at any other IP would kill the process.
This is correct Base fallback under a restrictive filter, not evidence that
every sandbox syscall is accelerated. A prepared alias is not a security
boundary against code already executing in the same process.

The owner currently requires immutable/pristine source bytes and serialized
mapping mutations. Arbitrary existing COW, concurrent or external code writers,
source truncation, writable/shared executable mappings and guest-visible
backing provenance still need production admission/invalidation. Do not
replace those requirements with a successful stress-test result.

### Resident Entry and Reclaimable Body

`svc_live_body.c` combines a closed bit and active count in one atomic word.
An invocation acquires ownership before reading body pointers and releases it
only after returning to resident code. Closing admission makes new invocations
use resident fallback while old calls finish normally.
`lifetime` performs 257 real body unmaps/reallocations, including an invocation
blocked in a native futex inside the body. Other peers continue making progress.
Early unmap is an expected-fatal negative control.

The entry itself has a different lifetime. A saved signal PC can still point
inside it before any body acquisition. `entry` constructs that continuation,
reclaims the drained body, and resumes safely through resident fallback.
Unmapping the entry with a zero body count is an expected-fatal negative
control. Entry gates remain resident until mm teardown; the body count does
not authorize their reclamation. Moving a live position-dependent branch
without restoring SVC is a separate expected-fatal control.

Preliminary 32768-stat timings, seven rounds on CPU mask 3, median milliseconds:

| Native SVC | Shroot Base | Direct payload callback | Forced-write SVC gate | Mirror SVC gate | Gate with reclaimable body |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 53.732 | 1054.353 | 174.962 | 170.426 | 165.252 | 163.126 |

Receipt: `e13be42a8e7f400792e0f7e76096c0b7`. Modes reverse on alternate
rounds. The direct-payload column is a C callback control, not a fresh
source-built-libc benchmark. The paired mirror/forced-write gate median ratio
is 1.015; individual ratios range from 0.915 to 1.406. Native samples range
from 40 to 76 ms. These noisy results support preliminary parity, not a speedup
from replacing the backing or adding body ownership.
Every timed accelerated run records 32768 completions in addition
to setup/warmup; cold discovery and publication are outside the timed region.

With other applications closed, a seven-round repeat on the same fixture and
CPU mask produced 41.186 / 928.515 / 146.465 / 156.929 / 148.089 / 161.902 ms
in the same column order (receipt `e6d2760c474d4086a9b00ed870dacd75`).
The mirror range was 136.922-187.024 ms and its paired ratio to the forced-write
gate was 0.983. This does not establish a stable backing-related speedup.

### File Workloads

The same fixture now accepts two additional workloads:

```sh
python native/guest-exec-lab/test_svc_live.py BUILD --benchmarks --workload opens --rounds 7 --cpu-mask 3
python native/guest-exec-lab/test_svc_live.py BUILD --benchmarks --workload mutations --rounds 7 --cpu-mask 3
```

`opens` repeatedly opens the same existing file read-only and closes it, for
4096 pairs. `mutations` performs 1024 cycles of exclusive empty-file creation,
close, rename and unlink, reusing two names. It does not write file contents or
fsync; it is not the earlier create/write/rename/unlink workload.
Both use 128 complete warmup iterations. Setup, patch publication, warmup,
post-loop validation and cleanup are outside the timer.
Four known fixture SVC sites use the same full-state gate and payload as the
stat experiment. Any cold exit fails the file benchmark rather than silently
falling back to Base. This measures warm syscall dispatch, not automatic
discovery in an arbitrary executable.

Seven-round medians in milliseconds, alternating mode order, CPU mask 3:

| Workload | Native SVC | Shroot Base | Direct payload callback | Forced-write SVC gate | Mirror SVC gate | Gate with reclaimable body |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Open/close, 4096 pairs | 8.789 | 375.254 | 51.034 | 47.380 | 51.974 | 53.043 |
| Empty create/close/rename/unlink, 1024 cycles | 26.589 | 230.113 | 75.597 | 92.972 | 77.396 | 86.577 |

Receipts: `1fa90daedb7b41458045528ac77a902b` (opens) and
`5d87daac8a6d4804b6b0e48c68179a18` (mutations); both passed all 70 samples.
Fixture SHA-256:
`2e54dea609bf0656179a25a134293788cf83517991d41ab7414529aa226a6684`.
Every accelerated guest sample completed exactly 8449 or 4609 calls,
respectively, including warmup and one setup stat. All benchmark samples had
zero cold misses, retirement, supervisor peer interrupts and memory repairs.
Native controls use the same fixture outside Shroot, not a chroot or PRoot
measurement.

The mirror ranges were 42.132-55.975 ms and 72.581-99.458 ms. Its ratios to
Base medians correspond to 7.22x and 2.97x speedups; its medians were about
2% above the direct callback control. These are preliminary warm-path results,
not a production-libc parity proof. In particular, the paired
mirror/forced-write ratios were 1.073 and 0.960: the difference between mutation
medians alone exaggerates the apparent benefit of the mirror.
After extending the fixture, receipt `8a0b7e607a364153a57905609fdf5a06`
passed all 30 native/guest correctness cases and eight expected-negative
controls.

### Cold Fallback Without Service Traps

An application can block or ignore SIGTRAP. Using BRK for a private fallback
then changes its shared disposition before the owner receives the stop; the
`cold-blocked-unsafe` control exits 133. This agrees with Linux 5.15's
[forced-signal implementation](https://github.com/torvalds/linux/blob/v5.15/kernel/signal.c#L1224).

`svc_direct.c` now also emits a two-instruction resident fallback: SVC followed
by a branch to the original continuation. Mismatched numbers, occupied private
frames and declined payloads enter it with the original architectural state.
`cold-syscall` checks blocked and ignored TRAP, full register preservation,
upper syscall-number bits, all frames busy and resumed acceleration after
admission is restored. There is no code retirement or service trap.

The physical syscall PC is different, so copying SVC alone is insufficient:

- `svc_filter.c` projects IP loads in classic-BPF filters to the original
  post-SVC PC. Other fields, actions, X and all scratch words retain their
  meaning. Conditional branches expand without the 8-bit offset restriction.
  Filters without IP loads remain byte-for-byte unchanged. Size/alias errors
  fail explicitly; this is not automatic filter admission in the runtime.
- `cold-filter` checks a real kernel ERRNO filter and blocks helper gettid.
  Omitting projection is an expected SIGSYS death (159), not an allowed call.
- `cold-trap` retains the application's SIGSYS action, data, logical
  `si_call_addr`, ucontext PC and its replacement return value. The dedicated
  proof supervisor translates the owned alias; omitted metadata fails with 97.
- `cold-restart` checks pipe read with and without SA_RESTART, also beneath
  an IP-and-FD-dependent filter. A proof-only TRACE rule for this native pipe
  call lets the supervisor restore the original PC **before execution**.
  Kernel EINTR/restart handling then uses that PC. Ordinary signal delivery
  must not simply rewrite a restarted PC: arm64
  [do_signal](https://github.com/torvalds/linux/blob/v5.15/arch/arm64/kernel/signal.c#L796)
  compares its saved restart address after the ptrace stop.

The last fixture verifies handler registers and successful restarted data,
with separate missing-context (97) and missing-projection (159) controls.
It does not prove precedence with every Shroot FD selector: a production alias
rule must not override the existing owner of a virtual descriptor.

`test_svc_filter` performs 4096 differential comparisons, including 16 scratch
words, high/low IP halves, near-miss aliases, long jumps and instruction limits.
Receipt `8340db42ec1045b39f73bece75259139` passes 38 native/guest cases and 16
expected failures with the proof supervisor enabled.
`8f9efdbc6d534c8dad354867b11d9432` repeats the restart pair ten times before
adding the strict IP filter; `ab361c875235458da7a67f2e931da183` repeats the
filtered pair and its controls three times. New guest cases require zero
quiescence interrupts and memory repairs. These are correctness runs, not
performance measurements; the successful 792-byte gate is unchanged.

The TRACE entry and SIGSYS projection require
`MAGICDESK_GUEST_SVC_SIGNAL_PROOF=ON` and
`test_svc_live.py --signal-proof`. Restore the normal OFF build afterward.
Still open: automatic filter installation/TSYNC admission, inherited unknown
IP filters, USER_NOTIF/debugger logical context, and a production-owned mapping
registry. In particular, a copied SVC cannot be admitted by assuming unknown
filters do not inspect its address.

### Signal Ownership

This experiment exposed an independent signal bug in internal task calls:
blocking their BRK return resets the application's shared SIGTRAP disposition
before ptrace sees it. `signal_protocol.h` now supplies the internal mask for
task calls, helpers, metadata return and deferred delivery. Task-affine calls
retain asynchronous TRAP in the existing delivery owner and resume the exact
internal stage. FD-helper and remote-filter fixtures check handler retention;
the latter also checks restoration of an originally blocked TRAP mask.

Still unproven for this gate: production-controlled publication permissions,
automatic filter revocation, arbitrary signal delivery inside its new guard,
production mapping/clone integration and complete client reset,
and stock Go/libc application coverage using this exact entry. Earlier
multi-instruction gate receipts do not certify these new boundaries.

The adjacent `mapping-task` resource regression passes. The `control-event`
filtered-wait stop-count regression reproduces on both this tree and a
separately built clean HEAD (300204 stops); it is not a passing regression
or evidence of a change caused by the SVC writer.

## Product Boundary

The ordinary bootstrap/supervisor now contains an opt-in owner, selected with
`--env SHROOT_MACHINE_ENTRY=1`. It does not launch a discovery debugger or need
the proof build option. Bootstrap allocates private frames and near-code pools;
`interception_memory` owns the registry across CLONE_VM, fork and exec.
First observed execution can publish a single SVC replacement without a peer
stop, predecessor witness or hot-site threshold. Observed syscall numbers at
one instruction share a chain of immutable guarded entries.

`svc_machine.c` owns logical signal contexts, deferred siginfo, checkpoint return
and cold replay at the original instruction. It uses the existing interception
filter, not a filter per pool or exec. Broker notifications from resident gates
return to this owner rather than being sampled as guest code. Source entry and
machine entry share the same per-thread channel and channel reentry guard.
Memory changes retire overlapping entry points; resident continuations remain
until address-space teardown. Debugger ownership disables machine admission.

`test_cooperative_runtime.py --machine-entry` runs the existing complete entry
contract. `test_svc_patch.py --integrated` and `test_svc_libc.py --integrated`
run the stock assembly/Go/libc fixtures directly, without the laboratory tracer.
`benchmark_cooperative.py --modes native proot shroot shroot-entry shroot-machine`
compares the same workload; `shroot-entry` is an explicit API caller, not a
measurement of rebuilt libc. Use the libc fixture for that separate control.

This remains opt-in. The normal writer uses ptrace against private RX mappings;
the mirror-loader experiment is not its production mapping owner. Bootstrap
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
Source-built entry does not depend on code-patch access and keeps its existing
protected path. Cooperative
channel revocation uses the same owner as source entry: one caller for a local
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
Source-built libc remains selectable for comparison and is not removed.

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

### Integrated Verification

Normal `MAGICDESK_GUEST_SVC_SIGNAL_PROOF=OFF` build, device UID 2000:

| Existing fixture | Receipt in `build/` |
| --- | --- |
| Full cooperative/resource suite without machine entry, after rebuilding every native target | `cooperative-runtime/oci-services-94657d4db2d74ac68ff93a1811e07344.json` |
| Complete cooperative entry contract with machine entry, including JIT, longjmp, debugger and TSYNC fallback, after full rebuild | `cooperative-runtime/oci-services-cda66ebfe08b4df2b6869aeeeae793ea.json` |
| Raw assembly, mapping changes, stock Go and Go with seccomp; no nested tracer | `svc-patch-results/oci-services-aa752b427c61403e8225f506cacb5528.json` |
| Stock/source-built glibc contracts, 256-thread retirement, asynchronous and blocked signal storms | `svc-libc-results/oci-services-5dc9d420cb50400fbb40d2eea8e2999f.json` |
| Dynamic stock glibc, 256-thread retirement and both signal storms | `svc-libc-results/oci-services-3ef862e229ff48999bf1ebf9daf41d8b.json` |
| 7,392 deterministic instruction boundaries, negative controls and eight queued-RT cases | `svc-direct-signals/oci-services-39fad79c82f5443bac175cb271c641de.json` |

The ELF-provenance and filter-fence change was checked separately:

| Check | Receipt in `build/` |
| --- | --- |
| Full Base cooperative/resource suite, including barrier wakeup changes | `cooperative-runtime/oci-services-754b2a53a8a043df931ff5bf1605d6b2.json` |
| Full machine-entry contract, including local versus TSYNC revocation and channel capacity | `cooperative-runtime/oci-services-2ca4d36f24f141dc9b9e9e5b0da470f3.json` |
| ELF text protections: 12 repairs; 24 TSYNC installs with 35 resident drains; raw and stock Go controls | `svc-patch-results/oci-services-40d734e648e24ba3bc63848d3274166c.json` |
| Twelve repeated live races without diagnostic tracing: 288 TSYNC installs, 305 resident drains | `svc-filter-debug/oci-services-199ef932227447f9b2d1dffe0beb3457.json` |
| 7,392 signal boundaries, negative controls and queued RT cases | `svc-direct-signals/oci-services-cc42ccd657ff44bf8a7530a09913e329.json` |
| Dynamic glibc contracts, 256-thread retirement, ordinary and blocked signal storms | `svc-libc-results/oci-services-8e55691ca87b422cae11b4128c8e2c6f.json` |

The live races exposed a lost readiness wakeup after task barriers and a
syscall-exit continuation incorrectly counted as an active callback. The fixes
republish queued resource readiness on barrier release and retain the existing
logical return owner. A full contract run also caught excessive revocation of
unfiltered peers; local and TSYNC filters now share the existing scoped owner.
Failed intermediate runs remain recorded; they are not passing evidence.

Stock-distribution verification additionally covered:

| Check | Receipt in `build/` |
| --- | --- |
| Alpine 3.23.6 OpenRC boot, service dependencies, restart and shutdown | `svc-alpine-openrc/oci-services-f87c91f4045d42a0b84c75f7560f7d1d.json` |
| SteamOS CLI, namespaces, IPC, DNS/HTTPS and socket-owner lookup | `shroot-image-tests/oci-services-5ad5bfdadb5d40a69f5bea15a9a5f86b.json` |
| Ubuntu systemd 255 boot, hardened units, user manager and socket/timer activation | `svc-ubuntu-systemd/oci-services-6078dcd945fd4c7d80f0476a8263f2f4.json` |
| Ubuntu Snap Firefox namespace and user-session preparation, not browser GUI | `svc-ubuntu-snap/oci-services-4e28fdb761a447c2a54f260e4dcb7013.json` |
| Ubuntu recipe Mousepad Wayland input/save and Weston render/detach/reattach | `svc-ubuntu-gui/oci-services-b78b2e993b4b47c9874ff2307d64e798.json` |
| 200 consecutive stock Go stress runs, each with 4,800 file cycles, GC, signals and CPU profiling | `svc-go-race/oci-services-72dd87b9b6d34122ab9c02e577fbecba.json` |
| Planner, ELF protections, TSYNC/protected-state races, protected proc views, assembly and five pairs of plain/filtered Go runs | `svc-patch-results/oci-services-961bc0cd54824027ba870f50fea182b3.json` |
| Complete machine-entry/resource contract after retained-result recovery fix | `cooperative-runtime/oci-services-075d2578ec83407e9de1d6a117c47bbc.json` |
| Twenty concurrent-reader/writer/filter runs, alternating Base and lazy entry, after complete-selector admission and address-space fence scoping | `svc-filter-admission/oci-services-66b3ed5cddc64e5294ba78552fd72294.json` |

These use unmodified distribution libc and require actual machine-entry
completions. They are correctness checks, not performance measurements.
Fork-inherited counters are not a census of distinct syscalls across the tree.
The earlier capture in
`svc-steamos-plasma/oci-services-23b14e392b384c8ba66317c80abdced6.json`
shows a splash and is not a passing desktop receipt. It is superseded by the
interactive checks below, not reclassified as success.

### Desktop and Container Acceptance

The extended matrix uses the current native build, stock distribution libc,
shell UID 2000 and virtual displays. SteamOS enters its installed
`magicdesk-desktop-session plasma-wayland` recipe as user 1000. Ubuntu uses its
systemd user session and recipe Weston. These are ordinary application launches;
no browser `--no-sandbox` or private browser build is used.

| Workflow | Receipt in `build/` |
| --- | --- |
| SteamOS Plasma, Dolphin, terminal, Steam login window and normal logout | `steamos-gui-final-start.log`, `steamos-gui-final-stop.log`, `svc-matrix-steamos-gui/` captures |
| SteamOS Flatpak Chromium: input, pointer, download, portal file chooser, WebGL and normal close | `svc-matrix-steamos-gui/flatpak-chromium-final/gui-report.json` |
| SteamOS Flatpak Firefox: same interactive checks | `svc-matrix-steamos-gui/flatpak-firefox-final/gui-report.json` |
| SteamOS VS Code: reload, editor/save, watcher, terminal, GDB variable update and normal close | `svc-matrix-steamos-gui/vscode-final/gui-report.json` |
| Ubuntu Snap Chromium and Firefox: same interactive browser checks | `svc-matrix-ubuntu-gui/snap-chromium-final/gui-report.json`, `snap-firefox-final/gui-report.json` |
| Ubuntu VS Code: same editor/debugger workflow | `svc-matrix-ubuntu-gui/vscode-final/gui-report.json` |
| Docker bridge/ports on SteamOS and Ubuntu; final Ubuntu repeat includes external DNS/HTTP | `shroot-image-tests/oci-services-f08966a923a1416e882253df7db1d531.json`, `oci-services-2fd5e4cd98684f669cb3ad352aa7ae37.json` |
| Podman bridge/ports on SteamOS | `podman-results/oci-services-121c15c877d147cba3816cb590ba331b.json` |
| Ubuntu Podman: bridge/ports, external DNS/HTTP, traced resolver and detach | `podman-results/oci-services-b642d64ca9394ae8a42b083be1608a21.json` |
| Ubuntu Podman: 40 sequential local outbound execs and full port lifecycle, repeated after final fixes | `podman-results/oci-services-07a56ec61ed7450a91c3b0e681bf9419.json`, `oci-services-d4dd0140dc8c44d8aff8b9e3b97c329b.json` |
| Eight mixed epoll modes under strace and machine entry | `shroot-image-tests/oci-services-cd47f6f7cd6946009cc6ac1abc2f32c4.json` |
| Three repetitions of all eight epoll modes under strace with Base | `shroot-image-tests/oci-services-8c51f26b6d3344eda4c3456ac55e5c42.json` |
| Nine debugger/strace workflows, including idle socket detach, machine entry and Base | `debugger-final/oci-services-f7d93f14d2154409919b1ab475a196c2.json`, `debugger-base-final/oci-services-e64757812018467d83dd14877908b71d.json` |
| Alpine musl/OpenRC boot, service lifecycle and cleanup | `svc-matrix-alpine-openrc/oci-services-f3ce7e0d48cf4a5e8253b76e0098f98d.json` |
| Original-PC/argument seccomp admission, killed helper calls, protected stdio and one-shot O_EXCL | `shroot-image-tests/oci-services-1b9864754c26450e8394c8b158ee32d5.json`, `oci-services-235ff9161c914ea4a6c21aef2f05c207.json` |
| Integrated planner, mapping/TSYNC/protected races, proc views and stock Go | `svc-patch-results/oci-services-250880b194c24e7b900fa3a748af4af9.json` |

Chromium's rendered WebGL check reports ANGLE/Zink/Turnip on Adreno 840.
Firefox's privacy-masked renderer string is not a GPU identification; its
pixel assertion verifies rendered output. These checks do not measure frame
rate. Steam reached its connected login window, not authenticated gameplay.
SteamOS recovery-image boot as an unmodified hardware OS is not certified by
its desktop recipe.

PipeWire playback reached Android on both desktops. The receipts
`svc-matrix-steamos-gui/audio-receipt.json` and
`svc-matrix-ubuntu-gui/audio-connected-receipt.json` contain nonzero received
and rendered PCM counters without reported overruns/errors/xruns. The test PCM
was silent, so it does not establish audible quality or absence of stutter.
The first Ubuntu fixture had lost the recipe's audio connection environment
across its private systemd intermediary; its zero-frame receipt is not a pass.

Docker checks use nftables, overlay2 and cgroup v2 with userland proxy disabled.
Both engines exercise TCP/UDP publications, named peers, DNS, local outbound IO,
binds, exec, conflict rejection and port release. External internet checks are
separate from deterministic local traffic. SteamOS Podman requires explicit
inherited host limits: its default nofile request exceeds Android's real hard
ceiling. The fixture records that configuration rather than pretending to raise
the native limit. Snap still uses snapd's degraded mode without AppArmor.
SteamOS container tools include test-installed Docker 29.1.3 and the signed
Arch Linux ARM aardvark-dns package; this is not a claim that the recovery
image includes those versions. Ubuntu uses its installed Podman/netavark/
aardvark packages and the separately installed Docker Engine.

Real applications exposed shared Base defects as well as accelerated-entry
coverage gaps: proc socket/owner views, PID translation for terminal/io-priority
calls, readonly reexec provenance, descriptor-selector filter budget, nftables
compat expressions, restrictive-filter FD delivery and inherited stdio metadata.
Their fixes live in the common owners and retain focused Base controls.
Application filter installation still revokes shared-memory acceleration;
successful sandbox startup does not imply accelerated execution inside every
filtered process. This matrix is correctness evidence, not a new speed benchmark
or authorization to delete the source-built comparison path.

The traced Podman workflow exposed two further shared-engine defects:

- Cancelled readiness could leave temporary-FD retirement owning the file-table
  turn while every eligible peer was excluded merely because it had a debugger.
  The common borrow policy now admits running inferiors and queued readiness
  peers at exact kernel boundaries, preserving debugger-held stops. The existing
  shared-table epoll fixture reproduced the timeout before this correction.
- Addressless native `recvfrom` could block inside the adapter, postponing a
  pending debugger detach until data arrived. Native payload IO now resumes at
  the original call boundary. The socket-detach fixture failed before the fix;
  both Base and machine-entry debugger suites pass afterwards.

The full traced Podman matrix then passed through resolver detach, subsequent
external DNS/HTTP, container removal and port release. Earlier intermittent
untraced exec timeouts remain recorded; their identical root cause is not
established merely by the later stress pass. The GUI matrix preceded these two
final fixes, while the focused debugger and container checks cover them.

### Earlier Shared-Engine Regression Controls

Two shared-engine races reproduced without machine-code entry:

- Native birth retirement could borrow a broker-held task while the broker
  delivered its original stop to the injected close. LLDB captured both engine
  threads asleep with that close still active. The broker now retains the exact
  event until the borrowed continuation is restored, without blocking unrelated
  events. `test_namespace_broker` deterministically failed before this fix.
  The unchanged affinity stress then passed 200 runs / 4,800 birth races
  (`svc-birth-timeout/oci-services-4f3bd84e2c344542b17f4a00f25fd257.json`).
- JIT memory repair could interrupt an internal semaphore poll before its entry
  stop was dispatched. Only the waiting phase recorded the service wake, so
  the resumed poll's `ERESTARTNOHAND` became a false application `EINTR`.
  Entry and waiting phases now share the wake accounting for IPC, socket
  readiness and debugger parking. The same affinity stress passed 200 runs /
  1,600 repairs (`svc-jit-wait/oci-services-411278fbb2894f6ca906906f04da561d.json`).
  The JIT fixture also checks that the repaired waiter still receives `EINTR`
  for a real application signal.

Original failures remain in
`cooperative-runtime/oci-services-4a94da4723c74dd8b753bc0a5022564e.json`
(timeout, without Plasma) and
`cooperative-runtime/oci-services-d8ddf7c8dd3941cf9a94a14c3a6d089e.json`
(internal wait). Earlier passing repeats with diagnostic logging were not
evidence that either race was fixed. No timeout was increased.
After both fixes, the full cooperative/resource suite passed without machine
entry (`cooperative-runtime/oci-services-4b64e08b1d9c4e1281a55c921106a7be.json`)
and with it (`cooperative-runtime/oci-services-bc25427b53c0496d9a4e666bc9622d25.json`),
including the new genuine-signal control.
Adjacent private-memory repair checks passed in
`shroot-image-tests/resource-private-memory-results.json`; three repetitions of
all eight mixed-epoll/sandbox modes passed in
`shroot-image-tests/oci-services-cc5ac990649949589269a1a0160450fb.json`,
including the expected fail-closed retirement case.

An eight-round, symmetric no-statistics open/close check after these changes
measured medians of 4.69 ms native, 304.98 ms Base, 36.59 ms source-built glibc
and 36.15 ms lazy SVC, for the same 4,096 pairs
(`svc-libc-results/oci-services-d2801aecd4124668a867ad494818b94b.json`).
This short regression check does not establish an improvement over the longer
earlier series: device scheduling and thermal state differ.

The earlier three-round glibc `opens` comparison (source 55.55 ms, machine
66.50 ms) had asymmetric instrumentation: only machine entry enabled runtime
statistics, including clocks in hot engine paths. It is not a fair performance
comparison. `test_svc_libc.py --integrated` now checks completion counters in an
untimed workload run and times all variants without runtime statistics.

Two repeat series used the same runtime and stock/source probe SHA-256 hashes
as that earlier run, UID 2000, CPU mask `3`, warm-up and alternating launch
order. Each sample performs 4,096 open/close pairs. Medians in milliseconds:

| Series | Samples per mode | Native | Base | Source-built glibc | Integrated SVC |
| --- | ---: | ---: | ---: | ---: | ---: |
| First | 16 | 5.89 | 349.25 | 42.88 | 46.28 |
| Second | 16 | 5.42 | 342.43 | 47.22 | 45.89 |
| Combined | 32 | 5.51 | 347.22 | 44.86 | 45.89 |

Combined median paired machine/source ratio is 1.040; the ratio of aggregate
medians is 1.023. Source samples range from 36.74 to 157.48 ms and machine samples
from 38.74 to 92.39 ms; no outliers were discarded. These measurements do not
support a stable 20% penalty, but also do not establish universal parity.
Both instrumented controls report 8,450 completions, zero declines and zero
unknown results. Libc contracts and 256-thread retirement passed in both series.
Receipts in `build/svc-libc-results/`:
`oci-services-b9eb7b3abd724d68a664c73c7e6850af.json` and
`oci-services-3b0b9f9f6edf4097a5ff9c03acd97ce2.json`.

The common benchmark's explicit API fixture below is a different control and
is not labelled as source-built libc.

The common benchmark used UID 2000, CPU mask `3`, 32 warm-up iterations and
three rotated rounds. Medians in milliseconds, excluding process startup:

| Workload | Native | PRoot | Base | Explicit API | Integrated SVC |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4,096 open/close pairs | 10.97 | 263.99 | 434.53 | 71.26 | 72.13 |
| 1,024 create/write-4KiB/close/rename/unlink cycles | 55.30 | 232.00 | 255.43 | 140.98 | 136.85 |
| 32,768 metadata reads | 52.72 | 2,135.82 | 1,015.25 | 134.25 | 137.89 |

Receipts in `build/cooperative-entry/`: `oci-services-56bdfed52344497fa91e6ddb622f54f7.json`
(opens), `oci-services-33f346dd3f9a44dc8868dc941874e95b.json` (files), and
`oci-services-1b7e59e6867a407e9067bda01f99dfd3.json` (metadata).
The source-built glibc comparison above uses its own workload fixture, not
this table's explicit API caller.

The Go stress exposed competing restart owners: a cold gate could be replayed
at its original SVC while metadata recovery still expected the alias. The
ordinary supervisor now leaves resident gates and active original sites to the
machine owner. Publication also avoids a site with an already-owned metadata
restart. These changes do not add a peer-stop publication barrier.

In particular, arbitrary self-modifying code, externally writable aliases,
simultaneous debugger ownership,
64 KiB pages and SVE/SME/MTE/PAC/BTI are not certified by these tests. Guard layout
is compatible with 4/16 KiB pages, but this device covers only 4 KiB.
No claim of transparent arbitrary instruction rewriting or general unwind
metadata is made. Existing libc compilation stays available until deployment
admission and representative application coverage meet the same contract.
