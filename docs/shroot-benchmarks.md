# Shroot Performance: Alpine

Measured on 2026-10-25 and 2026-10-26 on one Android phone. These results compare actual
execution environments, not equivalent isolation or a universal speed ranking.
Lower elapsed time is better; **chroot = 1.00x** in each row. Ratios are elapsed
time relative to chroot, not speedups.

## Exec Protocol Study

The subsequent 2026-10-26 candidate consolidates exec preparation and image
entry: it leases the existing mapped request buffer at dispatch, retains the
exact published ELF descriptors, prepares credentials with program publication,
and commits live/snapshot auxv and mapping provenance at the existing entry
checkpoint. Secure entry still lowers native dumpability before entering the
loader. Failed exec, scripts, descriptor execution and application filters keep
their existing contracts. No active-wait or event-service budget was increased.

Five alternating samples per bundle, with one excluded warmup and CPU 0-1,
separate the minimal process operations from the standard `/bin/true` workload:

| 128 cycles | Before consolidation | After consolidation |
| --- | ---: | ---: |
| `fork/exit/wait` | 48.89 ms | 48.61 ms |
| Minimal stock-musl dynamic exec | 368.25 ms | 332.57 ms |
| Minimal static exec | 346.65 ms | 277.60 ms |
| Standard `/bin/true` exec | 1,025.19 ms | 1,090.16 ms |

The minimal dynamic/static instrumented runs remove **513 observed stops,
2,309 ptrace requests and 258 worker deliveries** each. This is a protocol
reduction, not proof of a corresponding elapsed-time reduction for every program.
The standard workload has not improved consistently; the requested 2.5x gain
and PRoot parity are **not achieved**. Here `/bin/true` is the packaged coreutils
multicall binary, with additional shared-library dependencies, not the minimal
fixture. [Minimal samples, frequencies, counters and hashes](benchmarks/alpine-exec-entry-study-2026-10-26.json)
and [standard workload/file checks](benchmarks/alpine-exec-entry-paired-2026-10-26.json)
retain every sample, including the unfavorable results.

A deliberately incomplete isolated experiment stopped observing successful
ordinary file mappings and omitted their backing provenance. It removed 1,792
stops from the instrumented standard workload, but its five-round timing median
was **1,081.55 ms versus 1,081.38 ms** for the complete candidate. This does not
support a large gain from removing mmap exit stops alone. The experiment was
reverted; the rebuilt supervisor's SHA-256 matches the complete tested bundle.
It is not a selectable runtime mode. Instrumented direct launches and timing-
harness launches are separate series, not interchangeable samples.

The first paired file checks measured `stat` 73.38 -> 52.92 ms, file cycles
808.14 -> 785.67 ms, but open/close **114.87 -> 133.10 ms**. Consequently these
checks alone do not establish absence of a file-performance regression. A
separate 15-round alternating open/close repeat measured **171.62 -> 170.53 ms**;
the initial regression did not reproduce. Both series remain in the paired
report rather than selecting the faster result for either bundle.
Frequency observations cover the command envelope and are not used to normalize
elapsed time or attribute all differences to DVFS.

The complete candidate passed the selected cooperative-entry, SVC/Go, signal,
filesystem buffer/cancellation, supervisor-state and event-fairness suites,
exec-custody checks, and stored set-ID workflows on Alpine/musl and Debian/glibc
(including Debian in Base mode). The unified checkpoint suite also passed.
The installed APK and SteamOS session were not replaced; a fresh GUI latency
check and a new full three-mode performance series remain separate work.

## Current Common Series

This complete three-mode series precedes the exec consolidation above. Its
2026-10-26 candidate observes memory-call arguments at both original
SVC instructions and exact resident native aliases without eagerly reading the
complete register set. Error rewriting and task-affine helpers still capture
the full context. Native results, mapping provenance, noexec policy and resource
ordering are unchanged. The selected cooperative-entry, SVC, signal, filesystem,
supervisor-state and event-fairness suites passed on the staged bundle.

This common series uses CPU 0-1, verified `nice=0`, stock Alpine musl, one
excluded warmup and five interleaved samples per mode. It does not update the
installed APK. [Complete samples, frequencies and binary hashes](benchmarks/alpine-compact-alias-2026-10-26.json)
are retained together; faster rows from other series are not substituted.

| Workload | chroot | PRoot | Shroot | Geometric target |
| --- | ---: | ---: | ---: | ---: |
| 16,384 `stat` calls | 8.11 ms | 510.31 ms | 41.46 ms | 64.35 ms: met |
| 16,384 `open/close` pairs | 18.32 ms | 877.82 ms | 133.61 ms | 126.82 ms: not met |
| 16,384 create/close/rename/unlink cycles | 251.12 ms | 2,959.39 ms | 828.75 ms | 862.06 ms: met |
| 4,096 metadata/open/read checks | 16.93 ms | 478.92 ms | 141.65 ms | 90.04 ms: not met |
| 128 `fork/exec/wait` cycles | 127.83 ms | 497.73 ms | 1,181.75 ms | 252.24 ms: not met |
| 1,000,000 ready `ppoll` calls | 274.01 ms | 295.16 ms | 323.91 ms | 284.39 ms: not met |
| 1,000,000 ready `epoll_wait` calls | 294.04 ms | 318.21 ms | 331.39 ms | 305.88 ms: not met |
| 100,000 memory-operation iterations | 407.02 ms | 352.71 ms | 453.56 ms | 378.89 ms: not met |

The file-cycle result is **51.80 ms per 1,024 cycles**, close to the earlier
fast series. In a separate alternating comparison, the preceding small-tree
candidate and this bundle measured 785.02 and 771.51 ms respectively for
16,384 cycles. [All five paired workloads](benchmarks/alpine-compact-alias-paired-2026-10-26.json)
retain their warmups and samples. These results do not establish a code-only
speedup: both versions recovered the earlier file-cycle performance, while
short-process measurements varied substantially.

Only `stat` and file cycles meet the requested per-workload geometric target in
this series. Open/close is 5.4% above its target; process startup remains the
largest gap. No spin or event-service budget was increased. Event-fairness tests
do not replace a SteamOS GUI/input latency check. Frequency observations cover
the command envelope, not the timed loop alone, and do not normalize the times.

The corresponding three-round SQLite series measured medians of **113.50 s
chroot, 102.37 s PRoot and 109.74 s Shroot**; all five artifacts matched
byte-for-byte. Shroot did not meet either the PRoot time or the 107.79 s geometric
target. [Compilation samples and frequencies](benchmarks/alpine-compact-alias-sqlite-2026-10-26.json)
are separate from the exec study; compilation has not been rerun on that candidate.

## Earlier Small-Tree Candidate

The 2026-10-26 small-tree event-collection candidate uses the syscall-only
affinity observation described below, CPU 0-1, `nice=0`, one excluded warmup
and five interleaved samples per mode. It is a staged native bundle, not an
installed APK. This series precedes compact memory-argument observation.
[Complete samples, frequencies and binary hashes](benchmarks/alpine-short-collection-2026-10-26.json)
are retained together; faster rows from other series are not substituted.

| Workload | chroot | PRoot | Shroot | Geometric target |
| --- | ---: | ---: | ---: | ---: |
| 16,384 `stat` calls | 10.62 ms | 627.16 ms | 86.12 ms | 81.62 ms |
| 16,384 `open/close` pairs | 22.13 ms | 1,064.43 ms | 156.79 ms | 153.49 ms |
| 16,384 create/close/rename/unlink cycles | 330.34 ms | 3,590.30 ms | 1,612.14 ms | 1,089.05 ms |
| 4,096 metadata/open/read checks | 14.78 ms | 487.13 ms | 126.16 ms | 84.84 ms |
| 128 `fork/exec/wait` cycles | 128.77 ms | 493.27 ms | 1,197.71 ms | 252.03 ms |
| 1,000,000 ready `ppoll` calls | 269.76 ms | 298.50 ms | 307.36 ms | 283.77 ms |
| 1,000,000 ready `epoll_wait` calls | 293.33 ms | 316.43 ms | 344.74 ms | 304.66 ms |
| 100,000 memory-operation iterations | 397.47 ms | 453.34 ms | 458.44 ms | 424.48 ms |

None of these rows meets the per-workload target. Short-process startup is the
largest remaining gap. The file-cycle total is 98.40 ms per 1,024 cycles,
versus about 50 ms in the earlier series. The later common and paired checks
above recovered that performance on both candidate generations.
Frequency observations cover each command including startup/teardown, not only
the timed loop. They are not used to normalize elapsed times or claim that DVFS
explains the whole difference. SQLite compilation is measured separately.

A subsequent five-round alternating check on the same store measured the
earlier fast bundle at **1,624.38 ms** and this candidate at **1,615.96 ms** for
the same 16,384 file cycles. The earlier bundle also became slower: the last
runtime changes do not explain the twofold historical difference. The CPU 0-5
cluster's reported maximum was 2,112 MHz during this check, versus 3,629 MHz in
the earlier fast series; voluntary context switches also increased. These
observations do not establish how much of the difference each cause explains.

The separate three-round SQLite series measured medians of **77.86 s chroot,
61.71 s PRoot and 70.89 s Shroot**. All five artifacts matched byte-for-byte.
Times increased substantially during the series in all three modes, so these
medians do not establish a precise code-only difference. Shroot has not met
the compilation target. [Both complete reports](benchmarks/alpine-recovery-check-2026-10-26.json)
retain launch order, samples, CPU observations and binary hashes.

## Earlier Equal-Priority Candidate

This comparison uses CPU 0-1 (`--cpu-mask 3`), verified `nice=0` in all
three modes, stock Alpine musl and interleaved launch order. These are separate
measurements from the earlier CPU 0-3 series below. Each microbenchmark includes
five measured samples and one excluded warmup per mode.
[Samples, frequencies and exact runtime hashes](benchmarks/alpine-admission-2026-10-26.json)
identify each candidate; they are not measurements of the installed APK.

This series predates the harness's syscall-only affinity observation. Its
parent shell read `/proc/self/status` before timing, causing Shroot's descriptor
selectors to be inherited by measured descendants. Current runs use an untimed
child calling `sched_getaffinity` and `getpriority`; `--preopen-proc` explicitly
retains the earlier scenario. Neither path discards measured work, but their
startup and inherited-filter costs differ. Do not merge samples across these
methods or attribute their entire difference to a runtime optimization.

| Workload | chroot | PRoot | Shroot | Geometric target |
| --- | ---: | ---: | ---: | ---: |
| 16,384 `stat` calls | 9.44 ms | 510.02 ms | **50.70 ms** | 69.39 ms: met |
| 16,384 `open/close` pairs | 17.93 ms | 879.92 ms | **101.83 ms** | 125.61 ms: met |
| 16,384 create/close/rename/unlink cycles | 273.96 ms | 3,063.84 ms | **801.39 ms** | 916.17 ms: met |
| 4,096 metadata/open/read checks | 12.03 ms | 390.36 ms | 79.73 ms | 68.52 ms: not met |
| 128 `fork/exec/wait` cycles | 131.61 ms | 472.90 ms | 939.46 ms | 249.47 ms: not met |
| 1,000,000 ready `ppoll` calls | 213.62 ms | 229.08 ms | 228.78 ms | 221.21 ms: not met |
| 1,000,000 ready `epoll_wait` calls | 242.42 ms | 262.16 ms | 256.89 ms | 252.10 ms: not met |
| 100,000 memory-operation iterations | 303.50 ms | 349.01 ms | 345.98 ms | 325.46 ms: not met |

The target is `sqrt(T_chroot * T_proot)` for **each workload**, not an aggregate
score. The three primary file loops meet it; short-process startup remains
substantially slower than PRoot. Small polling differences are not proof of a
general advantage. Ready waits still execute in the guest's kernel thread.

The file-cycle result is about **50.09 ms per 1,024 cycles**, including all
sixteen blocks. It is not an 801 ms result for 1,024 cycles, nor does it measure
payload writes or durable `fsync`. Comparing historical totals requires the
same operation count and timing boundary.

A separate alternating check against the first fast candidate found no file
regression: `stat` 52.65 -> 43.91 ms, `open/close` 131.07 -> 117.45 ms and file
cycles 799.98 -> 774.95 ms. Those paired results are retained in the same JSON;
they must not be spliced into the three-mode table as if measured together.

The shared changes include native admission for safe private memory operations,
cached publication of their exclusion ranges, retained backing descriptors,
directory-cursor participation in the existing bounded inode operation window,
and optional diagnostic counters. They do not extend active-wait budgets or
remove fair event servicing. GUI latency still requires its own device check;
microbenchmark success alone does not establish SteamOS responsiveness.

## Historical Initial Candidate

All environments use the same Alpine 3.23.6 AArch64 rootfs, stock musl and GCC.
Shroot uses its default lazy SVC acceleration, without a rebuilt libc or
statistics instrumentation. Each row reports the median of interleaved runs.
Shroot here is the first staged performance candidate, before native unmap
admission described below, not an update installed into the user's running
environments. [Samples and runtime hashes](benchmarks/alpine-2026-10-25.json)
identify the exact binaries, source inputs and CPU-frequency observations.

These initial series predate explicit priority normalization. Termux's inherited
`nice=-10` gave PRoot a priority advantage over the shell/root runs at `nice=0`.
Keep them as historical measurements, not as controlled equal-priority results.
The current harness checks `nice=0` before and after every probe and sample and
records the inherited host priority separately.

| Workload | chroot | PRoot | Shroot |
| --- | ---: | ---: | ---: |
| 16,384 `stat` calls | 10.9 ms (1.00x) | 511.7 ms (47.00x) | 60.5 ms (5.55x) |
| 16,384 `open/close` pairs | 19.9 ms (1.00x) | 896.5 ms (44.96x) | 126.3 ms (6.34x) |
| 16,384 create/close/rename/unlink cycles | 262.4 ms (1.00x) | 3,086.8 ms (11.76x) | 774.3 ms (2.95x) |
| 4,096 metadata/open/read checks | 13.2 ms (1.00x) | 397.6 ms (30.21x) | 93.6 ms (7.11x) |
| 128 `fork/exec/wait` cycles | 132.9 ms (1.00x) | 630.3 ms (4.74x) | 1,569.5 ms (11.81x) |
| 1,000,000 ready `ppoll` calls | 217.4 ms (1.00x) | 237.8 ms (1.09x) | 277.6 ms (1.28x) |
| 1,000,000 ready `epoll_wait` calls | 245.9 ms (1.00x) | 270.7 ms (1.10x) | 313.2 ms (1.27x) |
| SQLite CLI and shared-library build, `-j4` | 43.04 s (1.00x) | 50.52 s (1.17x) | 65.15 s (1.51x) |

The file-cycle row has no payload writes or `fsync`; it is not a durable-write
benchmark. Its Shroot total averages about 48 ms per 1,024 cycles, not 774 ms
per 1,024 cycles. All sixteen consecutive blocks, including the first, count.
Neither this result nor the syscall microbenchmarks predict GUI/input latency.

Shroot is faster than PRoot in these file-heavy loops, but still slower than
native chroot. PRoot wins the compilation, short-process and ready-polling workloads. There
is deliberately no aggregate score combining unrelated tests.

## Initial Paired Changes

The same series alternates the installed reference bundle and the candidate
under UID 2000, using the same Shroot store. These are reductions in elapsed
time, not comparisons against an earlier run at another frequency.

| Workload | Reference Shroot | Candidate Shroot | Time reduction |
| --- | ---: | ---: | ---: |
| `fork/exec/wait` | 1,803.6 ms | 1,569.5 ms | 13.0% |
| `ppoll` | 334.0 ms | 277.6 ms | 16.9% |
| `epoll_wait` | 343.9 ms | 313.2 ms | 9.0% |
| SQLite build | 70.04 s | 65.15 s | 7.0% |

Ambient conditions changed during the SQLite series: the user took the phone
outside into colder air. Measured ranges were 32.60-53.59 s for chroot,
42.00-53.93 s for PRoot, 64.16-74.64 s for reference Shroot and 51.38-72.13 s
for the candidate. Median policy-wide CPU frequencies were respectively
2,625, 2,267, 3,154 and 2,813 MHz. The 7.0% median difference does **not**
establish a precise code-only speedup; this is not an unexplained runtime
instability. All five generated artifacts matched
byte-for-byte across the measured builds. The remaining PRoot gap is not closed.

File-loop medians changed by -1.6% to +3.4% in elapsed time, within the
observed sample spread; this is not evidence of a general file-speed gain.

The fixes target shared runtime mechanisms:

- Ordinary private `munmap` ranges no longer require syscall-exit observation
  merely because an unrelated ELF mapping has retained provenance. Shared
  address spaces and overlapping file/policy ranges keep ordered observation.
- The initial compact unmap path avoids a full register snapshot. Compiler
  allocation churn still entered the supervisor in this version.
- Native waits skip repeated service-gate comparisons in the seccomp filter.
  Their kernel wait is unchanged. The IP-dependent filter still has a cost even
  when no syscall is forwarded to userspace.
- Bootstrap reuses entry admission from its ready handshake. Unpublished lazy
  entry code is staged in a block, with ptrace fallback; final SVC publication
  and application signal/filter handling retain their existing owners.

A separate counter-enabled SQLite diagnosis found about 2.31 million `munmap`
calls. The range/compact-path changes reduced observed stops from about 4.72 to
2.42 million and ptrace operations from 11.85 to 4.96 million. Those diagnostic
timings are not mixed into the table.

## Native Unmap Candidate

The next candidate admits non-overlapping private unmaps directly in the
calling guest thread. Publication belongs to the sole address-space owner;
sharing, debugger/filter fences, protected mappings and uncertain policy
retain the observed path. File and SVC provenance are excluded. No mmap scan,
worker request or supervisor stop is added to each admitted operation.

A separate three-round interleaved series, including one excluded warmup:

| SQLite build, `-j4` | chroot | PRoot | Installed Shroot | Native-unmap candidate |
| --- | ---: | ---: | ---: | ---: |
| Median | 61.42 s | 62.95 s | 114.90 s | 72.80 s |

All five artifacts and both execution checks match. The candidate reduces
elapsed time by 36.6% against the installed reference in this series, but is
still 15.6% slower than PRoot. The per-workload geometric target is 62.18 s
and is **not met**. These measurements do not replace the earlier series
or establish a frequency-independent speedup. The policy-wide median
frequencies were 1777, 1822, 1824 and 1781 MHz respectively.

Preserving file performance is an independent acceptance condition. The
reference for the following checks is the **first fast candidate**, not the
slower installed reference. Both bundles use the same store and alternating
launch order; neither has statistics enabled.

| Workload | First candidate | Native-unmap candidate | Elapsed change |
| --- | ---: | ---: | ---: |
| 65,536 `stat` calls, 9 measured runs | 317.80 ms | 315.77 ms | -0.6% |
| 16,384 `open/close` pairs, 5 runs | 203.16 ms | 186.52 ms | -8.2% |
| 16,384 file cycles, 5 runs | 1648.90 ms | 1619.19 ms | -1.8% |

An initial shorter `stat` series measured 78.10 vs 85.12 ms; the longer repeat
did not reproduce that slowdown. Both series are retained, without discarding
samples. These checks found no reproducible file regression; they do not prove
a universal speedup or waive the same checks for later optimizations.
[Native-memory samples, hashes and frequencies](benchmarks/alpine-native-memory-2026-10-25.json)
include both reference identities and all measured and warmup samples.

In a counter-enabled build diagnosis, unmap entry stops dropped from about
2.31 million to 20,784; all observed stops fell to 186,728 and ptrace requests
to 478,856. This diagnosis is separate from ordinary timing. Correctness
coverage includes private/shared mappings, page rounding, asynchronous
signals, seccomp denial, TSYNC and protected mappings.

The optimization target is `T_shroot <= sqrt(T_chroot * T_proot)` **for each
workload**, not for an aggregate score. Remaining below that target does not
excuse a regression in stat, open/close or file cycles. Compilation, process
startup and ready polling remain open performance work.

## Method

- Device: nubia NX809J, Android 16/API 36, Linux 6.12.23, AArch64.
- Installed MagicDesk: 2.1.2 (224), build ID
  `a0a69107a28164fcffe18696c4ea9c72c48ad7f401bab20a3c20850ce5cc86a1`.
- Alpine GCC 15.2.0-r2, musl 1.2.5-r24, binutils 2.45.1-r0,
  Make 4.4.1-r3 and GNU time 1.9-r1. The compiler and `cc1` hashes match.
- Termux PRoot package: 5.1.107.92.
- Native chroot runs as host root. PRoot runs as the Termux UID, with its
  seccomp accelerator enabled and no fake-root extension. Shroot runs as host
  shell UID 2000, guest UID 0. Root is only a requirement for the native baseline.
- Every runtime and its children use an explicit CPU mask: CPU 0-1 (`3`) in
  the current equal-priority series, CPU 0-3 (`f`) in the historical series.
  Effective masks are checked before and after each sample. This is a pinned
  comparison, not an unrestricted eight-core result. Android scheduling groups,
  SELinux domains still differ between executor identities. Current runs
  verify the same normal priority; the initial historical runs did not.
- SteamOS/Steam/DDNet were stopped before measurement. The phone stayed awake.
  The initial series was unplugged; later native-memory measurements were on
  charge. Each report retains its power-source observations; absolute times
  from these series must not be combined. Governors and frequency limits were not changed. Background
  Android work and thermal/DVFS variation remain possible.
- Five measured samples per microbenchmark, three per compilation workload,
  one excluded warmup per mode.
  Launch order rotates each round. No outliers are discarded.
- Monotonic timing inside the existing C fixtures excludes environment launch,
  fixture compilation, setup and cleanup. Warmed page caches are retained;
  global cache dropping and compiler caches are not used.

CPU frequency is not locked. The JSON retains policy-wide residency-weighted
frequency and before/after frequencies and limits for every sample. These
observations include command startup/teardown and other tasks sharing the
policy; they are not per-thread frequency measurements. Do not normalize
elapsed times by them as if all work scaled linearly with CPU frequency.

The first exploratory runs had inherited CPU affinity, including one PRoot
probe restricted to CPU 0-1. They are **not** mixed into this table. The published
series use explicit, checked affinity in every mode.

## Reproduction

The harness is [benchmark_compile.py](../native/guest-exec-lab/benchmark_compile.py).
See [developer workflows](../native/guest-exec-lab/developer-workflows.md) for
preparation, identity requirements and interpretation of the retained counters.
Use an independent build-only sysroot, not a running user's desktop environment.

The Alpine rootfs is the official
[3.23.6 AArch64 minirootfs](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/alpine-minirootfs-3.23.6-aarch64.tar.gz),
SHA-256 `b17a57958e29735ff0e6e64254d958e65903687a70ca30cc430b33a965ad49d7`.
Install `build-base time coreutils` with stock `apk` and signature verification.
Record the rootfs and installed package versions in `manifest.json` beside
`sysroot/`. Shroot imports that tree through its image service with hardlinks
preserved; no libc or compiler binaries are substituted.

```sh
python native/guest-exec-lab/benchmark_compile.py WORK_DIRECTORY \
  --sqlite SQLITE_AMALGAMATION_DIRECTORY --runtime INSTALLED_GUEST_BUNDLE \
  --cpu-mask f --workload file-stat --iterations 1024 --file-blocks 16 \
  --rounds 5 --warmups 1
```

The first run reports its prepared `guestStore`. Reuse it explicitly with
`--guest-store STORE` for subsequent workloads; fixture/compiler mismatches
are rejected. Repeat for `file-open`, `file-cycle`, `metadata` and `spawn`.
For `poll`/`epoll`, use `--iterations 1000000`. The JSON `guest` mode denotes
ordinary accelerated Shroot, not Shroot Base.

For compilation, use `--workload compile --jobs 4 --rounds 3`. The source is
[SQLite 3.51.3 amalgamation](https://www.sqlite.org/2026/sqlite-amalgamation-3510300.zip),
archive SHA-256 `acb1e6f5d832484bf6d32b681e858c38add8b2acdfd42ac5df24b8afb46552b4`.
Each run removes the previous objects and builds the CLI and PIC shared library
with `-O3 -flto` and a fixed random seed. Timing surrounds `make`, not source
download or environment setup. SQL execution, shared-library execution and
byte-identical hashes of all five generated artifacts are required.

Do not compare these totals with historical tests using different operation
counts, CPUs, frequency limits, libc versions, storage or timing boundaries.
