# Cooperative Entry Fixtures

[Fixture guide](README.md) | [Runtime contract](../shroot/cooperative-entry.md) |
[Lazy SVC entry](svc-rewriting.md)

This guide covers reproduction, measurement boundaries and retained experiment
conclusions. The runtime contract owns routing, FD publication, cancellation and
sandbox semantics; it is not repeated here.

Shroot uses lazy entry in stock programs by default. Shroot Base uses ordinary
interception. Neither replaces package-owned libc files. Captured-request
laboratory modes isolate costs and are not substitutes for real application
checks. ABI 6 is the internal caller boundary.

## Runtime And Libc Iteration

Configure `MAGICDESK_GUEST_FIXTURES=ON` as described in the fixture guide.
`test_cooperative_libc.c` is an ordinary workload, not a libc patch.
For stock glibc, compile it against an existing distribution sysroot:

```sh
python native/guest-exec-lab/build_svc_glibc.py STOCK_SYSROOT OUTPUT --environment ubuntu
python native/guest-exec-lab/test_svc_libc.py BUILD OUTPUT/probe-stock --integrated --checks-only
```

The builder compiles and links only the probe, not libc. Its dynamic probe can
be tested with `--dynamic-loader`, `--dynamic-libc` and `--dynamic-extra` from
the same sysroot. Stock musl fixtures likewise need only the workload compiled
against musl. `test_cooperative_libc.py BUILD STOCK_FIXTURE` accepts the
static/dynamic probe pair and stock `sysroot/lib` layout for the broader
workload matrix. Do not reuse a fixture containing the retired source hooks.

Runtime changes rebuild the native targets. The provider stays in bootstrap;
there is no guest dlopen or hot-swapping protocol. Tests hash staged artifacts
and compare the same stock binary under native, explicit Base and lazy entry.
`--checks-only` omits timed workloads.

Run the entry/runtime model and guest checks separately:

```sh
python native/guest-exec-lab/test_cooperative_runtime.py BUILD
```

Required fixture targets and setup belong to that runner and the native CMake
configuration. A successful libc workload alone is not full runtime coverage.

The runtime suite covers initial argv/environment/exec-name string layout,
including an exec with empty environment; selected-directory `O_TMPFILE` errno;
and JIT repair while four peers create, close and unlink files. A deterministic
broker case holds the descriptor-table owner, interrupts a queued direct request
and requires that stop to become visible before the owner is released. This
guards against barrier/FD ownership cycles, not just a longer timeout.

## Measurements

Measure on an otherwise idle device after compilation. Record charging,
temperature, CPU mask, executor UID, kernel, runtime hashes, libc/probe hashes,
directory representation and application filter state. Retain all rounds,
including failures and outliers. Do not compare one best laboratory sample with
a production median.

The real-libc runner supports:
- `--rounds N --scale N --workloads ...` for selected workload families.
- `--reference-build BUILD --reference-kernel` for
  interleaved comparison against preserved runtimes with the same stock fixture.
- `--proot-prefix PREFIX` for a PRoot control under the same shell UID.
- `--sandbox` for actual argument-dependent kernel filters around timed calls.
- `--directory-mode logical|imported` to distinguish directory ownership.
- `--condition TEXT` to record device conditions.
- `--profile` for separate diagnostics; `--sample-statistics` instruments
  every timed sample and must not be mixed with uninstrumented timings.

Use the runner's `--help` for the current workload names. Balance pair precedence
and mode positions over complete rotation/reversal sets. Ratios of paired rounds
are not ratios of independently displayed medians. CPU affinity is a diagnostic
control, not a production scheduling policy.

The smaller captured-request benchmark can compare production routes too:

```sh
cmake --build BUILD --target benchmark_cooperative -j4
python native/guest-exec-lab/benchmark_cooperative.py BUILD \
  --workload opens --iterations 4096 --rounds 7 --spin-ns 25000 \
  --cpu-mask 3 --logical-root \
  --proot-prefix /data/data/com.termux/files/usr \
  --modes native proot shroot shroot-entry
```

Its report uses these internal mode names:

| Mode | Meaning |
| --- | --- |
| `native` | Actual syscalls in a disposable native directory |
| `proot` | Same static fixture and directory, shell UID 2000, fake root, verified seccomp acceleration |
| `shroot` | Production supervisor with ordinary interception, called Shroot Base in user documentation |
| `shroot-entry` | Production bootstrap entry with guest pointers and original-SVC fallback |
| `cooperative*` | Captured-request transport/engine experiments, not real-libc acceptance |
| `engine` | Same filesystem engine in the fixture process, without transport |
| `engine-read-lease` | Metadata lower bound holding the gate for the entire loop; not deployable |

The files workload creates exclusively, writes 4096 bytes, closes, renames and
unlinks; opens repeats readonly open/close. Metadata and directory workloads
exercise different paths. Invocations warm up before timing.

The executable is installed in the test store, without an extra bind attachment.
Preparation creates /bench with guest credentials. `--logical-root` additionally
assigns logical metadata to the root for every compared Shroot mode; it must not
be silently applied to just the candidate. Ordinary file-cycle assertions require
zero catalogue writes and no forced object/directory synchronization.
Physical-permission imports, watched files and overlays need separate results.

## Retained Performance Evidence

These historical series used source-integrated libc before its removal. They
document specific stages, not the performance of the current lazy frontend. Raw receipts are local artifacts under `build/cooperative-musl-results`;
they are not shipped assets or required files in a clean checkout.

### Path Admission And Native Births

Twelve balanced, uninstrumented rounds at scale 2, CPU mask 3, shell UID 2000,
without concurrent builds/tests, compared against `93d8e223`.
Receipt: `oci-services-7b56b64cc35149ad832e718c9f81a345.json`.
Candidate supervisor SHA-256:
`342492459c6854d0bcb94a4c75a037bdaa1a98c2eeddc0f05323efc6c67e8ed7`.

| Workload | Native ms | PRoot ms | Base ms | Reference entry ms | Candidate entry ms | Paired ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4096 exclusive file cycles | 92.07 | 800.52 | 942.80 | 453.62 | 345.44 | 0.757 |
| 4096 nonexclusive file cycles | 89.57 | 799.80 | 933.54 | 432.66 | 352.66 | 0.828 |
| 65536 stat calls | 51.07 | 3989.53 | 1849.55 | 231.87 | 218.40 | 0.954 |
| 8192 open/close pairs | 16.15 | 538.50 | 788.72 | 87.10 | 86.23 | 0.988 |

File cycles improved about 17-24%, not the proposed 1.5x. Opens were approximately
unchanged. An earlier roughly 4% stat slowdown was absent in two follow-up
series; that is not a universal non-regression guarantee. Absolute latency
drifted across sessions, so retain matched controls.

### Shared FD Admission

Ten balanced, uninstrumented rounds at scale 2, CPU mask 3, shell UID 2000,
against `892d419a`, without concurrent builds/tests.
Receipt: `oci-services-ce188c850fe445b6839f8e31baa8b4dc.json`.
Candidate supervisor SHA-256:
`57b3bd844c17fea08880ef3573d2c0c715aea447533876d280fd54e26c6624ae`.

| Workload | Native ms | Reference entry ms | Candidate entry ms | Paired entry ratio | Paired Base ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| 8192 readonly open/close pairs | 14.96 | 90.61 | 89.17 | 1.020 | 0.926 |
| 8192 writable open/close pairs | 14.35 | 84.27 | 100.31 | 1.031 | 0.964 |
| 4096 exclusive file cycles | 100.81 | 353.42 | 345.20 | 0.999 | 1.032 |
| 4096 nonexclusive file cycles | 101.91 | 343.29 | 334.21 | 0.933 | 0.979 |
| 65536 stat calls | 48.28 | 231.02 | 223.98 | 0.988 | 0.979 |

Ordinary opens benefit; entry opens do not demonstrate a gain. Writable entry
opens include a 220.73 ms outlier and a higher median. Do not discard that result
or claim uniform improvement. The file-cycle 1.5x target remains open.

Filtered open/close statistics fell from 20745 to 16645 ptrace requests per
4096 pairs, with real kernel filters and their stops still present. Receipts:
`oci-services-0809536a8e024b7399ab5209a9963c50.json` (reference) and
`oci-services-4fa6a597e3d7426284811ed98e0c8860.json` (candidate).
Fewer requests alone do not establish direct-entry speed inside a sandbox.

## Correctness Gates

Keep the following coverage independent of timed results:

| Boundary | Required checks |
| --- | --- |
| Admission | Unsupported calls, unavailable provider, nested entry, fork/exec, slot exhaustion and explicit pre-effect fallback |
| Caller memory | Invalid/guard-page paths, partial output, protected callers and real signal context |
| Effects | Cancellation before/after native entry, no mutation replay, exact publication and owned result retirement |
| FD ownership | EMFILE, close/reuse, dup/fcntl, shared tables, retained/unlinked objects, COW, mount policy and debugger-edited arguments |
| Filesystem | Live credentials/umask, readonly mounts, DAC/Landlock, directory offsets, watches and interrupted durable publication |
| Libc | Static/dynamic controls, musl and glibc cancellation/unwinding, FIFO signals, unmodified userspace |
| Sandboxes | Original-site application filters, automatic and set-ID Chromium routes without disabling the sandbox |

The shared-FD stage above passed runtime/models, watch/contracts and glibc:
`oci-services-a48a1f29c3a04194bf9683f76f407d8e.json`,
`watch-runtime-e7993e7340bd46d18db164f0f4e6ecc7.json`,
`oci-services-5b95241b58ba4523ac6fb0b96af1c333.json`.
Chromium automatic/set-ID reports each passed 4/4:
`browser-stage-results-48e64691fdd24d64aa6196c1d9017cc0.json` and
`browser-stage-results-2012262737624959b4a1fa48d16bcb25.json`.
Those are sandbox/JS/PNG checks, not GPU checks or verification of later builds.

A later signal regression reproduced false EINTR when a native plan was
cancelled before its kernel effect. The corrected owner retires the plan and
declines to ordinary admission; completed or unknown effects are never replayed.
Current focused evidence for that fix:
- Runtime/models: `build/cooperative-runtime/oci-services-9d9b015046d14bd687cc000cc9da116c.json`.
- Glibc: `build/cooperative-glibc-results/oci-services-34b2fe4b0f6740489db2009f427edf26.json`.
- Musl: `build/cooperative-musl-results/oci-services-a2d937826f2f4fd0b7bc89a694153191.json`.

These are correctness receipts, not new throughput measurements or a completed
SteamOS installer acceptance run.

The JIT-resume regression registers a direct-entry peer, parks it on a native
futex, repairs dirty private memfd code in another thread, then immediately
requests metadata through that peer's retained channel. Its eight rounds must
show actual successful memory repair, not native permission bypass. The old
runtime timed out after the first repair because barrier release left broker
admission stopped (`build/cooperative-jit-resume/oci-services-887ec085c0694c4da133626bd454966a.json`).
The fixed runtime passed the entry suite
(`build/cooperative-runtime/oci-services-5ca7ff78db6a4eda852477941b13cc25.json`)
and the resource `private-memory` suite, including protected callers, vfork and
remote writers. The same stock SteamOS `qmlplugindump org.kde.plasma.core 2.0`
completed without disabling JIT or rebuilding Qt.

## Experiment Boundaries And Rejected Approaches

The captured-request channel accepts bounded scalar values and captured paths,
not guest-selected credentials or namespace authority. It tests interruption,
stale requests, protected callers and FD balance. Its private worker/socket does
not validate production registration or application-filter admission.

Separate-table experiments transfer actual rights with sequence-matched receipts;
shared-table experiments require CLONE_FILES and exact slot ownership. None
licenses treating a worker's numeric FD as a guest descriptor.

Retain these negative findings when considering new optimizations:
- Sharing the full worker FD table exposes internal authority. The smaller relay
  alternative adds serial handoffs and scheduling contention.
- A whole-loop read lease blocks namespace writers. Production uses bounded
  operation windows, releases before parking or incompatible work, and still
  validates each call. It does not cache stat results or permissions.
- Raising a burst limit to 128 regressed repeated measurements. A fixed iteration
  count is not a portable time budget across governors and devices.
- A literal host pathname is not stable object authority across rename, unlink,
  mounts or sandbox policy. Production native plans retain exact pins.
- The best early roughly 48 ms open result is not an established production
  guarantee. Reduced stops and ptrace requests also need matched elapsed/CPU
  measurements.
- WAIT_KILLABLE_RECV availability did not imply safe semantics on the tested
  kernel. Keep newer flags and their fallback evidence in the
  [kernel compatibility ledger](../shroot/kernel-compatibility.md).
- Application seccomp is not bypassed to obtain laboratory transport timings.
  Original-SVC-only filters and protected callers retain their supported routes.

Superseded ABI descriptions and step-by-step experiment logs live in Git history.
Keep this guide focused on reproducible workflows and conclusions that constrain
the next implementation.
