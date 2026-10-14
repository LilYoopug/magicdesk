# Debugging And Performance Fixtures

[Fixture guide](README.md) | [Native architecture](../shroot/README.md)

Debugger workflows and matched measurements. Keep tracing overhead, fixture completion and production workload success separate.

- [Developer Workflows](#developer-workflows)
- [Runtime Benchmarks](#runtime-benchmarks)

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

Affinity is a diagnostic control, not the default execution policy. Compare the
whole guest/helper chain with the same allowed CPUs; pinning only its helpers
is a different experiment. A serial request chain distributed across CPUs can
look lightly loaded to the governor even while it saturates end-to-end execution.
Record actual per-thread execution frequencies, runnable delay and remote
wakeups before attributing a pinned speedup to cache locality or fewer switches.
Scheduler traces must include executable-name changes and have no dropped or
overwritten records. Keep tracing runs separate from ordinary timing samples.

For a power-policy control, change only disposable test tasks, never the global
governor or a live application. A privileged clamp experiment does not establish
shell availability. An accepted Android performance-hint session or seccomp
synchronous-wakeup flag does not establish an effective scheduling improvement.
Verify the outcome. Private affinity masks must not become an implicit policy
for every guest: they can reduce parallel throughput and alter CPU discovery.

Configure the native CMake build with `-DMAGICDESK_GUEST_FIXTURES=ON` to build
`libmagicdesk_guest_benchmark_namespace.so`. Run it under the same shell identity
with the prepared benchmark store as its sole argument. It executes the metadata
workload directly through the namespace engine, retaining inode/content checks
but excluding syscall interception and RPC. Its first sample warms the store;
the next three isolate engine cost. This diagnostic is not another guest runtime
or a replacement for end-to-end timings, and is not packaged in the APK.
