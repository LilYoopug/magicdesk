# Shroot Fixture Guide

This directory contains native probes, prepared Linux workloads and device
runners. Production implementation belongs to [native/shroot](../shroot/README.md).
The [user guide](../../docs/shroot.md) describes supported workflows and limits;
fixtures do not define a separate runtime or installation interface.

## Choose A Suite

| Contract | Guide |
| --- | --- |
| Bubblewrap, namespaces, credentials and application filters | [Namespace fixtures](namespaces.md) |
| SteamOS, X11/Wayland desktops, audio and GPU | [Desktop workflows](desktop-workflows.md) |
| OCI images, mounts, filesystem operations and watches | [Filesystem workflows](filesystem-workflows.md) |
| GDB, strace and matched performance measurements | [Developer workflows](developer-workflows.md) |
| Init systems and distribution boot | [Init matrix](init-matrix.md) |
| Browser workload and sandbox evidence | [Browser fixtures](browser/README.md) |
| Kernel seccomp/ptrace controls | [Sandbox controls](sandbox-research.md) |
| Native namespace admission and restricted brokers | [Isolation controls](chromium-isolation.md) |
| Descriptor custody, publication and resource teardown | [Resource verification](../shroot/resource-tests.md) |

## Evidence Rules

- Record the APK/helper identity, image source, executor UID and firmware/kernel.
  A staged helper validates that helper, not APK packaging or installer delivery.
- Keep native controls, Shroot component tests and real-application workflows
  distinct. An exit code alone does not prove a rendered page, audible output,
  container connectivity or complete browser isolation.
- Wait for the exact operation's completion and cleanup. A deadline is a failure
  bound, not evidence of readiness. Retain bounded logs and reproducible inputs
  in test artifacts rather than adding each run to this guide.
- Run destructive or failure-injection cases in disposable stores. Preserve the
  user's active sessions and use the agreed display for graphical checks.
- Unsupported hardware, unavailable native authority and an implementation
  failure are different results. Do not weaken assertions or silently disable a
  client's sandbox to obtain a pass.

## Installer Acceptance

A disposable-library recipe test is not end-to-end installer acceptance. Before
a release, also exercise the ordinary user path with the packaged APK:

1. Open a MagicDesk Shell console and download the maintained installer.
2. Use the default environment library, without a test-only
   `MAGICDESK_GUEST_HOME` override or staged helper bundle.
3. Exercise interactive configuration, DNS repair/cancellation before image
   work, and package-setup retry in the same environment after a resolver
   failure. Use a new independent environment name and retain an incompatible
   cached image to verify format-aware import without deleting existing stores.
4. Refresh Apps, find the installed application and whole-desktop entries in
   Start, and launch them without manually creating shortcuts.
5. Verify the selected protocol, usable content/input and applicable audio/GPU
   services. Close and relaunch through the same discovered entry.
6. Exercise `--resume` without replacing user data or silently changing DNS.

Custom-library tests remain useful for isolation. Their entries are not
automatically registered in the Android default-library catalog. Test
`--gui apps` and a whole-desktop profile separately; installing application
packages does not verify a desktop-session launcher.

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
