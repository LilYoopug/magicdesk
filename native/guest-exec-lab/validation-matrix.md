# Shroot Distribution Validation Matrix

This is the per-distribution acceptance ledger, not a supported-applications list
or a claim that all tests are automated. Keep every distribution printed by
`sh scripts/install_linux.sh --list` in every table. Results do not transfer
between distributions sharing a package manager, libc or init system.

Last reconciled: 2026-10-23. Current device evidence uses NX809J, Android 16,
Linux 6.12.23, 4 KiB pages and Android shell UID 2000. This does not cover the
minimum supported kernel 5.15, other firmware or Android root execution.

## Reading Results

Each cell is **Shroot / Shroot Base**, with independent results:

| Code | Meaning |
| --- | --- |
| N | Not run; includes fixtures that still need implementation |
| P | Passed the named scenario in the recorded run, not necessarily the latest build |
| I | Incomplete: some assertions passed, but acceptance remains open |
| F | Observed failure; retain its reproduction until a qualifying rerun passes |
| B | Blocked by a named prerequisite; not a pass or proof of an application defect |
| H | Historical coverage only; current acceptance and exact entry-mode evidence need reconciliation |
| NA | Not applicable, with an explicit distribution/package/hardware reason |

An N in the Base position means there is no qualifying Base receipt here; it
does not assert that nobody has ever run that workflow. H is not a pass in that
entry mode. Do not infer NA from a distribution's init choice or an unattempted
package install. Record unavailable distribution packages separately from a
Shroot implementation failure; do not silently substitute another userspace.

Missing workload packages or dependencies (for example Podman or aardvark-dns)
must not add source-build fallbacks to `install_linux.sh`. Lab-only source builds
may test Shroot compatibility, but their receipts must identify the upstream
version, provenance and locally built components. Such a pass does not establish
availability from that distribution's repositories or the installer. The
explicit Turnip build remains a separate graphics recipe, not a general license
to compile missing applications during installation.

P applies only to the native hashes, package versions and configuration in its
receipt. Staged native builds do not certify the installed APK. Rerun affected
cells after common runtime changes; do not promote older receipts to the new
build or use aggregate unit-test success as application acceptance.

## Installation And Init

Recipe setup covers the maintained installer and package/graphics preparation,
not Start discovery or GUI acceptance. PID 1 uses the distribution's own manager:
systemd, Alpine OpenRC, or Void/Armtix runit. Focused service tests and default
boot remain different assertions. Turnip requires rendered/read-back pixels,
not just a completed Mesa build or successful device enumeration.

| Recipe ID | Recipe setup | Package lifecycle | PID 1 boot | Service lifecycle | Turnip rendering |
| --- | --- | --- | --- | --- | --- |
| debian | P/N | I/N | P/N | P/N | I/N |
| ubuntu | H/N | H/N | H/N | H/N | I/N |
| alpine | P/N | I/N | I/N | I/N | I/N |
| fedora | P/N | P/N | P/N | P/N | P/N |
| arch | P/N | P/N | P/N | P/N | I/N |
| opensuse | P/N | I/N | P/N | P/N | N/N |
| openkylin | P/N | P/N | P/N | H/N | N/N |
| deepin | P/N | N/N | F/N | H/N | N/N |
| manjaro | P/N | N/N | H/N | H/N | N/N |
| void | P/N | N/N | P/N | P/N | I/N |
| armtix | P/N | P/N | F/N | P/N | N/N |
| steamos | H/N | H/N | H/N | H/N | H/N |

Package lifecycle means install, update/reinstall, verification and removal,
including transaction hooks. A zero package-manager exit with failed hooks is
not a pass. Historical SteamOS default boot remains degraded; H must not be
read as a healthy default target. See [init contracts and limits](init-matrix.md).

## Containers And Virtual Machines

Docker and Podman require bridge networking, published TCP/UDP, local outbound
traffic, peer IP/name resolution, binds, exec, port conflicts and released ports.
Record external DNS/internet separately from deterministic local peers. Keep
Docker nftables/no-userland-proxy and its older proxy profile distinct in the
receipt; a pass in one does not cover the other.

Libvirt requires a real managed QEMU guest, not just daemon readiness or
`virsh list`: define, start, serial output, pause/resume, shutdown and undefine.
QEMU's column is the direct TCG kernel/initrd boot and clean-exit scenario.
VM networking, firmware boot, disk persistence and KVM require separate checks;
neither a TCG pass nor guest `/dev/kvm` absence establishes host KVM availability.

| Recipe ID | Docker | Podman | Libvirt + QEMU | QEMU TCG boot |
| --- | --- | --- | --- | --- |
| debian | P/N | P/N | P/N | P/N |
| ubuntu | P/N | P/N | N/N | N/N |
| alpine | P/N | P/N | N/N | N/N |
| fedora | P/N | P/N | P/N | P/N |
| arch | P/N | P/N | P/N | P/N |
| opensuse | P/N | P/N | P/N | P/N |
| openkylin | P/N | P/N | P/N | P/N |
| deepin | P/N | P/N | P/N | P/N |
| manjaro | P/N | P/N | P/N | P/N |
| void | P/N | P/N | P/N | P/N |
| armtix | P/N | P/N | P/N | P/N |
| steamos | H/N | P/N | N/N | N/N |

## Packaged Browsers And Portals

Every browser cell includes its packaging runtime: Flatpak/bubblewrap or
snapd/snap-confine, install/update, ordinary-user launch, original sandbox,
input, page rendering, download and normal close/relaunch. Record hardware
composition/WebGL and crashes, not only a renderer string. Portal acceptance
also needs file selection/readback, document grants, FUSE lifetime and cleanup.
Record the packaging backend for each portal result; a Flatpak result does not
certify Snap. Snap's documented degraded mode is not AppArmor enforcement.

| Recipe ID | Flatpak Chromium | Flatpak Firefox | Snap Chromium | Snap Firefox | Document portal |
| --- | --- | --- | --- | --- | --- |
| debian | I/N | N/N | N/N | N/N | I/N |
| ubuntu | N/N | N/N | I/N | H/N | H/N |
| alpine | N/N | N/N | N/N | N/N | N/N |
| fedora | N/N | I/N | N/N | N/N | I/N |
| arch | N/N | N/N | N/N | N/N | N/N |
| opensuse | N/N | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N | N/N |
| void | P/N | P/N | N/N | N/N | P/N |
| armtix | P/N | P/N | N/N | N/N | P/N |
| steamos | H/N | H/N | N/N | N/N | H/N |

## Desktop And Development

Desktop acceptance includes recipe launch/discovery, input, ordinary clients,
close/reopen and owned-process cleanup. VS Code includes editor/save, external
file changes, integrated terminal, debugger, reload, sandbox and GPU checks.
Distribution-packaged browsers are separate from their Flatpak/Snap versions.
Audio needs audible continuity under load; counters alone are insufficient.
Gamepads need real buttons, axes and reconnect. Steam login is not gameplay.

| Recipe ID | Desktop | Native Chromium | Native Firefox | VS Code | Audio | Gamepad | Steam/game |
| --- | --- | --- | --- | --- | --- | --- | --- |
| debian | I/N | N/N | N/N | I/N | N/N | N/N | N/N |
| ubuntu | I/N | N/N | N/N | H/N | N/N | N/N | N/N |
| alpine | I/N | F/N | N/N | N/N | N/N | N/N | N/N |
| fedora | I/N | N/N | N/N | I/N | N/N | N/N | N/N |
| arch | I/N | N/N | N/N | N/N | N/N | N/N | N/N |
| opensuse | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| void | I/N | N/N | N/N | P/N | N/N | N/N | N/N |
| armtix | I/N | N/N | N/N | P/N | N/N | N/N | N/N |
| steamos | H/N | N/N | N/N | H/N | H/N | H/N | H/N |

Preserve separate application/package versions in the receipt.
Historical Fedora GNOME devkit/llvmpipe coverage does not certify GDM or hardware
composition. Current Fedora Weston coverage is listed below. See [desktop workflows](desktop-workflows.md) and
[stock-libc acceptance](svc-rewriting.md#desktop-and-container-acceptance).

## Added System Workloads

Implement and validate in this order: **nspawn -> BuildKit -> LXC**. Run the
small LTP selection alongside common runtime changes. A package installation
alone does not satisfy a workload. The machinectl column identifies the outer
OS owning machined and the stock nspawn unit; record the nested OS separately.

| Recipe ID | nspawn command | machinectl boot/lifecycle | BuildKit | LXC | LTP core |
| --- | --- | --- | --- | --- | --- |
| debian | N/N | P/N | N/N | N/N | N/N |
| ubuntu | N/N | N/N | N/N | N/N | N/N |
| alpine | N/N | N/N | N/N | N/N | N/N |
| fedora | N/N | P/N | P/N | P/N | I/N |
| arch | I/N | P/N | P/N | P/N | N/N |
| opensuse | N/N | P/N | P/N | P/N | I/N |
| openkylin | N/N | P/P | P/N | P/N | P/P |
| deepin | N/N | P/N | P/N | P/N | P/N |
| manjaro | N/N | P/N | P/N | P/N | P/N |
| void | N/N | N/N | P/N | P/N | P/N |
| armtix | N/N | N/N | P/N | P/N | P/N |
| steamos | N/N | N/N | N/N | N/N | N/N |

### Workload Contracts

- [nspawn](https://www.freedesktop.org/software/systemd/man/latest/systemd-nspawn.html):
  boot a nested distribution, use machinectl shell/service lifecycle, check
  private PID/mount/user namespaces and `/dev`/`/proc`, bind permissions, veth
  bridge networking and TCP/UDP publication. Keep command-only nspawn separate
  from the machinectl/systemd service workflow; do not replace OpenRC/runit
  merely to mark a distribution as passed.
- [BuildKit](https://github.com/moby/buildkit): build a multistage image, run
  parallel steps, verify cache reuse and invalidation, cache/secret mounts,
  exported-image execution, cancellation and cleanup. Keep OCI and containerd
  workers and guest-root/rootless configurations as separate subcases.
- [LXC](https://linuxcontainers.org/lxc/introduction/): create/start a container,
  attach/exec, verify credentials, mounts, `/dev`/`/proc`, cgroup interactions,
  original seccomp policy, bridge connectivity, restart, shutdown and destroy.
  Privileged/unprivileged refers to guest credentials, never Android elevation.
- For all three, exercise abnormal termination and repeat the same scenario.
  Verify no owned processes, mounts, sockets or reservations remain. Record
  exact missing operations; do not replace bridge with host networking, disable
  application protections, or report permissive cgroups as resource enforcement.

### Permanent LTP Selection

Start with these seven upstream test binaries, not the complete `syscalls`
suite. Pin and review the upstream source and harness before the first run;
record the revision and compiled hashes. Re-review before updating that pin.
Upstream supports [individual test execution](https://linux-test-project.readthedocs.io/en/latest/users/quick_start.html#running-single-tests).

Current reviewed pin: LTP `20250930`, commit
`d2550ffbbcfe163212cd7e9c132db65ae0fa06ed`. The official
`ltp-full-20250930.tar.xz` SHA-256 is
`048fa4d69ddbe8a94aa15da9bdc85713ab07a0abbc3de2b8bdd9757644aef1e4`.
Build only `lib/libltp.a` and the seven targets below with the distribution's
compiler. `test_booted_ltp.py` runs each once as the specified ordinary guest
user in a disposable working directory, records source/library/binary hashes,
and preserves every upstream status. Its 45-second outer failure bound kills
only that test's process group; it does not enable stress-loop options.

| Test | Initial contract |
| --- | --- |
| `dup01` | Duplicated descriptor refers to the same inode |
| `dup201` | Invalid dup2 descriptors return EBADF |
| `openat01` | Relative/absolute paths, directory FDs and error returns |
| `pipe01` | Pipe data write/readback and descriptor cleanup |
| `epoll_create1_01` | Native epoll creation, CLOEXEC policy and close on the ARM64 syscall ABI |
| `sigprocmask01` | Block, observe pending signal, unblock and deliver |
| `getuid01` | Basic guest UID syscall result; not full credential isolation |

Run bounded single iterations in test-only stores as an ordinary guest user,
with disposable temporary directories and inherited host limits. Do not expose
Android block devices, writable host proc/sys/sysfs or unrelated directories.
Exclude filesystem formatting, host-wide sysctls, time changes, module loading,
reboots and unbounded resource exhaustion. Mount/xattr and deeper
namespace/credential suites need separately reviewed fixtures; existing Shroot
tests retain that coverage and are not replaced by this small selection.

Retain every upstream subtest and status: TCONF/skip is uncovered, TBROK is a
broken run, and neither is a pass. Keep warnings and cleanup failures visible.
Compare failures with the same binaries and fixtures on a real Linux control
(a disposable VM is acceptable); native Android and Shroot Base alone are not
oracles for complete Linux behavior.

## Evidence And Open Work

This ledger retains current acceptance evidence and unresolved blockers, not
the history of repaired defects. Replace a failed status after a qualifying
rerun and remove its resolved explanation. Regression coverage belongs in the
tests. Local report paths identify evidence, not durable public downloads.

| Scenario | Current evidence and remaining scope |
| --- | --- |
| Fedora recipe and packages | `build/installer-fedora-turnip.json`; official Fedora 44 OCI rootfs, ordinary user `mdtester`, Weston, recipe-built Mesa 26.2.3 Turnip. `build/fedora-packages-lifecycle.log` and `build/fedora-packages-remove.log` cover hello install/execute/reinstall/RPM verification/removal. Full desktop acceptance remains open |
| openSUSE recipe | `build/installer-opensuse-turnip.json`; official Tumbleweed LXC rootfs authenticated with its official SHA-256 sidecar, Weston, ordinary user and Mesa 26.2.3 Turnip build. Repeated recipe preserves user data. `build/opensuse-matrix-packages.log` covers installation/transaction hooks of the container packages; full removal/verification lifecycle and rendering remain open |
| openSUSE default boot | `build/opensuse-turnip-boot-groups/oci-services-d99f06af17f14b7a970d023b7c497a5d.json`; staged runtime, systemd 261.4 reaches running with zero failed units, D-Bus/logind and service IO/restart pass. The IPv4 fabric still rejects IPv6 address creation explicitly; this is not IPv6 networking coverage. The installed APK has not yet received this runtime |
| Booted openSUSE Docker/Podman | `build/installed-opensuse-turnip/oci-services-ae2ce33f41dc44f8b4d7d23d523c607a.json` (Docker, stock service and package-selected iptables nft backend) and `oci-services-c72742a3e70140e5b3f9f2e92cd48c42.json` (Podman). Stock seccomp/cgroups, overlay, bridge, TCP/UDP publication, peer IP/names, binds/exec, conflicts/release and external internet/DNS pass |
| openSUSE LXC | `build/installed-opensuse-turnip/oci-services-0bd9e1a8a6c94796a9600e25b180fc63.json`; LXC 7.0, stock common policy and seccomp, nested Debian, attach/services, mounts, bridge TCP/UDP and cleanup across three normal/forced-stop boots. Unprivileged LXC and external networking remain untested |
| openSUSE direct QEMU | `build/installed-opensuse-turnip/oci-services-b19a889ea5dc40ed99625533bbd52277.json`; ARM64 kernel/initrd TCG boot, serial output and clean exit. Libvirt, KVM and VM networking are separate acceptance requirements |
| openSUSE machinectl | `build/installed-opensuse-turnip/oci-services-c70969796db44d2c867911b3c3802fd9.json`; stock systemd 261.4 unit, nested Debian, private users/veth, shell/services, bridge TCP/UDP and normal/forced-stop cleanup across three boots. Initial cold ownership preparation previously exceeded the fixture startup bound; cold preparation timing remains open |
| openSUSE Libvirt/QEMU | `build/installed-opensuse-turnip/oci-services-3b2fea5ded59481eb5b2e485418f9ce0.json`; stock libvirt 12.8.0 modular daemon and QEMU 11.1.2, define/start paused, serial, resume, kernel/initrd TCG boot, shutdown/undefine and cleanup. KVM and VM networking remain untested |
| openSUSE BuildKit | `build/installed-opensuse-turnip/oci-services-274c55493b534bf188cdbab1076e4f18.json`; official BuildKit 0.34.1 with distribution CNI 1.6.2, OCI sandbox and overlayfs. Multistage/cache/secret/export/run/cancel/cleanup pass; rootless/containerd workers and external networking untested |
| openSUSE LTP core | `build/installed-opensuse-turnip/oci-services-ba129bf7dcf0488c99bc7363fe7b7cca.json`; reviewed LTP 20250930 built with the distribution compiler/libc, guest UID 1000. Six binaries pass fully; `epoll_create01` retains two libc passes and ARM64 legacy-ABI TCONF, with no failed/broken checks |
| openKylin recipe/default boot | `build/installer-openkylin-turnip.json`; official openKylin 3.0 image, Weston, Turnip build, ordinary user and repeated recipe preserve settings/data. `build/openkylin-turnip-boot-rebind/oci-services-d2318cf7d61d469ca752cbf7fa907950.json` covers the stock default target with device-bound LXC DHCP |
| openKylin package lifecycle | `build/openkylin-package-lifecycle.log` and `build/openkylin-package-lifecycle-runtime.json`; repository hello 2.12.1-ok2 install, execution, reinstall, dpkg verification, independent file checksums and removal pass. `dpkg --audit` remains empty |
| Deepin recipe | `build/installer-deepin-turnip.log`, `build/installer-deepin-turnip.json`; official `linuxdeepin/deepin:crimson-arm64`, Weston, Mesa 26.2.3 Turnip build, locale, timezone, ordinary user and repeated recipe preserving settings/data. GUI/rendering acceptance remains open |
| Deepin default boot | `build/deepin-turnip-boot-admission/oci-services-fc95765b510c4d34a187f5826ab2b67a.json`; default target completes degraded: stock lxc-net requires IPv6, which the managed fabric does not yet implement |
| Deepin Docker | `build/installed-deepin-turnip/oci-services-b93c57b350bb452aba9a1c479e6d2e26.json`; stock Docker 26.1.5 service and separately packaged docker-cli. Overlay2, private cgroups, bridge, published TCP/UDP, peer DNS/IP, outbound internet, conflicts and released ports pass |
| Deepin Podman | `build/installed-deepin-turnip/oci-services-56c25421de50480eb9fc4b438aef0b70.json`; stock Podman/netavark plus upstream aardvark-dns 1.12.2 built locally because this repository omits its package. Original seccomp/cgroups, overlay, bridge, TCP/UDP, peer DNS/IP, repeated exec, internet and cleanup pass |
| Deepin QEMU | `build/installed-deepin-turnip/oci-services-90209b9194ce49119a03ece9bdba0d52.json`; stock QEMU 8.2 TCG boots the ARM64 kernel/initrd, serial output and normal poweroff pass |
| Deepin Libvirt/QEMU | `build/installed-deepin-turnip/oci-services-7af66e7aa810446eb66f779ebfdb4a6e.json`; stock libvirt service, managed TCG boot, pause/resume, serial output, shutdown/undefine and cleanup pass. VM networking and KVM remain untested |
| Deepin machinectl | `build/installed-deepin-turnip/oci-services-4cde4f1175d241b7a13aec1c9e5fecf4.json`; stock unit, nested Debian, private users/veth, shell/services, TCP/UDP and normal/forced-stop cleanup across three boots pass |
| Deepin BuildKit | `build/installed-deepin-turnip/oci-services-7aa8227fcb9848c1a8bccc1d979df520.json`; upstream 0.34.1, OCI/CNI, multistage/cache/secret/export, Podman execution and cleanup pass |
| Deepin LTP core | `build/installed-deepin-turnip/oci-services-fb794ebaaa514526a13ea5dbe2d0c804.json`; all seven pinned upstream binaries pass as UID 1000, including the ARM64 epoll_create1 ABI, with no FAIL/BROK/TCONF |
| Deepin LXC | `build/installed-deepin-turnip/oci-services-d57165f8b91c484b934633f5e8e267dd.json`; LXC 6.0.1, stock policy/seccomp, nested Debian, attach/services, mounts, bridge TCP/UDP and normal/forced-stop cleanup across three boots pass. Unprivileged containers and external networking remain untested |
| Manjaro recipe | `build/installer-manjaro-turnip.json`; official ARM64 rootfs, Weston, Turnip, locale/timezone, ordinary user and resume preserving data. Runtime and GUI acceptance remain open |
| Manjaro Docker | `build/installed-manjaro-turnip/oci-services-6f4a619b107d4dff981ab331894f4896.json`; Docker 25.0.2 service, nft provider, bridge, TCP/UDP publication, peer DNS/IP, external internet and port cleanup pass |
| Manjaro Podman | `build/installed-manjaro-turnip/oci-services-348c9ab4bbf94162a1ba394236943a92.json`; Podman 4.9.3/netavark 1.10.3, stock sandbox/cgroups, bridge, TCP/UDP publication, peer DNS/IP, external DNS/HTTP, conflicts and port cleanup pass |
| Manjaro machinectl | `build/installed-manjaro-turnip/oci-services-d82aa306a5c2430d82733f4136c0664a.json`; three nested Debian boots, private users/veth, shell/services, TCP/UDP, normal/forced-stop cleanup pass |
| Manjaro Libvirt/QEMU | `build/installed-manjaro-turnip/oci-services-8043c944dec94dfda5da29608239481d.json`; libvirt 10.0/QEMU 8.2.1 managed TCG boot, serial, pause/resume, shutdown and undefine pass. `oci-services-ccd1b94e30fd4071ac13578e16f2591d.json` covers direct TCG boot; VM networking/KVM remain untested |
| Manjaro LXC | `build/installed-manjaro-turnip/oci-services-8be5cba3f33b4311993623f26cd2c472.json`; LXC 5.0.3 stock sandbox, nested Debian boot, attach/services, mounts, bridge TCP/UDP and three normal/forced-stop lifecycle rounds pass |
| Manjaro LTP core | `build/installed-manjaro-turnip/oci-services-e8b36eb8d1994b1e9b7c5629e6df34a9.json`; seven pinned upstream binaries built in Manjaro pass as UID 1000, with no FAIL/BROK/TCONF |
| Manjaro BuildKit | `build/installed-manjaro-turnip/oci-services-ae8be0b1b75f42388079823bf6ae351c.json`; packaged BuildKit 0.12.2 with CNI, stock OCI sandbox, multistage/cache/secret/export, Podman execution, cancellation and cleanup pass |
| Void recipe | `build/installer-void-turnip.json`; official ARM64 glibc rootfs, Weston, Turnip, ordinary user and resume preserving data. Full recipe discovery and desktop lifecycle acceptance remain open |
| Void default boot | `build/void-default-runit-current/oci-services-1c7cc9a615c84b24b1466ab42040ed5d.json`; stock runit stages and default services, restart with a new service PID, and owned-process cleanup pass |
| Void Docker | `build/installed-void-turnip/oci-services-1913fb5f08494da79807691ad344479c.json`; stock runit service, Docker 29.8.0, containerd 2.3.2 and runc 1.5.2. Bridge TCP/UDP publication, peer DNS/IP, binds/exec, external internet, conflicts and port cleanup pass |
| Void Podman | `build/installed-void-turnip/oci-services-fa8ed9fad7d24073b2ff228139de092d.json`; Podman 6.1.4, stock sandbox/cgroups, bridge, published TCP/UDP, peer DNS/IP, external internet, conflicts and port cleanup pass |
| Void QEMU | `build/installed-void-turnip/oci-services-74ca18689b564fe3ab2818bbf91dc475.json`; packaged QEMU 11.1.2, ARM64 kernel/initramfs TCG boot, serial output and normal poweroff pass |
| Void Libvirt/QEMU | `build/installed-void-turnip/oci-services-23e06f44c5874105be2faf7ad425f559.json`; packaged libvirt 12.8.0 under runit, managed ARM64 TCG boot, serial, pause/resume, poweroff and undefine pass after emulator capability discovery. Cold all-architecture discovery latency and VM networking remain open |
| Void BuildKit | `build/installed-void-turnip/oci-services-7cdb929590b54750affb9ffda1b47c7d.json`; official 0.34.1 under runit with packaged CNI, OCI sandbox, multistage/cache/secret/export, Podman execution, cancellation and cleanup pass |
| Void LXC | `build/installed-void-turnip/oci-services-c41e1d2807144c899cf9c4c3e4a5ed84.json`; packaged LXC, nested Debian, stock seccomp, attach/services, bridge TCP/UDP and three normal/forced-stop lifecycle rounds pass |
| Void LTP core | `build/installed-void-turnip/oci-services-ec75bc0dbf564555be5d82ce0d0bdd52.json`; seven pinned upstream binaries built with Void's compiler/libc pass as UID 1000, with no FAIL/BROK/TCONF |
| Void Flatpak browsers | `build/installed-void-turnip/void-firefox-gui/gui-report.json`, `void-chromium-gui/gui-report.json` and the corresponding `void-firefox-reopen`/`void-chromium-reopen` reports; original Flatpak sandboxes, keyboard/pointer, download, chooser/readback, WebGL pixels, normal close and same-profile relaunch pass. `build/void-flatpak-update-current.log` records successful stock update checks. Chromium renders through ANGLE/Zink/Turnip |
| Void portal | `build/installed-void-turnip/void-portal-lifecycle.json`; ordinary-user document export, live sandbox read/write, revocation denial and export cleanup pass. Two SIGTERM/D-Bus-reactivation rounds remove the document FUSE mount; GUI chooser/readback is covered by both browser reports |
| Void VS Code | `build/installed-void-turnip/void-vscode-sandbox-fixed/gui-report.json`; VS Code 1.140.0, cpptools 1.34.4 and distribution GDB 18.1: editor/save, external file events, integrated terminal, reload, breakpoint, step, normal close and hardware composition pass. The live renderer has UID 1000, NoNewPrivs=1 and Seccomp=2. The exact fixture then stops its launch, graphics and display without changing HOME; full recipe desktop discovery remains separate |
| Armtix package lifecycle | `build/installed-armtix-turnip/d36117e964b34fc49e9a1611bacd35a8.log` records successful mkinitcpio reinstall and all four stock initramfs hooks; its subsequent unavailable `hello` query is not acceptance. `0552cfd0fb3c493fabb64c8892bfd5bf.log` covers the available repository package `tree`: install, execution, reinstall, package-file verification and removal. No workload source build is added to the recipe |
| Armtix default boot | `build/armtix-boot-final/oci-services-de2bda2b57944655b082fcf9f843e420.json`; stock runit reaches stage 2 and service start/restart/stop pass, but startup still reports unsupported persistent-root read-only reconfiguration and missing binfmt_misc. Overall boot remains F; reaching the desktop does not certify a healthy default boot |
| Armtix Docker | `build/installed-armtix-turnip/oci-services-421f9571fce94263acf95d0231e6d441.json`; stock runit Docker 29.9.1, containerd 2.4.2 and runc 1.5.2, named legacy cgroup membership, default overlayfs snapshotter and package-selected nft frontend. Bridge TCP/UDP publication, peer DNS/IP, binds/exec, external DNS/internet, conflicts and port cleanup pass |
| Armtix Podman | `build/installed-armtix-turnip/oci-services-e379d8ce233d490db3006d4754301aaa.json`; stock sandbox/cgroups, bridge, TCP/UDP publication, peer DNS/IP, external internet and cleanup pass |
| Armtix Libvirt/QEMU | `build/installed-armtix-turnip/oci-services-bffac31b93ae4d60baf272173671f6ec.json`; packaged runit libvirtd/virtlogd/virtlockd, managed TCG kernel/initrd boot, serial output, pause/resume, poweroff and undefine pass. `build/armtix-qemu-current.log` records direct TCG boot. VM networking and KVM remain untested |
| Armtix BuildKit | `build/installed-armtix-turnip/oci-services-1be91d4c029440b99da82bf66c9711fb.json`; official 0.34.1 archive and packaged CNI under runit, OCI/overlayfs sandbox, multistage/cache/secret/export, Podman execution, cancellation and cleanup pass |
| Armtix LXC | `build/installed-armtix-turnip/oci-services-f4a278d4280045e59e53506a9c601e69.json`; packaged LXC, nested Debian, stock seccomp, attach/services, bridge TCP/UDP and three normal/forced-stop lifecycle rounds pass |
| Armtix LTP core | `build/installed-armtix-turnip/oci-services-c42605e1c1114363924976170920b1ba.json`; all seven pinned LTP 20250930 binaries built with the distribution compiler/libc pass as UID 1000, with no FAIL/BROK/TCONF |
| Armtix VS Code | `build/installed-armtix-turnip/armtix-vscode-gui/gui-report.json`; VS Code 1.140.0, cpptools 1.34.4 and distribution GDB 18.1: editor/save, external file events, integrated terminal, reload, breakpoint, step, normal close and hardware composition pass. The live renderer has UID 1001, NoNewPrivs=1 and Seccomp=2. Full recipe desktop discovery and close/reopen remain separate |
| Armtix Flatpak browsers | `build/installed-armtix-turnip/armtix-firefox-gui/gui-report.json`, `armtix-chromium-gui/gui-report.json` and the corresponding `armtix-firefox-reopen`/`armtix-chromium-reopen` reports; Firefox 158.0.1 and Chromium 156.0.8078.47, original sandboxes, keyboard/pointer, download, chooser/readback, WebGL pixels, normal close and same-profile relaunch pass. Chromium uses ANGLE/Zink/Turnip. These tests explicitly built Mesa for SDK 25.08 because the host libraries require a newer ABI; the automatic recipe does not perform this second build. `build/armtix-flatpak-update-verified.log` covers the stock update check |
| Armtix portal | `build/installed-armtix-turnip/armtix-portal-lifecycle.json`; UID 1001, two document export/read/write/revoke and SIGTERM/reactivation rounds pass, with FUSE mount removal. Both browser reports cover GUI chooser/readback. `build/armtix-browser-complete-stop.log` records normal fixture cleanup without changing HOME |
| openKylin Podman | `build/installed-openkylin-turnip/oci-services-b3d2149b5330452fad8dba528907340f.json`; Podman 5.7.0, stock seccomp/cgroups, overlay, nftables bridge, published TCP/UDP, peer DNS/IP, internet, conflicts and released ports pass |
| openKylin Docker | `build/installed-openkylin-turnip/oci-services-97097511bae241668089a38eefb47f06.json`; official Docker service with vendor `/opt/system` command path. Overlay, bridge, TCP/UDP publication, peer DNS/IP, external internet, conflicts and released ports pass |
| openKylin Libvirt/QEMU | `build/installed-openkylin-turnip/oci-services-7294486ccd24434085e40df5ddc75622.json`; libvirt 12.0/QEMU 10.2.1, managed ARM64 TCG boot, pause/resume, serial, poweroff and undefine pass. `oci-services-8ec6d36797154166a9eb8c40c0882459.json` covers direct QEMU boot. VM networking remains untested |
| openKylin BuildKit | `build/installed-openkylin-turnip/oci-services-7e09f6f7835642b991ca30a1f6b69952.json`; official BuildKit 0.34.1, OCI/overlayfs/CNI worker, multistage build, cache, secrets, export, Podman execution, cancellation and cleanup pass |
| openKylin machinectl | `build/installed-openkylin-turnip/oci-services-2fd17eb1579d4d67a8bdd902436a8f6b.json` (Shroot) and `oci-services-12f6221ee8f64ac99967cf47b9eb7a0a.json` (Base); stock unit, nested Debian, private users/veth, shell/services, TCP/UDP and normal/forced-stop cleanup pass across three boots in each mode on the final staged runtime. Two preceding three-boot Shroot runs also passed; timeout bounds and unit policy are unchanged |
| openKylin LTP core | `build/installed-openkylin-turnip/oci-services-15047b71876e45ecba1c15582415ce0c.json` (Shroot) and `oci-services-6bbf78520ce848ea8abef45a2766aa5a.json` (Base); seven pinned upstream binaries built with this distribution's compiler/libc pass as UID 1000 in both modes, including the ARM64 epoll_create1 ABI, with no FAIL/BROK/TCONF |
| openKylin LXC | `build/installed-openkylin-turnip/oci-services-657d92e0fd5d4f67b9482a2a415f921d.json`; packaged LXC 6.0.6, nested Debian, stock common policy/seccomp, attach/services, mounts, bridge TCP/UDP and cleanup pass across three normal/forced-stop boots. Unprivileged LXC and external networking remain untested |
| Fedora Flatpak Firefox | `build/installed-fedora-turnip/firefox-sdk-gui/gui-report.json`, `build/fedora-firefox-sdk-gui.log`; Firefox 158.0.1 with matching SDK-built Mesa, ordinary sandbox and normal vsync: window, keyboard/pointer, download, GUI file selection/readback, WebGL pixels and normal close pass. Normal relaunch and desktop teardown remain open |
| Fedora default boot/services | `build/fedora-turnip-boot/oci-services-1dc2ebfb62a84574b3bb354baca3ae55.json`; systemd 259.10, private bridge, default target running with no failed units, journal sync/readback, D-Bus/logind and RTKit lifecycle. `build/fedora-hostnamed-fixed.log` additionally covers hostnamectl on a later staged runtime |
| Booted Fedora Docker | `build/installed-fedora-turnip/oci-services-3623ddaba2db47959b1355be3c64c8fd.json`; stock Docker 29.8.2 service, containerd 2.3.5 overlayfs snapshotter, runc 1.5.2 and recipe-selected iptables-nft frontend. Cold image pull, IPv4 bridge, TCP/UDP publication, peer IP/names, binds/exec, conflicts/release and internet with 20 external DNS queries per container pass; native Docker nftables backend and IPv6 are not covered |
| Booted Fedora Podman | `build/installed-fedora-turnip/oci-services-d595dbe5ff9a4ac3b9b8b5813002e719.json`; stock seccomp, enabled cgroups, overlay and bridge. TCP/UDP publication, local outbound, peer IP/names, binds/repeated exec, conflicts/release and internet with 20 external DNS queries per container pass |
| Fedora desktop/VS Code | `build/installed-fedora-turnip/desktop.png` and `vscode/gui-report.json`; Weston/user systemd session and VS Code 1.140.0 editor/save, external watcher, PTY, GDB breakpoint/step and window reload pass. GPU, recipe discovery, close/reopen and full desktop cleanup acceptance remain open |
| Fedora Turnip | `build/fedora-gbm-pixels.log`; recipe-built Mesa 26.2.3, GBM/EGL import, Zink/Turnip on Adreno 840, 64 exact alternating frames and real DMA-BUF fences. This does not certify a Flatpak/Snap driver bundle |
| Fedora Flatpak portal | `build/fedora-flatpak-portal.log`; ordinary user export, read/write through the live sandbox and immediate revocation pass. GUI chooser and portal shutdown/FUSE cleanup acceptance remain open |
| clone3 contract | `build/shroot-image-tests/oci-services-142abe4139bd4065a4d1285b6b225118.json`; native control plus Base/lazy fork, thread/TLS, vfork, TIDs/pidfd, signal masks/dispositions and seccomp; versioned read-only arguments at a guard page, admission errors, guest logical PID selection, cgroup placement, protected callers and rollback. This does not replace per-distribution application acceptance |
| Fedora machinectl | `build/installed-fedora-turnip/oci-services-e142c29e233748c1ac0a1fce4b6ca844.json`; stock systemd 259.10 unit boots nested Debian with private users/veth, shell/services, 20 TCP and 20 UDP exchanges per round, poweroff, killed-leader restart and cleanup across three boots |
| Fedora LXC | `build/installed-fedora-turnip/oci-services-1bd1e23d9f4540e8883cf69a6fc99e44.json`; LXC 6.0.6, stock common policy/seccomp, guest-root nested Debian, attach/services, mounts, 20 TCP and 20 UDP bridge exchanges per round, normal/forced stop and cleanup across three boots. Unprivileged LXC and external networking remain untested |
| Fedora Libvirt/QEMU | `build/installed-fedora-turnip/oci-services-cd9846bbd3e24577b18ee08ad5342b2e.json`; stock modular libvirt 12.0.0 and QEMU 10.2.2, define/start paused, serial, resume, real kernel/initrd TCG boot, poweroff/undefine and fixture cleanup. VM networking and KVM untested |
| Fedora direct QEMU | `build/installed-fedora-turnip/oci-services-df0485453492407c98ccc883ccf88508.json`; QEMU 10.2.2, ARM64 kernel/initramfs serial boot and clean exit with TCG. KVM and VM networking are not covered |
| Fedora BuildKit | `build/installed-fedora-turnip/oci-services-08b8e9442b0544c99e0ad3971addc562.json`; official BuildKit 0.34.1 ARM64 archive SHA-256 `c8c97b84baf89dfe0ea85063ac24ad88eb909979ea476ce3ef9e8e11e60ebef8`, Fedora CNI 1.9.1, TOML-configured OCI/overlayfs/CNI worker with sandbox. Multistage/cache/secret/export/run/cancel/cleanup pass; rootless/containerd workers and external networking untested |
| Fedora LTP core | `build/installed-fedora-turnip/oci-services-4911f111f0124271b8ed88ec97db48f7.json`; reviewed 20250930 sources built with Fedora compiler/libc, guest UID 1000. Six complete binaries pass; `epoll_create01` has two libc passes and one TCONF for the absent ARM64 legacy `__NR_epoll_create` ABI. No failed/broken checks; partial coverage remains I, not P |
| Alpine recipe setup | `build/installer-alpine-turnip.json`, `build/installer-alpine-turnip-graphics.json`; official Alpine 3.23.6 minirootfs, OpenRC, ordinary user `mdtester`, Weston and recipe-built Turnip 26.2.3. Package install/update passed; complete removal/hook lifecycle and default boot acceptance remain open |
| Booted Alpine Docker | `build/installed-alpine-turnip/oci-services-2d14d73fd3fc4136a8657f02c699749c.json`; Docker 29.5.2, containerd 2.2.0, runc 1.4, overlay, nftables/no userland proxy; bridge TCP/UDP, peer names, local outbound, binds/exec, port conflicts and release |
| Booted Alpine Podman | `build/installed-alpine-turnip/oci-services-53ce67cd91414e999b62de5d4724e954.json`; headless OpenRC, Podman 5.7.0, overlay, bridge with iptables frontend, stock seccomp and enabled cgroups; TCP/UDP, peer names, local outbound, binds/exec, conflicts and port release. Both containers pass internet access and 20 external DNS requests each |
| Alpine graphics | Retained fixture `40b1817740c04f168813229740d5435e`, command `7e065d9b179442fa887e1e3248747928`: Weston renders with Zink/Turnip on Adreno 840; packaged Chromium 149 renders a page but its GPU process receives SIGSEGV and WebGL is unavailable. Full input/download/portal acceptance and ordinary udev control ownership remain open |
| Booted Ubuntu containers | `build/installed-ubuntu-fuse/oci-services-f1b3c700b35d486a86254a0c5fa56278.json` (stock Docker service), `build/installed-ubuntu-fuse/oci-services-30c079114d4240b4bb0d70a16679bebe.json` (Podman, headless systemd/control target); staged native hashes in receipts. Bridge, published TCP/UDP, peer IP/name exchanges, binds/exec, conflicts and port release pass; both containers in each run also pass internet access and 20 external DNS requests each |
| Ubuntu cold Snap Chromium | `build/ubuntu-snap-captured-writes-clean/oci-services-77b29f4d93c645ce871c95c6014e4cfc.json`: three uninstrumented discarded-namespace confined-shell launches pass in 26.74/24.22/26.64 s, with CPU policy maxima 2.112/1.8624 GHz. Instrumented receipt `build/ubuntu-snap-captured-writes-profile/oci-services-028219ad597245049fbbfcdf0fae94dc.json` records 55,557 captured control writes and 5,433,244 main-supervisor ptrace requests. Changed CPU limits exclude a clean elapsed-time comparison with earlier builds. Stock 30 s helper deadline is unchanged; substantial margin remains open |
| Ubuntu Snap Chromium GUI | Retained native fixture `d225845a01ff43ae84ef648da865cafd`; `build/installed-ubuntu-fuse/chromium-refreshed-3/gui-report.json`: Chromium 155.0.8059.84 revision 3564 after successful stock `snap refresh` (change 105, log `3040cb6165054f57b0b499f8dd338247.log`). Guest UID 1000, stock sandbox and Wayland pass keyboard/pointer, download/chooser readback, normal close and WebGL pixels through ANGLE/Zink/Turnip on Adreno 840. Earlier revision 3560 also passed close/relaunch. Focused Weston/systemd fixture closes with graphics/display/HOME cleanup; this does not certify recipe discovery or document-portal grants |
| Ubuntu FUSE | `build/ubuntu-fuse-capture-wait/oci-services-391bc722a78e40a4962610b1c6d63c8a.json` and `build/ubuntu-fuse-capture-wait-close/oci-services-79a6826040174c54884fb96153bb7d51.json`; SquashFS hardlink exec/reexec, ORIGIN, set-ID/nosuid, vectored/partial IO, shared/private mapping races and filtered close/flush/FD-reuse checks pass. This is not document-portal GUI acceptance |
| Ubuntu default services | `build/ubuntu-matrix-cups-fixed/oci-services-684acee80f0b453ab5be6f3efcc6f74d.json`; PID 1 reaches its target, but CUPS readiness/restart and dockerd service failure require investigation; an active startup shell is not service readiness |
| SteamOS default boot | `build/steamos-matrix-default-boot/oci-services-a4815ff6455a46c8a5fa0538ec657f7e.json`; degraded boot, Deckard hardware services, resolver/firewall and tmpfiles descriptor failures need reconciliation with the recipe before application acceptance |
| Debian/Arch recipe setup | `build/installer-debian-turnip.json`, `build/installer-arch-turnip.json`, `build/installer-arch-turnip-render-only.log`; rendering/application acceptance remains open |
| Debian default boot/services | `build/debian-turnip-boot/oci-services-33ba076e37744211a82f0c348c8c5839.json`, `build/debian-turnip-systemd-fixed/oci-services-f7a091b709d84ad1ba282be55b888d6a.json` |
| Arch default boot/services | `build/arch-default-bridge-current/oci-services-3c014103a9cc4944beeb1999ff86627b.json`; private `bridge`, default target reaches `running`, journal write/sync/readback, D-Bus and logind restart pass; resolved is active. In `routed`, its initial-namespace bind to port 53 is also an Android publication and is denied by the host; this pass does not cover that mode |
| Booted Debian Docker | `build/installed-debian-turnip/oci-services-372c29b83a41433c967a53619048ae80.json`; 26.1.5, overlay2, iptables, no userland proxy, TCP/UDP/peer names/local outbound/port conflicts and release; external internet not revalidated |
| Booted Debian Podman | `build/installed-debian-turnip/oci-services-f472a602c8fd4b1b8114b5e72f13c459.json`; 5.4.2, overlay, bridge/nftables, stock seccomp, enabled cgroups, no `--ulimit` overrides; TCP/UDP/peer names/local outbound/binds/repeated exec/conflicts/port release; both containers pass internet access and 20 external DNS requests each |
| Booted SteamOS Podman | `build/installed-steamos/oci-services-0200184ae9e4442bab1a0e2ee7650fca.json`; 5.5.2, retained headless systemd/control target, overlay, bridge, stock seccomp, enabled cgroups, no `--ulimit` overrides; published TCP/UDP, peer names, local outbound, binds/exec, conflicts, port release and internet with 20 external DNS requests per container. This is not default-target or Plasma acceptance |
| Booted Arch Docker | `build/installed-arch-turnip/oci-services-f22142e8b86d445487808334efd9d370.json`; nftables, no userland proxy, local TCP/UDP/peers/port release; external internet not revalidated |
| Booted Arch Podman | `build/installed-arch-turnip/oci-services-77b349d3bd484dcea16079deba040c5e.json`; staged native hashes, overlay, bridge, stock seccomp, enabled cgroups, no `--ulimit` overrides; published TCP/UDP, peer names, local outbound, binds/exec, conflicts and port release; both containers also pass internet access and 20 external DNS requests each |
| Debian direct QEMU TCG | `build/debian-qemu-tcg/oci-services-c5ddb332933a4cb79cb23fff41767722.json`; kernel/initrd serial boot, not KVM or VM networking |
| Debian/Arch libvirt | `build/installed-debian-turnip/libvirt-report.json`, `build/installed-arch-turnip/libvirt-report.json` and adjacent `libvirt-serial.log`; stock daemon/device policy, explicit Cortex-A72 for the ARM64 kernel; VM networking and KVM untested |
| Arch direct QEMU | `build/installed-arch-turnip/oci-services-06fb45af690c4e56b16e4a1a071ff80f.json`; packaged QEMU, ARM64 kernel/initramfs TCG boot, serial kernel-contract checks and normal poweroff pass. VM networking and KVM remain untested |
| Arch package lifecycle | `build/arch-recipe-current/oci-services-4ba3363dd1b243988c709225b0366c19.json` covers current recipe setup, signed repository upgrade and tree installation. `build/arch-package-lifecycle-current.log` and `build/arch-package-lifecycle-runtime.json` cover booted stock pacman reinstall, all post-transaction hooks, mkinitcpio 42.2 image generation and independent repeat, file verification and removal. Hardware/firmware warnings remain visible; no failed hooks or generation errors |
| Arch machinectl | `build/installed-arch-turnip/oci-services-b79fc7c63c4b479ba5588b75e50d5d74.json`; stock systemd 262.1 unit boots nested Debian 257.13 with private users/veth, shell, services, 20 TCP + 20 UDP exchanges per round, poweroff, killed-leader restart and cleanup across three boots |
| Debian machinectl | `build/installed-debian-turnip/oci-services-8e78d11924a540428e278ebbcd479bd0.json`; stock systemd 257.13 unit, nested Debian 257.13, same three-boot shell/service/TCP/UDP/termination/cleanup contract as Arch |
| Arch BuildKit | `build/installed-arch-turnip/oci-services-ca28a04bd3254bd0955b70cd530c8247.json`; 0.34.1 OCI/overlayfs worker, CNI 1.9.1 bridge, sandbox mode, multistage build/cache/secret/export/run/cancel/cleanup, no explicit container ulimits; rootless/containerd workers and external network untested |
| Arch LXC | `build/installed-arch-turnip/oci-services-1bc60138c4034ba0b1cac9aca88fb310.json`; 7.0.0 stock common policy, guest-root container, nested Debian systemd 257.13, attach/services, devpts/proc/cgroup mounts, stock seccomp, 20 TCP + 20 UDP bridge exchanges per round, normal shutdown, forced stop and restart across three boots; process/veth/cgroup/root/bridge cleanup passes. Unprivileged LXC and external DNS/internet not covered |
| Debian Flatpak sandbox and portal | `build/unit-portal-verified.log`; Chromium's stock Flatpak sandbox reads/writes a granted document and loses access on revocation. UID 1000, two SIGTERM/D-Bus-reactivation rounds pass with exact process exit and FUSE mount removal. Browser rendering, GUI chooser/readback and GPU acceptance remain open |
| Debian VS Code | `build/installed-debian-turnip/vscode/gui-report.json`; editor/save, external watcher, PTY, debugger and reload pass; GPU/full desktop acceptance open |

Machinectl evidence does not cover nspawn command-mode bridge/publication or
external DNS. Nested shutdown reports `/tmp: not mounted` for a locked inherited
mount; retain that diagnostic without weakening mount restrictions.

Historical evidence remains in the [init matrix](init-matrix.md),
[desktop workflows](desktop-workflows.md) and
[SVC acceptance](svc-rewriting.md#desktop-and-container-acceptance). Reconcile
exact receipts and scope before replacing H with P.

Every receipt must identify recipe/source, installer configuration, package
versions, APK/native hashes, device/kernel/page size, Android/guest identities,
entry mode, command, assertions and cleanup. Keep backend choices and prerequisites
as subcases, not a single green result for an entire OS. Never publish retained
`session.json` files: they contain control tokens.
