# Shroot Distribution Validation Matrix

This is the per-distribution acceptance ledger, not a supported-applications list
or a claim that all tests are automated. Keep every distribution printed by
`sh scripts/install_linux.sh --list` in every table. Results do not transfer
between distributions sharing a package manager, libc or init system.

Last reconciled: 2026-10-22. Current device evidence uses NX809J, Android 16,
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
| ubuntu | H/N | H/N | H/N | H/N | H/N |
| alpine | H/N | H/N | H/N | H/N | N/N |
| fedora | H/N | H/N | H/N | H/N | N/N |
| arch | P/N | F/N | P/N | P/N | I/N |
| opensuse | N/N | N/N | H/N | H/N | N/N |
| openkylin | N/N | N/N | H/N | H/N | N/N |
| deepin | N/N | N/N | H/N | H/N | N/N |
| manjaro | N/N | N/N | H/N | H/N | N/N |
| void | N/N | N/N | H/N | H/N | N/N |
| armtix | N/N | H/N | H/N | H/N | N/N |
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
| ubuntu | H/N | H/N | N/N | N/N |
| alpine | N/N | N/N | N/N | N/N |
| fedora | N/N | N/N | N/N | N/N |
| arch | P/N | P/N | P/N | N/N |
| opensuse | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N |
| void | N/N | N/N | N/N | N/N |
| armtix | N/N | N/N | N/N | N/N |
| steamos | H/N | H/N | N/N | N/N |

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
| debian | F/N | N/N | N/N | N/N | B/N |
| ubuntu | N/N | N/N | H/N | H/N | H/N |
| alpine | N/N | N/N | N/N | N/N | N/N |
| fedora | N/N | N/N | N/N | N/N | N/N |
| arch | N/N | N/N | N/N | N/N | N/N |
| opensuse | N/N | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N | N/N |
| void | N/N | N/N | N/N | N/N | N/N |
| armtix | N/N | N/N | N/N | N/N | N/N |
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
| ubuntu | H/N | N/N | N/N | H/N | N/N | N/N | N/N |
| alpine | H/N | N/N | N/N | N/N | N/N | N/N | N/N |
| fedora | H/N | N/N | N/N | N/N | N/N | N/N | N/N |
| arch | I/N | N/N | N/N | N/N | N/N | N/N | N/N |
| opensuse | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| void | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| armtix | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| steamos | H/N | N/N | N/N | H/N | H/N | H/N | H/N |

Preserve separate application/package versions in the receipt.
Historical Fedora desktop coverage is a GNOME devkit/llvmpipe session, not GDM
or hardware composition. See [desktop workflows](desktop-workflows.md) and
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
| fedora | N/N | N/N | N/N | N/N | N/N |
| arch | I/N | P/N | P/N | F/N | N/N |
| opensuse | N/N | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N | N/N |
| void | N/N | N/N | N/N | N/N | N/N |
| armtix | N/N | N/N | N/N | N/N | N/N |
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

| Test | Initial contract |
| --- | --- |
| `dup01` | Duplicated descriptor refers to the same inode |
| `dup201` | Invalid dup2 descriptors return EBADF |
| `openat01` | Relative/absolute paths, directory FDs and error returns |
| `pipe01` | Pipe data write/readback and descriptor cleanup |
| `epoll_create01` | Epoll descriptor creation and close; report ABI variants separately |
| `sigprocmask01` | Block, observe pending signal, unblock and deliver |
| `getuid01` | Basic guest UID syscall result; not full credential isolation |

Run bounded single iterations in disposable stores as an ordinary guest user,
with explicit temporary directories and inherited host limits. Do not expose
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
| Debian/Arch recipe setup | `build/installer-debian-turnip.json`, `build/installer-arch-turnip.json`, `build/installer-arch-turnip-render-only.log`; rendering/application acceptance remains open |
| Debian default boot/services | `build/debian-turnip-boot/oci-services-33ba076e37744211a82f0c348c8c5839.json`, `build/debian-turnip-systemd-fixed/oci-services-f7a091b709d84ad1ba282be55b888d6a.json` |
| Arch default boot/services | `build/arch-turnip-boot-ethernet/oci-services-5c561103e79044abab1afe110829a93b.json`, `build/arch-turnip-systemd-fixed/oci-services-d20b62ed713c4c299508a52385b81263.json` |
| Booted Debian Docker | `build/installed-debian-turnip/oci-services-372c29b83a41433c967a53619048ae80.json`; 26.1.5, overlay2, iptables, no userland proxy, TCP/UDP/peer names/local outbound/port conflicts and release; external internet not revalidated |
| Booted Debian Podman | `build/installed-debian-turnip/oci-services-d92a29d275db400ab1a3c48e23edc48b.json`; 5.4.2, overlay, bridge/nftables, stock seccomp, enabled cgroups, no `--ulimit` overrides; TCP/UDP/peer names/local outbound/repeated exec/port release; external internet not revalidated |
| Booted Arch Docker | `build/installed-arch-turnip/oci-services-f22142e8b86d445487808334efd9d370.json`; nftables, no userland proxy, local TCP/UDP/peers/port release; external internet not revalidated |
| Booted Arch Podman | `build/installed-arch-turnip/oci-services-38c4daf8174849e59146c3cb3f1fbef1.json`; overlay, bridge, stock seccomp, enabled cgroups, no `--ulimit` overrides; local TCP/UDP/peers/port release |
| Arch Podman external DNS/internet | `build/installed-arch-turnip/oci-services-caf5d816307e4527af22f6dd02e09e50.json`; separate earlier run |
| Debian direct QEMU TCG | `build/debian-qemu-tcg/oci-services-c5ddb332933a4cb79cb23fff41767722.json`; kernel/initrd serial boot, not KVM or VM networking |
| Debian/Arch libvirt | `build/installed-debian-turnip/libvirt-report.json`, `build/installed-arch-turnip/libvirt-report.json` and adjacent `libvirt-serial.log`; stock daemon/device policy, explicit Cortex-A72 for the ARM64 kernel; VM networking and KVM untested |
| Arch package lifecycle | `build/arch-libvirt-prepare/oci-services-c8f541d87e69484da6356634de0c3fec.json`; package hooks and subsequent mkinitcpio host-kernel errors still need a clean qualifying run |
| Arch machinectl | `build/installed-arch-turnip/oci-services-aa8afa3dff38441e8ef6df97c5896874.json`; stock systemd 262.1 unit boots nested Debian 257.13 with private users/veth, shell, services, 20 TCP + 20 UDP exchanges per round, poweroff, killed-leader restart and cleanup across three boots |
| Debian machinectl | `build/installed-debian-turnip/oci-services-8e78d11924a540428e278ebbcd479bd0.json`; stock systemd 257.13 unit, nested Debian 257.13, same three-boot shell/service/TCP/UDP/termination/cleanup contract as Arch |
| Arch BuildKit | `build/installed-arch-turnip/oci-services-ca28a04bd3254bd0955b70cd530c8247.json`; 0.34.1 OCI/overlayfs worker, CNI 1.9.1 bridge, sandbox mode, multistage build/cache/secret/export/run/cancel/cleanup, no explicit container ulimits; rootless/containerd workers and external network untested |
| Arch LXC | `build/installed-arch-turnip/lxc-nul.json`, `lxc-nul.trace`; 7.0.0 stock common configuration fails at unsupported `clone3`; fixture root/bridge cleanup succeeds |
| Debian Flatpak Chromium | `build/installed-debian-turnip/flatpak-start.trace`; bubblewrap descriptor-path lookup fails for a hardlinked runtime file; browser-based portal acceptance blocked |
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
