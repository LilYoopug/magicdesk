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
| ubuntu | H/N | H/N | H/N | H/N | I/N |
| alpine | P/N | I/N | I/N | I/N | I/N |
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
| ubuntu | P/N | P/N | N/N | N/N |
| alpine | P/N | P/N | N/N | N/N |
| fedora | N/N | N/N | N/N | N/N |
| arch | P/N | P/N | P/N | N/N |
| opensuse | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N |
| void | N/N | N/N | N/N | N/N |
| armtix | N/N | N/N | N/N | N/N |
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
| debian | F/N | N/N | N/N | N/N | B/N |
| ubuntu | N/N | N/N | I/N | H/N | H/N |
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
| ubuntu | I/N | N/N | N/N | H/N | N/N | N/N | N/N |
| alpine | I/N | F/N | N/N | N/N | N/N | N/N | N/N |
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
| arch | I/N | P/N | P/N | P/N | N/N |
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
| Arch package lifecycle | `build/arch-libvirt-prepare/oci-services-c8f541d87e69484da6356634de0c3fec.json`; package hooks and subsequent mkinitcpio host-kernel errors still need a clean qualifying run |
| Arch machinectl | `build/installed-arch-turnip/oci-services-b79fc7c63c4b479ba5588b75e50d5d74.json`; stock systemd 262.1 unit boots nested Debian 257.13 with private users/veth, shell, services, 20 TCP + 20 UDP exchanges per round, poweroff, killed-leader restart and cleanup across three boots |
| Debian machinectl | `build/installed-debian-turnip/oci-services-8e78d11924a540428e278ebbcd479bd0.json`; stock systemd 257.13 unit, nested Debian 257.13, same three-boot shell/service/TCP/UDP/termination/cleanup contract as Arch |
| Arch BuildKit | `build/installed-arch-turnip/oci-services-ca28a04bd3254bd0955b70cd530c8247.json`; 0.34.1 OCI/overlayfs worker, CNI 1.9.1 bridge, sandbox mode, multistage build/cache/secret/export/run/cancel/cleanup, no explicit container ulimits; rootless/containerd workers and external network untested |
| Arch LXC | `build/installed-arch-turnip/oci-services-1bc60138c4034ba0b1cac9aca88fb310.json`; 7.0.0 stock common policy, guest-root container, nested Debian systemd 257.13, attach/services, devpts/proc/cgroup mounts, stock seccomp, 20 TCP + 20 UDP bridge exchanges per round, normal shutdown, forced stop and restart across three boots; process/veth/cgroup/root/bridge cleanup passes. Unprivileged LXC and external DNS/internet not covered |
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
