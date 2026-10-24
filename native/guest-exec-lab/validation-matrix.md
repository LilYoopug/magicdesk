# Shroot Distribution Validation Matrix

This is the per-distribution acceptance ledger, not a supported-applications list
or a claim that all tests are automated. Keep every distribution printed by
`sh scripts/install_linux.sh --list` in every table. Results do not transfer
between distributions sharing a package manager, libc or init system.

Last reconciled: 2026-10-24. Current device evidence uses NX809J, Android 16,
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
| ubuntu | P/N | P/N | I/N | I/N | P/N |
| alpine | P/N | P/N | P/N | P/N | P/N |
| fedora | P/N | P/N | P/N | P/N | P/N |
| arch | P/N | P/N | P/N | P/N | I/N |
| opensuse | P/N | I/N | P/N | P/N | N/N |
| openkylin | P/N | P/N | P/N | P/N | N/N |
| deepin | P/N | N/N | P/N | P/N | N/N |
| manjaro | P/N | N/N | P/N | P/N | N/N |
| void | P/N | N/N | P/N | P/N | I/N |
| armtix | P/N | P/N | P/N | P/N | N/N |
| steamos | P/N | I/N | F/N | I/N | I/N |

Package lifecycle means install, update/reinstall, verification and removal,
including transaction hooks. A zero package-manager exit with failed hooks is
not a pass. SteamOS default boot remains degraded; focused control-target tests
do not certify a healthy default target. See [init contracts and limits](init-matrix.md).

### Boot And IPv6 Acceptance

The 2026-10-23 staged-runtime run used each installed recipe environment, without
an init replacement. All local IPv6 suites passed. The networkd scenario checks
router solicitation/advertisement, SLAAC lifetimes, gateway installation,
wait-online, effective MTU/hop limit, TCP/UDP traffic and router withdrawal.
The binfmt scenario checks the stock boot unit, execution and service restart.
These do not certify every networkd option or external internet access.

Receipts below are `oci-services-ID.json`: boot receipts are under
`build/ipv6-binfmt-boot/`, socket receipts under `build/shroot-image-tests/`.
All runs use default lazy entry; Base remains untested in this batch.

| Recipe | Boot / binfmt / networkd | Boot receipt ID | Local IPv6 receipt ID (PASS) |
| --- | --- | --- | --- |
| debian | P / P / P | `575399e858884d1dbe1874242cae6a4c` | `f5225204674149c89d412b6345ce8e6d` |
| ubuntu | I / P / P | `ab02a8bece5d46de807eb0347bc60696` | `5288fb359718469ea76033506b3cffa6` |
| alpine | P / N / NA (OpenRC) | `f1baebe8d6554b46a002af7387a0e1ac` | `d0b867759a994e8fbc60692e5285a09e` |
| fedora | P / P / P | `2dae19fc1aa245cf8f7add26663e40fa` | `5299bce94b364f1e8aa8304d7c8638a3` |
| arch | P / P / P | `bc915121291e4f34ab51401a0269f49d` | `d69c5902538b433dba0bba1074fa618b` |
| opensuse | P / P / P | `02e150c483294a1da3bd1a317873ed57` | `32f9692fc7db4dda83a0d406a2758e67` |
| openkylin | P / P / P | `df13520ab5d741d99a59464f095608a5` | `1714ef9068d045a2a256d80be63d0859` |
| deepin | P / P / P | `40f5b5045a224a71b27437364a80cc91` | `d4f59c0e2d1d43bcbd4d22b924001072` |
| manjaro | P / P / P | `f7be656fa9da4364915e575d3af7b30f` | `28c08a0520b148459d0052b90d569b69` |
| void | P / N / NA (runit) | `c9d13ce4051c47eb8157aecc1a0f29b2` | `d7281d10f2024a239cd902720e544e31` |
| armtix | P / N / NA (runit) | `30d38d4aec124fc1835aa5e5995d0365` (*) | `2473bd1c2149472daa21744e1cbdca78` |
| steamos | F / N / N | `fa6234c4dadc46878677e15ed535fb97` | `0aebd5e239ad43f6b1f1a62cbf5e8249` |

Fedora and openSUSE required their separately packaged networkd, installed in
the lab from their own repositories before the passing rerun. This does not
replace openSUSE's Wicked or add a test-only dependency to the user recipe.
SteamOS firewalld still submits unsupported UDP/ICMP REJECT rules.
(*) Armtix's 2026-10-24 boot receipt is under `build/compat-contract-tests/`:
stock runit stages, service start/restart/stop and launch cleanup pass without
startup failures. Its root remount uses the documented persistent-store contract.
Current focused service receipts under `build/boot-service-repair/`:
`a90f1ba5666a4fe987381e65d4bb3f37` verifies SteamOS Avahi mDNS over IPv4/IPv6
and three restart cycles. `0553d599fba34bf2ba48e0262789fb0d` verifies Ubuntu
default-target startup, journal/D-Bus/logind IO and three CUPS IPP restart
cycles within the unchanged five-second readiness bound. These receipts do
not certify SteamOS firewalld or unrelated Ubuntu container-service shutdown.

### Candidate Distribution: NixOS

NixOS is not yet an installer recipe or a recipe-installed matrix row. The
2026-10-23 probe uses the official ARM64 LXC rootfs
`nixos-image-lxc-26.05.12530.c1ff116587e6-aarch64-linux.tar.xz` from
[Hydra build 350465271](https://hydra.nixos.org/build/350465271), SHA-256
`333b1d718db3d99147ca2b5fb6d533b4aabaac98420d48e9a5369799433352ae`.
The imported image and writable probe instance are separate; no foreign
userspace, altered activation script or disabled service substitutes for NixOS.

| Scenario | Shroot / Base | Evidence under `build/ipv6-binfmt-boot/` |
| --- | --- | --- |
| Store registration and forced sandboxed derivation rebuild | P/N | `oci-services-08f9b5cbe6b3425ebeee4acec42b8dc7.json`; stock `nix-build --check --option sandbox true`, local inputs, substituters disabled, output readback |
| Stock activation in prepared init namespace | P/N | Same 2026-10-24 receipt; activation returns 0, private dev/proc/run from the common init fixture, disk-backed ramfs for `/run/keys` |
| Stock `/sbin/init`, default target and shutdown | P/N | Same receipt; systemd 260.5 reports running and zero failed units, D-Bus/journal/logind IO and restart pass, clean guest shutdown |

The boot uses routed networking with guest-owned DNS; resolvconf and
network-local-commands complete. A launch-owned read-only DNS mount is not
compatible with openresolv managing the same file. Focused stock firewall,
network-local-commands and resolvconf commands pass in
`oci-services-147018b884ff4e4cbd42c69d7a488187.json`.
Packaged dhcpcd lease/renewal, DNS options, route installation and bidirectional
UDP pass with Base and lazy entry: IPv4 receipt
`build/shroot-image-tests/oci-services-a8157781c0a2495d959beb57cd08fade.json`,
IPv6 receipt `build/shroot-image-tests/oci-services-37e026b65ce3490c87c1707d85cf5428.json`.
The DHCP fixture uses separate guest namespaces and does not certify an Android
uplink or stock boot after activation. Its hook verifies the received DNS
options; stock resolvconf is covered separately, not by that fixture hook.
Default boot still logs DHCP timeout/permission warnings on its chosen uplink;
zero failed units do not certify external DHCP connectivity. Desktop, graphics,
containers, recipe integration and package lifecycle remain unverified.
Logical ramfs is disk-backed compatibility, not memory-only/non-swappable
storage; `/run/keys` therefore has no such secret-storage guarantee.

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
| ubuntu | P/N | P/N | P/N | P/N |
| alpine | P/N | P/N | P/N | P/N |
| fedora | P/N | P/N | P/N | P/N |
| arch | P/N | P/N | P/N | P/N |
| opensuse | P/N | P/N | P/N | P/N |
| openkylin | P/N | P/N | P/N | P/N |
| deepin | P/N | P/N | P/N | P/N |
| manjaro | P/N | P/N | P/N | P/N |
| void | P/N | P/N | P/N | P/N |
| armtix | P/N | P/N | P/N | P/N |
| steamos | P/N | P/N | N/N | P/N |

### Local IPv6 Container Acceptance

The 2026-10-24 Arch reruns use stock container packages, their normal seccomp
policy and cgroups, with default Shroot entry. Both cover bridge networking,
TCP/UDP publication, peer IP/name exchange, local outbound traffic, conflicting
ports and port release. They do not request public-internet access.

| Engine | Profile and native observer | Receipt |
| --- | --- | --- |
| Docker 29.9.2 | nftables, no userland proxy, cgroup v2, published `::1` | `build/shroot-image-tests/oci-services-da9ad945e8ff4b0a83719c1f0650a960.json` |
| Podman 6.1.4 / Netavark 2.1.0 | overlay, stock seccomp/cgroups, wildcard IPv6 publication observed through Android's existing local global address | `build/podman-results/oci-services-ca516b0fb73343f68ac530d1031c7391.json` |

The observer runs as native Termux UID 10601, outside Shroot. These runs change
neither Android addresses nor its routes. Podman's tested address is not `::1`;
see the [fixture contract](README.md) for the separate observer/publication
options. Docker still logs missing `memory.events`: the unimplemented memory
controller is not advertised, and the test does not certify memory limits/OOM
notifications.

### IPv6 Uplink Coverage

The following 2026-10-23 checks use the staged native runtime under Android UID
2000; they supplement, rather than replace, the booted-service matrix above.
The ordinary VPN rejects IPv6. An authorized temporary host policy rule selected
the existing cellular route only for `2606:4700:4700::1111/128` and the test UIDs.
The container publication check additionally assigned the outer guest's IPv6
address to Android loopback. Both rules and the address were removed and absence
verified after the tests; the VPN policy was not changed. This is lab setup,
not a root dependency or automatic VPN bypass in Shroot.

| Recipe | IPv6 uplink checks | Evidence |
| --- | --- | --- |
| alpine | PASS: routed and bridge, UDP DNS, TCP DNS, verified HTTPS, remote IPv6 source | `build/ipv6-binfmt-boot/oci-services-4dbeeb4aceac4edbb3cd934febf41f12.json` |
| arch | PASS: routed and bridge uplink; local ICMPv6, address/route lifecycle, dual-stack sockets, nftables and publication | `build/shroot-image-tests/oci-services-04b7301938c348ad85458cbbacedea6f.json` |
| ubuntu | PASS: routed and bridge, UDP DNS, TCP DNS, verified HTTPS, remote IPv6 source | `build/ipv6-binfmt-boot/oci-services-4dbeeb4aceac4edbb3cd934febf41f12.json` |
| arch / Docker | PASS: nftables, no userland proxy, VFS, cgroup v2; IPv6 TCP/UDP host-address publication, peer IP/names, DNS/HTTPS from both containers, conflicts and released ports | `build/shroot-image-tests/oci-services-f55084f23c3e4036a1ddff141dd841cc.json` |
| arch / Podman | PASS: overlay, stock seccomp/cgroups; IPv6 TCP/UDP host-address publication, named peers, DNS/HTTPS from both containers, conflicts and released ports | `build/podman-results/oci-services-b8cd9497a9e445488e38c39842e2b2ca.json` |

The publication client is native Termux UID 10601, outside Shroot. Its tested
address is `fd6d:6473::64`, not `::1`. These receipts do not certify public
inbound cellular reachability, every distribution's networkd boot, arbitrary
IPv6 destinations, or a different VPN's behavior.

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
| ubuntu | N/N | N/N | P/N | P/N | P/N |
| alpine | N/N | N/N | NA/NA | NA/NA | N/N |
| fedora | N/N | I/N | N/N | N/N | I/N |
| arch | N/N | N/N | N/N | N/N | N/N |
| opensuse | N/N | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N | N/N |
| void | P/N | P/N | N/N | N/N | P/N |
| armtix | P/N | P/N | N/N | N/N | P/N |
| steamos | H/N | F/N | N/N | N/N | I/N |

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
| ubuntu | I/N | N/N | N/N | P/N | N/N | N/N | N/N |
| alpine | I/N | P/N | P/N | N/N | N/N | N/N | N/N |
| fedora | I/N | N/N | N/N | I/N | N/N | N/N | N/N |
| arch | I/N | N/N | N/N | N/N | N/N | N/N | N/N |
| opensuse | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| openkylin | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| deepin | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| manjaro | N/N | N/N | N/N | N/N | N/N | N/N | N/N |
| void | I/N | N/N | N/N | P/N | N/N | N/N | N/N |
| armtix | I/N | N/N | N/N | P/N | N/N | N/N | N/N |
| steamos | I/N | N/N | N/N | H/N | H/N | H/N | F/N |

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
| ubuntu | N/N | P/N | P/N | P/N | P/N |
| alpine | NA/NA | NA/NA | P/N | P/N | P/N |
| fedora | N/N | P/N | P/N | P/N | I/N |
| arch | I/N | P/N | P/N | P/N | N/N |
| opensuse | N/N | P/N | P/N | P/N | I/N |
| openkylin | N/N | P/P | P/N | P/N | P/P |
| deepin | N/N | P/N | P/N | P/N | P/N |
| manjaro | N/N | P/N | P/N | P/N | P/N |
| void | N/N | N/N | P/N | P/N | P/N |
| armtix | N/N | N/N | P/N | P/N | P/N |
| steamos | N/N | P/N | P/N | F/N | P/N |

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
| Armtix default boot | `build/compat-contract-tests/oci-services-30d38d4aec124fc1835aa5e5995d0365.json`; stock runit stages and default services, service start/restart/stop and owned-process cleanup pass without startup failures |
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
| Alpine recipe setup | `build/installer-alpine-turnip.json`, `build/installer-alpine-turnip-graphics.json`; official Alpine 3.23.6 minirootfs, OpenRC, ordinary user `mdtester`, Weston and recipe-built Turnip 26.2.3. Current helper refresh: `build/alpine-recipe-matrix-current/oci-services-b1df331f4f7341bda5a6d27757e3116a.json`. `build/alpine-matrix-apk-complete.log` covers tree 2.2.1-r0 install/reinstall, package-file audit, removal and BusyBox trigger restoration |
| Alpine OpenRC | `build/alpine-matrix-boot-current/oci-services-64622aa756d44ce9acb3d5bd338c99f0.json`; stock OpenRC 0.63 PID 1 with the fixture's explicit container runlevels and private bridge. Boot completion, syslog/crond start/restart/stop, PID retirement and exact launch cleanup pass. This does not certify host hardware services or unchanged bare-metal runlevels |
| Booted Alpine Docker | `build/installed-alpine-turnip/oci-services-5d0cbe2689884d1083178d71f455d1b8.json`; Docker 29.5.2, stock OpenRC service without daemon.json, default containerd snapshotter/overlayfs and iptables-nft frontend; bridge TCP/UDP, peer names, local outbound, binds/exec, port conflicts and release. Both containers pass internet access and 20 external DNS requests each. This is separate from the previously tested explicit nftables/no-userland-proxy configuration |
| Booted Alpine Podman | `build/installed-alpine-turnip/oci-services-6c8ac187f2a24a28b5a0ff39a3a4da88.json`; OpenRC, Podman 5.7.0, overlay, bridge with iptables frontend, stock seccomp and enabled cgroups; TCP/UDP, peer names, local outbound, binds/exec, conflicts and port release. Both containers pass internet access and 20 external DNS requests each. Installing its unconditional INPUT counter while Chromium already owns direct connections remains blocked with EBUSY; this pass starts Podman before browser traffic |
| Alpine Libvirt/QEMU | `build/installed-alpine-turnip/oci-services-7d97ee05fd2b412eb251b22f9528c577.json`; packaged modular libvirt with virtlogd/virtqemud, managed TCG kernel/initrd boot, paused start/resume, serial, poweroff, undefine and cleanup. Direct QEMU: `build/installed-alpine-turnip/oci-services-2df2d3e800724350ba714170b9460593.json`. VM networking and KVM untested |
| Alpine LXC | `build/installed-alpine-turnip/oci-services-3b4d3d68c4744f2dbec4999beb3cd33f.json`; packaged LXC 6.0.5, stock common policy/seccomp, nested Debian, attach/services, mounts, TCP/UDP, three normal/forced boot-stop cycles and exact process/veth/cgroup cleanup. Outer bridge control uses Alpine BusyBox ip |
| Alpine BuildKit | `build/installed-alpine-turnip/oci-services-18b75e110b7c4559a15b7776687c9840.json`; official Alpine buildkit/buildctl 0.25.1-r6 packages, CNI 1.8.0-r6, OCI worker under OpenRC. Multistage build, cache reuse/invalidation, secret/cache mounts, exported-image execution, cancellation and cleanup pass |
| Alpine LTP core | `build/installed-alpine-turnip/oci-services-45f8dc69710041ed83f9d67f6e5bd33d.json`; reviewed 20250930 sources built with Alpine compiler/musl; all seven binaries pass as guest UID 1000 |
| Alpine unavailable packages | `build/alpine-matrix-buildctl-install.log`; enabled official v3.23 main/community repositories supply neither systemd/nspawn nor snapd. Those package-specific workflows are NA; OpenRC, LXC and native browsers remain separate checks, not substitute passes for Snap or nspawn |
| Alpine graphics/Chromium | `build/alpine-egl-gbm-current.log` covers 64 GBM/EGL frames. `build/installed-alpine-turnip/alpine-chromium-lazy-queue-prototype/gui-report.json` and `alpine-chromium-sandbox-final/gui-report.json` cover packaged Chromium 149.0.7827.53: ordinary-user Wayland input, download, GTK chooser/readback, WebGL green pixels, normal close and same-profile relaunch. Both GPU reports confirm hardware composition, `Sandboxed: true` and zero GPU-process crashes. Recipe Mesa 26.2.3 received an incremental rebuild with the common queue patch; this is not a new full installation. `a2c3a0ac1b9c4220abb0785a0ee36f29.log` covers the real Mesa queue lifecycle/failure fixture. Document-portal grants and full desktop discovery remain separate |
| Alpine native Firefox | Staged fixture `57359ca724544117b985100886d3507f`; `build/installed-alpine-turnip/alpine-firefox-verified/gui-report.json` and `alpine-firefox-verified-relaunch/gui-report.json` pass ordinary-user input, download, file readback, WebGL green pixels, normal close and reuse of the same profile. Firefox reports its privacy-masked Adreno renderer name, not the actual device model. File selection uses the GTK fallback because the desktop portal service is absent; this does not certify document grants or Flatpak |
| Ubuntu recipe/packages | `build/ubuntu-recipe-matrix-current/oci-services-48ed04289e704edfad13dd42656e89ba.json`; current recipe helper refresh retains installed Turnip. `build/ubuntu-package-lifecycle-current.log` and `build/ubuntu-package-policy-verify-current.log` cover hello 2.10-3build1 install/reinstall, retained-file checksums and removal. Two documentation omissions match the image's explicit dpkg exclusions, checked separately in `build/ubuntu-package-policy-current.log`; dpkg audit is empty |
| Booted Ubuntu containers | `build/installed-ubuntu-fuse/oci-services-46aaa9fe2ec54283aabb3cd6b7a973b9.json` (stock Docker service), `build/installed-ubuntu-fuse/oci-services-84e3905829284b8d8923dc103a717180.json` (Podman, headless systemd/control target); staged native hashes in receipts. Bridge, published TCP/UDP, peer IP/name exchanges, binds/exec, conflicts and port release pass; both containers in each run also pass internet access and 20 external DNS requests each |
| Ubuntu Libvirt/QEMU | `build/installed-ubuntu-fuse/oci-services-ad1ba3366d594c0086ca6b13638c2efc.json`; official libvirt 10.0.0/QEMU 8.2.2, managed TCG boot, paused start/resume, serial, poweroff, undefine and cleanup. Direct TCG: `oci-services-ba2e038c0e7c4ce39e047fc78ed56c79.json`. VM networking and KVM remain untested |
| Ubuntu machinectl/LXC | `build/installed-ubuntu-fuse/oci-services-10e11441c9ef4854804ec93a997e3953.json` (systemd 255.4 machinectl) and `oci-services-18fb21efdf1f4e8d9cd83028b9472adf.json` (LXC 5.0.3): nested Debian, stock policies, shell/services, namespace/mount checks, bridge TCP/UDP, three normal/forced-stop cycles and process/veth cleanup pass |
| Ubuntu BuildKit | `build/installed-ubuntu-fuse/oci-services-7cb5bd022e60453096744368fd7cf7eb.json`; official upstream 0.34.1 archive for testing only, distribution CNI 1.1.1, OCI/overlayfs sandbox. Multistage build, cache reuse/invalidation, secrets, export/Podman execution, cancellation and cleanup pass. Rootless/containerd workers remain untested |
| Ubuntu LTP core | `build/installed-ubuntu-fuse/oci-services-34d8493fa9554fdd9625c4edd76c9b69.json`; reviewed 20250930 built with the Ubuntu compiler/glibc, all seven tests pass as the installed ordinary user `ubuntu`, UID 1000 |
| Ubuntu cold Snap Chromium | `build/ubuntu-snap-captured-writes-clean/oci-services-77b29f4d93c645ce871c95c6014e4cfc.json`: three uninstrumented discarded-namespace confined-shell launches pass in 26.74/24.22/26.64 s, with CPU policy maxima 2.112/1.8624 GHz. Instrumented receipt `build/ubuntu-snap-captured-writes-profile/oci-services-028219ad597245049fbbfcdf0fae94dc.json` records 55,557 captured control writes and 5,433,244 main-supervisor ptrace requests. Changed CPU limits exclude a clean elapsed-time comparison with earlier builds. Stock 30 s helper deadline is unchanged; substantial margin remains open |
| Ubuntu Snap Chromium GUI | `build/installed-ubuntu-fuse/ubuntu-chromium-sandbox-final/gui-report.json` and `ubuntu-chromium-sandbox-relaunch/gui-report.json`; stock Chromium 155.0.8059.84 revision 3564, guest UID 1000 and Wayland. Input, download/chooser readback, WebGL pixels, normal close and same-profile relaunch pass. Both GPU reports confirm hardware composition, `Sandboxed: true` and zero GPU crashes. Incrementally rebuilt recipe Mesa uses the common deferred-queue patch and the standard GPU content publisher; `bb4e82b4e74a479b8ecbb46e50a02424.log` checks matching installed/published library hashes. `ab2742619b54423a994fd4edef28a78a.log` covers two package/connection switches with automatic publication; `146c3b683c604612b3b45c5f3d9a285a.log` covers unchanged preparation without monitor restart. `ff5b6839ccaa4e94b57de1434f0892ba.log` covers Mesa queue lifecycle/failure tests against Ubuntu glibc. Cold-start margin, full recipe desktop discovery and document grants remain separate |
| Ubuntu FUSE | `build/ubuntu-fuse-capture-wait/oci-services-391bc722a78e40a4962610b1c6d63c8a.json` and `build/ubuntu-fuse-capture-wait-close/oci-services-79a6826040174c54884fb96153bb7d51.json`; SquashFS hardlink exec/reexec, ORIGIN, set-ID/nosuid, vectored/partial IO, shared/private mapping races and filtered close/flush/FD-reuse checks pass. This is not document-portal GUI acceptance |
| Ubuntu Snap Firefox | `build/installed-ubuntu-fuse/ubuntu-firefox-current/gui-report.json` and `ubuntu-firefox-relaunch-current/gui-report.json` cover fresh and same-profile Firefox 158.0-2 revision 9056. Stock refresh change 106 completes all hooks (`build/ubuntu-firefox-refresh-resolved.log`); `ubuntu-firefox-updated-current/gui-report.json` passes again on 158.0.1-1 revision 9112 with the same profile. Ordinary UID 1000, stock sandbox, input, download, chooser/readback, WebGL green pixels and normal exit |
| Ubuntu Snap portal | `build/installed-ubuntu-fuse/ubuntu-snap-portal-updated.json`; two ordinary-user document grant/read/write/revoke and SIGTERM/reactivation rounds pass after the Firefox update, including exact portal exit and FUSE mount removal. Firefox GUI receipts separately cover chooser/readback |
| Ubuntu VS Code | `build/installed-ubuntu-fuse/ubuntu-vscode-current/gui-report.json`; Code 1.142.0, Electron 43.7.7: editor/save, external-file watch, integrated PTY, GDB breakpoint/step/locals, window reload and normal close. Hardware composition/WebGL and renderer seccomp/NNP are enabled |
| Ubuntu default boot | `build/ubuntu-default-complete-current/oci-services-a2c2bbdb31da4e0ea6f9980a3dff0529.json`; stock systemd 255.4 reaches running with zero failed units on a private bridge; D-Bus/logind, journal readback/restart and RTKit lifecycle pass. CUPS initially restarts, LXC shutdown reports an error, and libvirt's default bridge control remains unsupported; VM-network acceptance is separate |
| Ubuntu services | `build/ubuntu-cups-restart-current.log`: stock CUPS Snap answers lpstat before and after service restart, then stops normally. `build/ubuntu-rtkit-current.log`: RTKit D-Bus query/restart/stop; `build/ubuntu-logger-claim-current.log`: journal write/sync/readback with the requested parent PID. These focused control-target runs do not certify the default OS target |
| SteamOS recipe/default boot | `build/steamos-recipe-hardware-current/oci-services-c668b2e77f3a4d77958f4f40811784f0.json`; official recovery image, helper refresh and full pacman synchronization. Avahi protocol/restart acceptance is recorded above. Firewalld REJECT, hardware boot and the package removal/verification lifecycle are not certified |
| SteamOS Docker | `build/installed-steamos/oci-services-8fb322d2f22048b2a44664b671732ee7.json`; official upstream Docker 29.1.3 binaries installed only for the lab, nftables/no userland proxy, overlay2 and stock container seccomp/cgroups. Headless systemd passes bridge TCP/UDP, peer names, local outbound, binds/exec, conflicts, port release and 20 DNS requests plus HTTP per container. Under concurrent Plasma/browser/BuildKit load, `oci-services-d37d40beacb3444f9c3d546fbcb25aad.json` timed out during internet access and task cleanup; concurrent-load acceptance remains open |
| SteamOS machinectl | `build/installed-steamos/oci-services-fb35961b3aa643c798479f264b5e2bd5.json`; stock systemd-nspawn template, nested Debian, shell/services, private UID map, veth TCP/UDP, normal poweroff, forced leader death, restart and process/veth cleanup pass headlessly. `build/steamos-nspawn-current.log` records a systemctl timeout under graphical load; that scenario remains open |
| SteamOS BuildKit | `build/installed-steamos/oci-services-30f589a9207c412ca7fcf8485cc2105b.json`; upstream 0.34.1 and CNI 1.8.0 binaries installed only for testing because enabled distro repositories lack packages. Multistage build, cache reuse/invalidation, secret/cache mounts, OCI export and execution, cancellation and cleanup pass |
| SteamOS LXC | `build/installed-steamos/oci-services-ff79554694fe4323ab88a29509e6b2b0.json`; packaged LXC 6.0.0 writes to FD -1 after an absent IPv6 sysctl. Boot fails. This is also present in upstream 6.0.0 network.c; no fake IPv6 control or successful invalid-FD write is provided |
| SteamOS QEMU/LTP | `build/installed-steamos/oci-services-9a0df3dbb34343389baf1a40bb9adf0d.json`: packaged QEMU 9.0 TCG kernel/initrd serial boot and clean exit. `oci-services-6ddd15e3132b4dce8c3e8e95cd9dc6aa.json`: all seven reviewed LTP 20250930 tests pass with the guest toolchain as UID 1000. Libvirt has no package in enabled repos and remains untested |
| SteamOS Plasma/Flatpak | Recipe Plasma Wayland renders through KWin/Zink/Turnip (`build/steamos-plasma-support-current.log`). `build/installed-steamos/steamos-firefox-verified/gui-report.json` passes Firefox input, download, chooser readback, WebGL pixels and normal close. Same-profile relaunch under container load loses WebGL and trips Firefox's watchdog (`steamos-firefox-verified-relaunch/gui-report.json`); repeat acceptance fails. `build/steamos-portal-current.log` passes document grants, write/read and live revocation. The auto-restored Steam client reports transport error 0x3000; neither client nor gameplay acceptance passes |
| Debian/Arch recipe setup | `build/installer-debian-turnip.json`, `build/installer-arch-turnip.json`, `build/installer-arch-turnip-render-only.log`; rendering/application acceptance remains open |
| Debian default boot/services | `build/debian-turnip-boot/oci-services-33ba076e37744211a82f0c348c8c5839.json`, `build/debian-turnip-systemd-fixed/oci-services-f7a091b709d84ad1ba282be55b888d6a.json` |
| Arch default boot/services | `build/arch-default-bridge-current/oci-services-3c014103a9cc4944beeb1999ff86627b.json`; private `bridge`, default target reaches `running`, journal write/sync/readback, D-Bus and logind restart pass; resolved is active. In `routed`, its initial-namespace bind to port 53 is also an Android publication and is denied by the host; this pass does not cover that mode |
| Booted Debian Docker | `build/installed-debian-turnip/oci-services-372c29b83a41433c967a53619048ae80.json`; 26.1.5, overlay2, iptables, no userland proxy, TCP/UDP/peer names/local outbound/port conflicts and release; external internet not revalidated |
| Booted Debian Podman | `build/installed-debian-turnip/oci-services-f472a602c8fd4b1b8114b5e72f13c459.json`; 5.4.2, overlay, bridge/nftables, stock seccomp, enabled cgroups, no `--ulimit` overrides; TCP/UDP/peer names/local outbound/binds/repeated exec/conflicts/port release; both containers pass internet access and 20 external DNS requests each |
| Booted SteamOS Podman | `build/installed-steamos/oci-services-c7f3ba36461a4bb18ffa6530083d4dcb.json`; 5.5.2, retained headless systemd/control target, overlay, bridge, stock seccomp, enabled cgroups, no `--ulimit` overrides; published TCP/UDP, peer names, local outbound, binds/exec, conflicts, port release and internet with 20 external DNS requests per container. Installing an unconditional INPUT counter over existing native browser connections still returns EBUSY. This is not default-target or concurrent Plasma acceptance |
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
