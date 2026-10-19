# Shroot

Shroot runs ARM64 Linux userspace through MagicDesk's explicitly selected shell
or root executor. The unrooted path uses Android's authorized shell UID 2000.
It needs neither Termux, PRoot, a virtual machine nor a replacement Android
kernel. glibc and musl distributions, applications, init systems and container
engines use the same runtime.

This guide covers installation, daily use, supported workflows and their limits.
The [native architecture](../native/shroot/README.md) describes implementation
owners and contracts; the [fixture guide](../native/guest-exec-lab/README.md)
describes how those contracts are tested.

- [Requirements](#requirements) and [isolation boundaries](#boundaries)
- [Installer](#linux-installer), [SteamOS](#steamos-recovery-image) and [GPU setup](#graphics-drivers)
- [Environments and commands](#named-environments)
- [Optional libc acceleration](#optional-libc-acceleration) and [Alpine containers in SteamOS](#alpine-containers-inside-steamos)
- [Systemd, OpenRC, Docker and Podman](#services-and-containers)
- [Guest credentials](#guest-credentials), [Landlock](#filesystem-restrictions) and [browser sandboxes](#application-filters-and-browsers)
- [Graphics integration](#graphical-connections) and [coverage](#coverage-and-limits)

## Requirements

- MagicDesk on Android 14+ and an authorized shell/root service. Shizuku or
  Shevery supplies shell access without Android root. Managed Desktop is
  optional and has its own Android 15+ requirement.
- Linux 5.15+ with the required operations permitted under the selected executor.
  Kernel version, Android version and build success alone do not establish this.
- An ARM64 userspace and executor-accessible executable storage. The guest
  supplies its libraries, packages and configuration.
- Sufficient storage for the image, writable data and any optional driver build.

Root is an explicit user choice, not a fallback. A denied shell operation never
causes an identity switch. Other MagicDesk tools, Termux and prepared chroot
launchers remain independent when Shroot is unavailable.

### Optional Kernel Support

Run `shroot --probe` in a Shell console to check runtime admission. The probe
exercises executable mappings, pidfds, subreapers, selective ptrace, seccomp
notifications, descriptor publication and helper teardown in child processes.
A failure reports the operation and errno before starting guest programs.
Dependencies newer than 5.15, fallbacks and coverage are tracked in
[kernel compatibility](../native/shroot/kernel-compatibility.md).

Helpers are immutable, versioned executables, never libraries loaded into ART.
A running guest tree keeps its exact helper bundle across APK updates because
later exec calls still need it. Startup of ordinary MagicDesk services does not
probe or initialize Shroot.

## Boundaries

Shroot implements selected Linux interfaces in userspace while retaining the
Android kernel for execution and ordinary data IO. Its filesystem and namespace
models can supply operations that the host's container configuration or shell
policy does not offer natively. This is not a complete Linux ABI.

Each launch captures its store, user, home, working directory, arguments and
connections. There is no global current distribution. Several environments,
several launches of one environment, and separate PRoot/chroot sessions can run
concurrently. Each launch owns one supervised process tree; stopping it does not
stop another launch. Persistent stores outlive those processes.

**Implemented restrictions are meaningful, but not a complete security boundary.**

| Area | Implemented behavior | Boundary |
| --- | --- | --- |
| Filesystems | Guest roots, mount views, DAC/ACL permissions, read-only/no-exec policy, Landlock filesystem rules | Unadapted calls and retained host descriptors are not fully confined |
| Processes | Nested PID views, proc visibility, translated waits/signals and guest PID 1 lifetime | Not a host kernel PID namespace |
| Credentials | Guest users, groups, capabilities, drops and namespace ownership | Guest root never grants Android root or kernel capabilities |
| IPC and terminals | Separate SysV IPC owners, store-scoped pathname sockets, private devpts views | Inherited connections retain authority; explicit abstract Unix sockets share the host namespace |
| Network | Offline child namespaces or routed IPv4, private ports, supported nftables flow filtering and NAT | Native backing ports remain reachable; not a host firewall or full Linux network isolation |
| Resource controls | Launch-local real-UID `RLIMIT_NPROC`; logical cgroup membership, controller settings and device-filter bookkeeping | Cgroup CPU, memory, pids and device limits are not enforced; other resource limits remain native |
| Application filters | Installed seccomp filters and their denial actions remain active | The filesystem broker is not itself confined by every caller's filter domain |

Use trusted images and programs. Logical separation prevents many accidental
cross-environment interactions and enforces supported access checks, but it is
not sufficient for hostile multi-tenant workloads. The selected executor's
Android permissions and SELinux remain the host ceiling.

## Commands

`shroot` manages Linux environments and launches programs. Standalone downloads
use `magicdesk download`; no Linux environment is required.

### Optional Libc Acceleration

Shroot can optionally use a locally built musl/glibc with direct syscall entry.
**Shroot Base** uses the distribution's unmodified libc and remains the fallback.
The installer prepares this experimental acceleration by default, reusing a
compatible cached build or compiling on the device. It does not replace Android's
libc or overwrite package-owned files in Linux.

#### Enable After Installation

Linux does not need to be reinstalled if you chose Base during setup. Use a
MagicDesk **Shell** console, not a terminal inside Linux, with the same shell/root
executor that owns the environment. Use an installer matching your MagicDesk
version; the downloaded script contains all MagicDesk source hooks and patches.

1. Run `shroot list` to find the installed environment's name. The example below
   uses `steamos`; substitute your chosen name.
2. Avoid other package installations or updates in that environment while libc
   is being prepared. Its package manager may update build dependencies.
3. Prepare libc only, without reinstalling Linux or reapplying GUI/GPU settings:

```sh
sh ~/install_linux.sh --prepare-libc steamos --jobs 2
```

Wait for `Shroot libc prepared: ...`. Start Linux again through its existing
shortcut or `shroot login steamos`; new compatible programs select the build
automatically. Already running programs are not switched. `shroot libc list`
lists cached builds, not proof that a particular application is using one.

The first preparation saves the installer as the local recipe. To prepare again,
including after a package update changes the distribution's libc:

```sh
shroot libc prepare steamos --jobs 2
```

For an OCI image, use its reference instead of an installed environment name;
see the [Alpine container example](#alpine-containers-inside-steamos).

Preparation installs build dependencies directly in the selected Linux and
compiles there, with progress in the console. Python/compiler tools belong to
that Linux, not Android or Termux. There is no full-environment backup or copy.
A compatible cached build is reused before package installation. A cache miss
needs temporary space for sources, build outputs and staged libraries. Build
packages remain installed; package upgrades are not rolled back on failure.
Successful temporary work is removed; failures retain its location for diagnosis.
A retry starts a new build unless a compatible artifact was already published;
retained partial libc work is not an incremental-build checkpoint. Shroot's
private libc never overwrites the distribution's package-owned libc. Preparing
again with a freshly downloaded installer updates the saved recipe; ordinary
launches never fetch or compile anything.

When `--libc shroot` is selected, Mesa/Turnip, KWin and the Weston maintenance
build install their dependencies first, then prepare or reuse libc for the
resulting environment, and start compilation in a fresh accelerated launch. Compiler stages do not
install packages that could invalidate that selection. This accelerates the
build tools; it does not link the resulting graphics libraries to a private libc.

Normal `shroot run/exec/login` commands do not change. Nested Docker/Podman
processes can select compatible registry entries too, without rebuilding OCI
layers or wrapping `docker run`. Matching uses exact original interpreter/libc
hashes and the entry ABI, not merely a distribution name or version. A package
update that changes those files uses Base until a corresponding build is ready.
Running processes retain their current mappings.

Container support does not imply the same speedup as an unfiltered program.
An installed application seccomp filter disables shared-memory execution;
the integrated libc then retains the kernel-admitted syscall route. Preparing
libc for an image therefore does not by itself establish a speedup under a
container's normal sandbox. Compare actual container workloads with the same
image, mounts and seccomp profile; see [sandbox behavior](../native/shroot/cooperative-entry.md#sandboxes-and-debuggers).

The registry is shared within the selected executor's environment library,
not between shell and root identities. Selected files are mounted readonly at
`/opt/shroot/libc/KEY`; installed source images remain unchanged. New readonly
or non-root container roots may need prepared empty attachment directories;
restricted roots which cannot admit the attachment use Base. Static executables
and calls bypassing the integrated libc also retain Base interception.

`shroot libc prune` removes builds not held by active launches/mounts, including
builds for stopped environments; their next launch may use Base. To explicitly
disable selection in a working environment without deleting shared builds or
rerunning the installer, create its Base-selection marker:

```sh
shroot exec steamos --user root -- /bin/sh -ec 'mkdir -p /etc/shroot; : > /etc/shroot/libc-base'
```

Here `root` is the Linux guest account, not Android root. Restart the affected
Linux programs to use Base. Successful `--prepare-libc steamos` preparation
clears this marker and enables selection again. This command needs a working
guest shell; it is not recovery for a loader that cannot start.

The installer's default `--libc shroot` prepares/enables this path, including with
`--yes` and `--resume`; explicit `--libc keep` preserves existing selection without
building. The main interactive questions offer `shroot`, `base` and `keep` before
choosing compiler parallelism. That one job count applies to libc, Mesa/Turnip
and KWin. Exact matching prevents accidental cross-version reuse, but is not
proof that an upstream rebuilt libc preserves
every distribution-specific private ABI. See the [integration contract and
coverage](../native/shroot/libc/README.md) before enabling it for important work.

#### Alpine Containers Inside SteamOS

This example assumes [Docker Engine](#docker-engine) is already configured and
running inside a Shroot SteamOS environment. Preparation and the SteamOS launch
must use the same MagicDesk executor and environment library. SteamOS's glibc
build cannot substitute for Alpine's musl; prepare the container image separately.

**In MagicDesk's Shell console, outside SteamOS:**

```sh
sh ~/install_linux.sh --prepare-libc alpine:3.23 --jobs 2
```

The installer downloads the ARM64 image into a temporary Shroot environment,
identifies its original musl and prepares a matching build in the shared registry.
Compiler packages are installed in that temporary environment, not SteamOS or
the original Docker image. Its build targets the original image's libc even if
the temporary environment's package manager upgrades its build dependencies.
Wait for `Shroot libc prepared: ...`. Once the recipe is registered, the equivalent
command is `shroot libc prepare alpine:3.23 --jobs 2`.

**In a SteamOS terminal connected to that Docker daemon:**

```sh
docker pull --platform linux/arm64 alpine:3.23
docker run --rm -it --platform linux/arm64 alpine:3.23 sh
```

The new container's compatible dynamic programs select musl from the registry.
No Dockerfile change, extra OCI layer, manual library copy or `LD_PRELOAD` is
needed. This example uses Alpine's default guest-root user and a writable root;
readonly/non-root roots may need prepared attachment directories as described
above. Existing processes keep their mapped libc until restarted.

**Inside the Alpine container**, inspect the library mapped by a new process:

```sh
grep -E '/(libc/artifacts|opt/shroot/libc)/' /proc/self/maps
```

A mapping of `KEY/lib/libc.so` under the registry or attachment path identifies
the prepared musl in that diagnostic process. `shroot libc list` in MagicDesk's
Shell only shows available builds; it does not establish selection. No matching
mapping, or a denied maps read, leaves selection unconfirmed. Check the exact
image, executor/library, attachment permissions and the absence of the container's
`/etc/shroot/libc-base` marker before assuming acceleration.

**For reproducible runs**, pin the image instead of relying on a moving tag.
After pulling it, run in SteamOS:

```sh
docker image inspect --format '{{index .RepoDigests 0}}' alpine:3.23
```

Use the printed `repository@sha256:...` reference instead of `alpine:3.23` in
both `--prepare-libc` and `docker run`. Retain `--platform linux/arm64` for Docker.
If an image update or `apk upgrade` replaces musl, prepare the new image's libc;
an incompatible cached build is not reused. A modified running container is not
the unchanged image identified by its original tag or digest.

Keep Docker's normal seccomp profile. A mapped prepared musl proves selection,
not the unfiltered direct-entry speedup: installed application filters retain
kernel syscall admission. Compare Base and prepared-libc workloads under the
same sandbox and storage configuration.

### Linux installer

[`scripts/install_linux.sh`](../scripts/install_linux.sh) installs ARM64 Linux
through the same named-environment manager. Run it in a MagicDesk **Shell**
console with shell or root access. Termux and managed Desktop are not required.
Download the file before running it so terminal input remains available for
the questions:

```sh
magicdesk download https://raw.githubusercontent.com/mekhontsev/magicdesk/main/scripts/install_linux.sh ~/install_linux.sh
sh ~/install_linux.sh
```

This is the maintained download address. The installer can be updated without
replacing the APK; download again to atomically replace `~/install_linux.sh`.
UID 2000's shell home is `/data/local/tmp/magicdesk/`; root consoles use
`/data/local/tmp/magicdesk-root/home`. Release tags retain the installer matching
that release.
The current installer requires MagicDesk 2.1.2 or newer (`versionCode` 224),
including the X11 SysV shared-memory bridge used by its software graphics profile.
Before questions, downloads or environment access, including `--resume`, it
checks the running app with `magicdesk get_state --field data.app.versionCode`.
An older version, unavailable CLI or invalid response stops installation without
changing Linux environments. Update MagicDesk and open a new Shell console,
or use the matching release-tag installer when keeping an older APK.
`--help`, `--list` and embedded-script/patch exports work without MagicDesk.
The minimum follows required APK behavior, not every installer revision;
development builds within one version cycle share the same version code.

The script itself asks for the distribution, independent environment name,
GUI profile, graphics driver, locale, timezone and fonts. Additional questions
cover an optional guest account, X11/Wayland application entries, extra packages,
DNS and package-download cleanup. The same choices
are command-line options; `--yes` suppresses questions. `--list` is read-only.

| Distribution | Source | GUI recipes |
| --- | --- | --- |
| Debian 13 | Official debuerreotype ARM64 slim rootfs | apps, Xfce, Weston, Plasma 6 |
| Ubuntu 24.04 | Official Ubuntu Base ARM64 rootfs | apps, Xfce, Weston |
| Alpine 3.23 | Official aarch64 minirootfs | apps, Xfce, Weston |
| Fedora 44 | `registry.fedoraproject.org/fedora:44` | apps, Xfce, Weston, experimental GNOME devkit |
| Arch Linux ARM | Official generic aarch64 rootfs | apps, Xfce, Weston |
| openSUSE Tumbleweed | Official dated aarch64 LXC rootfs | apps, Xfce, Weston |
| openKylin 3.0 | `openkylin/openkylin:latest` | apps, Xfce, Weston |
| Deepin 25 | `linuxdeepin/deepin:crimson-arm64` | apps, Xfce, Weston |
| Manjaro ARM | Official dated Manjaro ARM rootfs | apps, Xfce, Weston |
| Void (glibc) | Official dated aarch64 rootfs | apps, Xfce, Weston |
| Armtix (runit) | Official dated Armtix rootfs | apps, Xfce, Weston |
| SteamOS ARM64 0.3.0 | Official Valve Steam Frame recovery archive | supplied applications, Plasma 6 |

`none` installs console tools only. `apps` supplies Mousepad, Thunar and Xfce
Terminal, XKB data, icons and a session D-Bus setup. `xfce` adds an X11 desktop;
`weston` adds a nested Wayland desktop with Xwayland. `plasma` adds KDE Plasma 6
with X11 and Wayland desktop entries on Debian and SteamOS. `gnome` selects Fedora's
development-kit shell, not a systemd/GDM login session. GUI recipes are package
configurations, not a claim of complete desktop compatibility. Fedora 44's Glycin
2.1.5 decodes PNG and SVG through stock Bubblewrap with its original seccomp
filter. GNOME devkit is checked with an explicit private system bus and PipeWire;
the installer recipe still needs this session-service arrangement. Rolling Arch's
default pacman sandbox uses Shroot's Landlock filesystem policy, independently
of host kernel Landlock availability. Missing operations are not bypassed by
silently disabling sandboxes.

Desktop launcher names include the distribution's `NAME` from `/etc/os-release`
(or `ID` when absent). MagicDesk adds the independent environment name, for
example `Alpine Linux - Xfce Desktop (work)`. Resume refreshes installer-owned
desktop entries; distribution and user-provided entries remain unchanged.

Every GUI profile installs PipeWire/Pulse client support, the ALSA plugin,
SDL2, libudev and Wayland window decorations. Android audio and gamepads are
provided by the shared Shroot launch services, without raw host input-device
binds or extra controller daemons. Gamepad input follows the focused Android
host. Desktop volume controls use a private guest PipeWire graph; Xfce and
Plasma include their mixer integration. Individual applications connect directly
to Android's audio service. See [audio](audio.md) and [gamepads](gamepads.md).

Images and repository packages are trusted executable inputs, not sandboxed
content. `--image REF` selects another OCI source of the same distribution and
version; the guest architecture and OS are checked before package setup. Arch
uses the distribution's rootfs and performs a complete rolling userspace upgrade.
The installer preserves upstream repository signature policy and pacman's default
filesystem sandbox. Armtix's supplied rootfs disables repository signatures;
the installer warns about this and does not silently change that policy.
Package output and errors stay in the console.

Recipes prefer official generic ARM64 rootfs archives when available. Disk images,
ISOs and OCI-layout archives are not interchangeable with a rootfs tarball; the
other distributions retain their OCI sources. Upstream sources include
[Debian's official image artifacts](https://docker.debian.net/),
[Ubuntu Base](https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/),
[Alpine](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/),
[Arch Linux ARM](https://archlinuxarm.org/about/downloads) and
[openSUSE](https://download.opensuse.org/ports/aarch64/tumbleweed/appliances/).

Official rootfs archives have pinned URLs and SHA-256 digests. Arch's upstream
`latest` URL is mutable: replacing that archive requires a verified recipe pin
update, never accepting a checksum mismatch. Its pinned bytes were verified with
the upstream build-signing key; users need no separate GPG installation.
`--downloads DIR` selects their reusable verified cache. Gzip archives go directly to Shroot's
native importer. XZ archives use the same isolated, digest-pinned Python OCI
helper as the recovery converter, only to change compression; tar entries,
ownership and hardlinks remain untouched. This requires neither Python nor
Termux on Android. The temporary helper is removed after successful import/setup;
failed conversion work is retained with its exact location. `--resume` never
downloads or replaces a rootfs. These recipes launch applications and desktops
directly; they do not switch the distribution's init system or boot PID 1.
On networks without working IPv6, `FORCE_IPV4=1 sh install_linux.sh --distro void`
selects XBPS's IPv4-only downloads. This explicit setting also applies to resume
and optional graphics setup, without changing Android networking.

Package setup uses the guest root account, without granting Android root or
changing the executor UID. Setup processes explicitly declare `SYSTEMD_IN_CHROOT=1`
to package hooks because these recipes do not boot the OS. This is not persisted
in login profiles or applied to subsequent init-system launches. GUI setup creates
root-owned, sticky X11/ICE socket directories for direct non-root desktop sessions.
`--create-user developer` creates a password-locked
ordinary account; choose it with `login --user developer` or a shortcut's User
field. It does not change the image's default account. `--locale ru_RU.UTF-8`
prepares guest locale data; `--timezone system` snapshots Android's IANA zone.
The selected login locale clears the inherited shell `LC_ALL` override.
On apt-based images it also retains translations during package installation;
packages already installed with translations excluded need reinstallation to
restore those files.
`--fonts cjk` adds Chinese/Japanese/Korean fonts. `--package NAME` is repeatable;
`--cache clean` removes downloaded packages, not user files or Mesa build work.

```sh
sh ~/install_linux.sh --name debian --gui xfce --yes
sh ~/install_linux.sh --distro alpine --name alpine-work --gui weston
sh ~/install_linux.sh --name debian --resume --gui xfce
sh ~/install_linux.sh --name debian --resume --gui plasma --gpu turnip
```

Existing names are never replaced. `--resume` explicitly continues package
setup after detecting and validating the distribution. Without explicit options
it preserves GUI selection, locale, timezone, fonts and graphics profile while
refreshing installed GUI service dependencies, helper scripts and installer-owned
desktop entries. It does not remove previously installed desktops when another
profile is added or rewrite distribution/user launchers. After an
interrupted image installation, inspect `shroot list` before choosing a
new installation or resuming. A package failure leaves the environment available
for diagnosis and retry.

New installs validate DNS with the other settings, before final confirmation
or image work. The interactive installer explains an unavailable
policy and asks for a replacement; invalid addresses repeat only the DNS question.
The default response cancels. With `--yes`, failure stops before image downloads
and setup. `shroot dns --check system|preserve|IP[,IP...]` uses the same validation
without changing a resolver; it does not test server reachability.

If package setup fails, the interactive installer offers retry, changing DNS
and retrying, or cancellation. It retains the installed environment and all
other choices. An unattended `--yes` run stops with the original failure code
and a resume hint. A package error is not automatically classified as DNS failure.

New installs default to **Current network** (`--dns auto`, also accepted as
`--dns system`). The additional settings offer this option alongside keeping
the image's DNS (`preserve`) and entering custom DNS addresses. Automatic mode
copies the DNS servers of the current shell/root executor's Android network
once; it does not pin the network. A VPN is not a reason to reject this mode;
Android's per-UID routing decides whether the VPN covers the executor.
Android Private DNS still requires an explicit `--dns IP[,IP...]` choice or a
prepared image resolver with `--dns preserve`: plain guest DNS does not
reproduce Android's encrypted resolver policy.
No public resolver is selected automatically. For a new environment, system or
explicit DNS replaces the image's resolver through the existing offline DNS
command; `preserve` leaves it alone. Resume retains existing DNS. Later network
changes can make the saved DNS addresses unreachable. Users can edit Linux's
`/etc/resolv.conf`, use their distribution's resolver configuration, or explicitly
refresh an inactive environment with `shroot dns NAME system --replace`.
The installer does not run a background network monitor or overwrite later edits.

#### Resume An Interrupted Installation

In a MagicDesk Shell console, using the same shell/root executor as before:

```sh
shroot list
sh ~/install_linux.sh --resume --name steamos --gui plasma --gpu turnip --libc shroot --jobs 4 --fonts keep
```

This example continues SteamOS with Plasma and explicitly selected Turnip;
substitute your environment name and repeat the options you intended to install.
`--resume` detects the installed distribution and skips rootfs download/import.
It reruns package setup and the selected preparation stages, not the interrupted
process at its last instruction. Completed compatible libc builds can be reused;
unfinished libc builds start in a new work directory. Mesa and KWin retain their
own build directories. None of these steps requires a full copy of the environment.

Do not pass `--dns` or `--image` with `--resume`, including `--dns preserve`:
resume already retains both, and explicitly rejects these flags. Change DNS
separately through `shroot dns` or Linux's resolver configuration. Package setup
can still access repositories and download missing packages or source archives.

Closing the console window retains its PTY; reopen it through **Terminal sessions**
to continue watching the same installer. **End session**, app process death and
APK replacement end that PTY. Afterward, use resume in a new console. A saved
command history or retained build directory is not a surviving installer process.

#### SteamOS recovery image

```sh
sh ~/install_linux.sh --distro steamos --name steamos --yes
```

The installer downloads Valve's [Steam Frame ARM64 recovery 0.3.0](https://steamdeck-images.steamos.cloud/recovery/steamframe-oobe-repair-20260922.5153644-0.3.0.img.bz2)
with pinned SHA-256 verification, not the x86 Steam Deck recovery image.
A temporary, digest-pinned official `python:3.14-alpine3.23` OCI
environment reads the GPT/Btrfs image without mounting it. Pinned binary wheels
for Dissect Btrfs, cstruct and util are downloaded and verified by
`magicdesk download`; neither Python nor a compiler is required on Android.
These external readers are AGPL-3.0 projects from
[Dissect](https://github.com/fox-it/dissect.btrfs), not APK dependencies.
The conversion code is embedded in `install_linux.sh`.

The root partition and its factory `/var` defaults become a local OCI layer,
preserving file contents, ownership, modes, timestamps, symlinks, hardlinks,
POSIX ACLs and file capabilities. Btrfs compression attributes describe storage
only and are omitted. Other unsupported attributes stop conversion explicitly.
Recovery-disk repair tools, EFI partitions and recovery `/etc` overrides are not
installed. Android partitions and mount state are untouched.

The named environment uses the image's ordinary `steamos` account. Its supplied
Steam client archive and missing SDK/root links are prepared in that account's
home without replacing an existing installation or user-owned links.
The Turnip profile supplies overridable FEX GL/Vulkan thunk defaults and exposes
its private Mesa prefix to pressure-vessel; it does not replace per-game FEX
configuration. After refreshing Apps, select Steam or another
supplied application; `shroot login steamos` opens a terminal as `steamos`.
Use `shroot login steamos --user root` for guest administration.

For an x86 Linux game using Valve's FEX compatibility tool, set its Steam
**Properties > General > Launch Options** to:

```text
magicdesk-steam-game %command%
```

The recipe installs this launcher inside SteamOS. It derives a cached emulator
descriptor from the selected Steam tool, retaining its architectures, library
requirements and arguments. Inside pressure-vessel it makes FEX's empty root
explicit (`/`) and gives the private Mesa profile priority while preserving the
runtime's library paths. Valve's files and per-game FEX configuration are not
modified. Commands without a matching FEX descriptor and an explicitly supplied
`PRESSURE_VESSEL_EMULATOR` pass through unchanged. This does not guarantee
compatibility with every game or Proton configuration.

Reserve about 35 GB of free storage during conversion/import. Verified source
archives and wheels remain in `$HOME/downloads` (`--downloads DIR` overrides
this); a validated import releases its own temporary converter environment
and local OCI layout even if later package setup fails. Failed conversion/import
retains the exact work directory printed in the console. It never prunes unrelated
Shroot environments or downloads.

SteamOS defaults to `--gui plasma --gpu auto --fonts keep`: it retains its supplied
program selection and repository configuration, adding explicit nested Plasma
launchers. Before preparing Steam for first
use, it updates packages with `pacman -Syu` against those repositories, retaining
the image's keyring and signature policy. A package-manager failure stops setup and retains the
environment for `--resume`; guest networking must work with the selected DNS.
Resume repeats the package update before continuing. This does not move to Arch's
rolling repositories or invoke SteamOS's disk/firmware updater.
Kernel-module scriptlets can warn about missing modules for the running Android
kernel; the guest's kernel packages do not replace it. System-manager hooks skip
services in the non-booted environment. Their diagnostics remain in the console.
Locale, timezone and additional guest-user settings remain available. This is
SteamOS userspace, not a booted recovery/VR session; individual games require
their own verification. `--gui keep --gpu keep` deploys only the supplied stack.
The private graphics recipe builds Mesa and a matching KWin 6.2.5 adapter without
replacing Valve's packages or upgrading Plasma to a different ABI. Choose
**Plasma Desktop (wayland)** in Apps after setup. To add this configuration to an
already deployed image:

```sh
sh ~/install_linux.sh --name steamos --resume --gui plasma --gpu auto
```

Refresh MagicDesk's Linux application list after installation. Distribution
entries remain untouched; `--protocol x11|wayland|both` controls the installer's
own application entries. Selected whole-desktop entries open in one viewer.
See [Launch installed Linux](getting-started.md#launch-installed-linux) for the
application, whole-desktop and terminal launch steps.
The shared catalog preserves application/desktop presentation for both protocols;
guest declarations cannot replace store-derived host paths or graphics routing.

#### Graphics drivers

Except for SteamOS's automatic selection, graphics default to software rendering
through a guest-owned `/etc/profile.d/magicdesk-graphics.sh`.
A supported Adreno GPU with accessible
KGSL can use the optional Turnip profile:

```sh
sh ~/install_linux.sh --name debian --resume --gpu turnip
sh ~/install_linux.sh --name debian --resume --gpu software
```

Turnip setup installs distribution-specific build dependencies and compiles Mesa
26.2.3 inside the guest. The HTTPS source archive has a pinned SHA-256; the
non-DRM Wayland/Zink and capability-probed KGSL timestamp changes are embedded
in the installer and applied without fuzz. All distribution recipes share this
patch, including non-DRM EGLDevice identification from the real driver's
acceleration capability and UUID. An APK update does not rebuild installed
Mesa: use the resume command above, then restart the affected applications.
Turnip, Zink, EGL,
GLX and GBM come from that same build. Zink also supports GPU rendering with
CPU readback when Kopper is disabled or the X server lacks DRI3. That path has
a frame copy, not zero-copy presentation.
Steam's CEF interface and animated GLX output have coverage in nested Xwayland
on Adreno 840. `--jobs N` controls compiler parallelism
(1-8, default 2). Allow several GB of space for sources, build files and libraries.
Build work stays in `/var/cache/magicdesk/mesa/` for resuming; completed libraries
have an immutable recipe-addressed prefix in `/opt/magicdesk/mesa/`.

A temporary profile explicitly selects that Vulkan ICD, DRI directory and EGL
vendor. Bounded Vulkan enumeration must report Turnip before an atomic profile
replacement enables it for new launches. Failure preserves the previous profile;
existing programs are not restarted. This suitability check is not proof that
every OpenGL application renders correctly. Build/render checks cover Debian
and SteamOS configurations; other toolchains and GPUs require separate validation.
Software fallback uses the distribution's unchanged libraries.
SteamOS's supplied Mesa contains Zink but no Gallium llvmpipe driver. Its software
profile installs the official `vulkan-swrast` and matching `llvm17-libs` packages
alongside the image's newer LLVM, then runs Zink over Lavapipe. Vulkan and
surfaceless EGL probes must succeed before the profile is replaced. No Mesa
build is required. Legacy X11 MIT-SHM attaches guest SysV segments through a
namespace-scoped FD bridge to the app-UID server, so the profile no longer needs
`MESA_VK_WSI_DEBUG=noshm`. Pixel data stays in shared mappings. This is CPU
rendering, not Turnip or hardware acceleration.
Neither profile replaces Android libraries, distribution
drivers or the APK renderer, and no privileged identity switch is performed.
`--gpu auto` first checks access to KGSL, then builds and probes Turnip when it
is available. An unavailable or incompatible GPU selects software rendering with
a visible diagnostic. Download, package and compilation failures stop setup;
they are not classified as unsupported hardware. Explicit `--gpu turnip` fails
instead of selecting software when its GPU probe fails.
The lab obtains the identical patch with `sh scripts/install_linux.sh --print-mesa-patch`.

#### Plasma and desktop sessions

The `plasma` profile adds both `Plasma Desktop (x11)` and
`Plasma Desktop (wayland)`. With Turnip selected, it additionally builds pinned
KWin 6.3.6 for Debian 13 or 6.2.5 for SteamOS from a checksum-verified KDE archive.
The shared DMA-BUF adapter and version-specific API changes are embedded
in the installer (`--print-kwin-patch [VERSION]`). The build is guest-owned,
not an APK dependency or system compositor replacement. The recipe includes
Debian's Plasma dependency minimum. Work stays in `/var/cache/magicdesk/kwin/`,
and complete builds use immutable `/opt/magicdesk/kwin/` prefixes. Only the
Wayland desktop launcher selects those libraries, plugins and executables.
An unsuccessful KWin build retains the previous KWin selection. Adding Turnip
to an installed Plasma desktop also prepares its matching KWin adapter when
`--gui keep` is selected; it does not install Plasma in an applications-only
environment.

```sh
sh ~/install_linux.sh --distro debian --name plasma --gui plasma --gpu turnip
sh ~/install_linux.sh --name plasma --resume --gui plasma --gpu turnip
```

All whole-desktop entries use `magicdesk-desktop-session MODE`, where MODE is
`xfce`, `weston`, `gnome`, `plasma-x11` or `plasma-wayland`. It reads the current
graphics/application profile, reuses a supplied D-Bus session (or starts one),
and acquires the guest audio graph without replacing the launch's gamepad
capability. The same helper can run in a prepared graphical console. Software
Weston uses Pixman and software Plasma Wayland uses QPainter; the Turnip profile
selects OpenGL Weston and the private KWin adapter.

The Weston recipe upgrades package versions 13.0.0 through 13.0.3 to the official
13.0.4 maintenance source, built privately inside that Linux. This avoids the
13.0.0 popup-focus crash reproduced with Firefox. The same version check applies
to every distribution, including software rendering; newer packaged versions
remain in use. `--resume --gui keep` prepares an existing recipe-installed Weston
desktop without replacing its package files. `--jobs` and libc build selection
apply just as they do to Mesa and KWin. No compositor binary is added to the APK.

Plasma launches its classic session inside the selected graphical connection,
without booting systemd or a system bus. Hardware-related KDE services may remain
unavailable. GUI recipes configure PipeWire clients to use native scheduling
checks without Portal/RTKit delegation; these sessions do not supply a privileged
realtime scheduler. The settings live in PipeWire's client configuration drop-ins,
not in syscall emulation, and leave kernel resource limits intact.
The application profile supplies VLC's installed plugin directory when
`VLC_PLUGIN_PATH` is unset, including multiarch layouts. This avoids VLC's native
`/proc/self/maps` relocation guess in an object-backed store without replacing
its packages or user launchers. Explicit application overrides remain intact;
this does not virtualize the pathnames in native proc mapping tables.
The software profile uses the distribution's KWin with QPainter on
Wayland; switching profiles affects new launches, not an already running session.
On RM11 under UID 2000, the private Wayland compositor renders Plasma, Dolphin,
its launcher and Overview through Zink/Turnip. A nested EGL client submits
DMA-BUF v3 buffers and produces changing frames; desktop resizing preserves GPU
composition. This coverage is for Debian 13, KWin 6.3.6 and Adreno 840, not other
GPUs or all Plasma services.

Graphical launches keep the normal per-launch runtime directory,
session bus and X11/Wayland connection; the script does not start an Android
service, display server or system D-Bus daemon. A shell is available with
`shroot login NAME`.

Installer, application and desktop checks have different scopes; adding a
distribution recipe does not certify every GUI profile on it. See
[coverage and limits](#coverage-and-limits) for tested workflows and known
client/driver limitations.

### Named environments

In a newly opened MagicDesk Shell console:

```sh
shroot install debian:trixie-slim --name work
shroot install alpine:3.23 --name tools
shroot list
shroot inspect work
shroot login work
shroot exec work -- /bin/sh -c 'mkdir -p /mnt/project'
shroot exec work --bind /sdcard/Download /mnt/project -- /bin/sh
shroot run tools -- /bin/sh
shroot launches work
shroot stop work LAUNCH_ID
shroot backup work /sdcard/Download/work.tar.zst
shroot restore /sdcard/Download/work.tar.zst --name restored
shroot remove tools
shroot prune
```

The named-environment manager uses the selected shell executor. It needs neither
Termux, Python, an external download tool nor a Docker daemon. Image import
does not execute package scripts. The installer above is the separate step
that configures packages and GUI services.

#### Images and storage

`install` accepts a public OCI reference, a local OCI layout with `--oci`, or a
tar/gzip/zstd rootfs archive with `--rootfs`. Registry acquisition selects Linux
ARM64 and verifies SHA-256 and sizes. Anonymous Bearer challenges are supported;
credentials are not forwarded to another origin. Private-registry credentials,
Docker-save archives and other rootfs compression formats are not supported.

Each name selects an independent writable store. Images and archives reuse
sealed content-addressed images; OCI imports also share verified layer bodies.
Instances copy up on mutation. `path NAME` returns the immutable store location;
`inspect NAME` includes source, image configuration and lower dependencies.
Reusing a removed name creates a new identity, never retargets a running launch
or an existing shortcut.

The default library is `$MAGICDESK_RUNTIME/guest-environments`;
`MAGICDESK_GUEST_HOME` selects another executor-accessible executable filesystem.
Do not edit its backing files as a normal rootfs: names, hardlinks, metadata and
shared image ownership belong to the inode store. Use guest commands, explicit
attachments or backup/restore.

Eligible private regular files use native names by default, with sparse metadata
for non-root ownership. Creation, rename and deletion avoid per-file SQLite
writes; this also applies to conflict-free names in admitted writable-overlay
upper directories. Copy-up and whiteouts retain catalogue transactions.
Hardlinks and shared image operations promote native files into
the same inode model without copying their data or invalidating open descriptors.
This optimization does not bypass guest permissions, mounts or Landlock.

Namespace changes become visible atomically. Ordinary writes and closes are not
durability barriers: `fsync`, `fdatasync` and `syncfs` synchronize native data and
the corresponding committed catalogue metadata. Native-name directory entries
require directory fsync or syncfs for durability, as on Linux. Imports, image sealing and
snapshot publication also request explicit barriers. Unsynced changes may be
lost on power failure; process-crash tests do not establish hardware power-loss
guarantees. See [inode-store transactions](../native/shroot/inode-store.md#transactions).

`backup` requires an inactive store and includes its shared data; a restored
instance has no lower dependencies. `remove` also requires an inactive store.
Explicit `prune` checks dependencies and lifetime locks before removing unused
stores, images, layers and downloads. Busy or uninspectable resources stop
cleanup; attached host directories are never removed. There is no background GC.
Do not create unmanaged snapshots referring to library-owned images; use
backup/restore for independent storage.

Catalog mutations report busy rather than wait behind another operation.
Listing and launch resolution do not wait for downloads. Interrupted publication
does not expose a partial environment; recognized abandoned staging is reclaimed
by subsequent publication or explicit recovery. Inspect the catalog before
retrying an operation whose result was lost.

Format **17** is the persistent-storage compatibility baseline. Formats 14-16
are not upgraded; export needed files with their matching runtime before
recreating those environments. They are never automatically deleted.
From format 17 onward, supported metadata revisions are prepared in place before
use, preserving environment paths, files, identities and shared sources. An update
requiring exclusive access reports busy while another launch or dependent store
retains the storage; stop those launches and retry. Listing and application
catalog inspection do not initiate schema updates. `shroot image prepare STORE`
explicitly prepares a store without launching it. A newer, unknown revision is
rejected; downgrading an APK does not downgrade its storage.
See [storage evolution](../native/shroot/inode-store.md#storage-evolution).

#### Launches and directory attachments

| Command | Meaning |
| --- | --- |
| `run NAME` | Use the image's Entrypoint/Cmd |
| `exec NAME -- COMMAND` | Start a new supervised tree with an explicit command |
| `login NAME` | Open the selected account's login shell |
| `launches NAME` | List live launch IDs from CLI, terminal and graphical callers |
| `stop NAME ID` | Cancel that exact supervised tree |

`exec` does not enter an already running container. All three launch commands
accept user, environment, cwd, hostname and directory-attachment options.
`--bind HOST GUEST` and `--bind-ro HOST GUEST` attach existing directories to
one launch. Declare nested targets parent first; each retains its own read-only
policy. The same [network profile](#network-modes) is accepted by run, exec,
login and the low-level `--store` runner, including launches that start an OS init.

Login uses `/etc/passwd` for home and shell. Numeric users absent from that file
use `/`, `/bin/sh` and a numeric username; no account is created. Image launches
supply HOME, SHELL, USER and LOGNAME defaults. Image environment and explicit
`--env` values override exec/run defaults; login uses account values unless
explicitly overridden. `--cwd` selects the requested guest directory.

Launch IDs address retained supervisor records, not reusable process numbers.
Cancellation acceptance is not completion: list again to observe retirement.
Closing an ordinary Console window retains its PTY and programs; stopping the
launch ends its tree. Neither action removes the store.

#### DNS

Installation accepts `--dns system` (default), `--dns preserve`, or up to three
comma-separated numeric addresses. System DNS is a one-shot active-network
snapshot, not an Android resolver proxy. No public resolver is chosen implicitly.
VPN networks are accepted; Android applies routing for the selected executor's
UID. Private DNS needs an explicit policy because copying resolver addresses
does not preserve its encrypted semantics. Saved addresses do not automatically
follow later network changes.

The manager retains nonempty or symlinked `/etc/resolv.conf`.
`shroot dns NAME POLICY --replace` explicitly replaces it in an inactive
environment; without `--replace` the preservation rule applies. The installer
uses replacement for a new environment with system/explicit DNS, while resume
retains existing DNS. Restore preserves the backed-up configuration.

Launch-time `--dns IPv4` is a different, temporary policy: repeat it for up to
three servers. It mounts a read-only `/etc/resolv.conf` for that launch only;
other launches and the stored configuration are unchanged. The file must already
exist (a symlink to an existing regular file is accepted). Missing or dangling
targets fail before the application starts. Preparing an image's resolver is an
installation operation, not an implicit persistent mutation during launch.

#### Android command access

`--magicdesk` explicitly enables the shared
[Linux command channel](automation.md#linux-command-access):

```sh
shroot exec work --magicdesk -- magicdesk get_state
shroot login work --magicdesk
```

The launch receives a read-only client mount at `/run/magicdesk` and a
launch-scoped authorization channel. Images and shortcuts contain no credentials.
Ordinary launches omit the attachment. The option also works with raw stores,
local image launches and the terminal/shortcut picker. Native Termux and PRoot
use the same service through `magicdesk-connect`, independently of Shroot.

#### Prepared stores and offline images

Low-level commands remain available for explicitly prepared inputs:

```sh
shroot --import /absolute/prepared-rootfs /absolute/new-store --preserve-ownership
shroot --store /absolute/new-store --user root --home /tmp --cwd / -- /bin/sh -l
shroot image import /absolute/oci-layout /absolute/image --preserve-ownership
shroot image create /absolute/image /absolute/instance
shroot image run /absolute/instance -- /bin/sh
shroot image rootfs /absolute/rootfs.tar.gz /absolute/rootfs-image
shroot image backup /absolute/instance /absolute/backup.tar.zst
shroot image restore /absolute/backup.tar.zst /absolute/restored-instance
```

Tree import accepts an immutable prepared directory, not an archive or a
distribution name. It publishes into a new store atomically; default bounds are
2 GiB and 200,000 entries. Unsupported metadata/objects, source mutation,
overlap and populated destinations are errors. `--preserve-ownership` retains
guest UID/GID, permissions and set-ID metadata, never host set-ID bits.

`image import --layers /absolute/layer-pool` shares file bodies across imports.
Image Env, WorkingDir, Entrypoint and Cmd feed the ordinary guest runner.
Import and backup need no execution probe; launching does. See
[images and views](../native/shroot/images.md) for formats, lifetimes and limits.

#### Apps, terminals and automation

Start, the shortcut editor and the terminal environment picker use the same
default-library catalog as an ordinary Shell CLI invocation. An explicit
`MAGICDESK_GUEST_HOME` selects another library for that command; it does not
register that library with Android's application catalog. Use the default library
for applications intended to appear in Start.

Refresh Apps after changing installed packages; discovery
does not run guest programs or refresh on every menu opening. Identities include
the immutable environment ID, so identically named apps remain independent.
Artwork uses the shared asynchronous icon service.

Installer-owned `.desktop` entries live inside the environment's
`/usr/local/share/applications`; they are not separately copied Android Desktop
shortcuts. A whole-desktop recipe and an `apps` recipe publish different launchers.

Terminal, X11 and Wayland entries share launch recipes and optional user
selection. An empty terminal command opens a login shell. XKB is resolved from
the selected store's `/usr/share/X11/xkb`; custom entry scripts can supply an
explicit host-visible path. Each graphical launch owns its runtime directory,
session bus and authenticated file helper. Import/export uses actual guest
paths, not guesses about physical backing names.

MCP `guest.list` and `guest.inspect` expose the catalog; `guest.launches` and
`guest.stop` address native launch ownership. `guest.start`, `guest.status` and
`guest.cancel` track a command by operation ID/revision. Disconnecting MCP does
not cancel work. App restart discards operation receipts, not persistent stores;
cancellation does not roll back committed changes or authorize blind retries.

## Services And Containers

These are runtime capabilities and tested Linux configurations, not automatic
installer modes. `install_linux.sh` prepares direct application/desktop launch;
it does not boot PID 1 or enable Docker/Podman. Minimal images may need their
distribution's init, D-Bus and container packages installed first.

### Systemd, OpenRC and runit

Unmodified systemd runs as guest PID 1 in Shroot's private PID/mount/UTS/IPC/cgroup
views. Tests cover system and user managers, oneshot and notify services, socket
and timer activation, FD-store restart, credentials and restricted service
filesystems. Separate checks boot distribution default targets and exercise
the journal, system D-Bus and logind.

Alpine's `openrc-init` and Void/Armtix runit have boot and service lifecycle
coverage. These launches use private proc, `/run`, `/dev`, terminal and cgroup
views, not Android's init system. Starting `/sbin/init` in an ordinary application
shell is not an equivalent setup.

See the [init matrix](../native/guest-exec-lab/init-matrix.md) and
[init fixtures](../native/guest-exec-lab/namespaces.md#namespace-clients) for setup
and exact assertions. Kernel-module loading and unavailable hardware services
need container-appropriate configuration; Debian/openKylin default-target checks
explicitly drop `CAP_SYS_MODULE`. SteamOS's default boot remains degraded on
hardware/network units. Passing a userspace boot does not certify a display
manager, graphical login or hardware boot.

### Network modes

Networking belongs to one supervised process tree, not to its persistent store.
The same store can have independent simultaneous launches with different policies.

| Launch option | Policy |
| --- | --- |
| Omitted or `--network host` | Native Android networking; no virtual network or relay is allocated |
| `--network none` | Private network with working loopback and no external route |
| `--network bridge` | Prepared private IPv4 network, bridge/uplink, outbound access and optional published ports |
| `--network routed` | Low-level routed backend for guests such as Docker/Podman that configure their own network topology |

`routed` remains supported, not deprecated or an alias for `bridge`.
An application-created network namespace starts with down loopback and no
external connectivity, even when its parent has a prepared network.

```sh
shroot exec work --network bridge -p 127.0.0.1:8080:80 -- /usr/sbin/nginx -g 'daemon off;'
shroot exec work --network bridge -p 127.0.0.1:5353:53/udp -- /path/to/dns-server
shroot login work --network none
```

Repeated `-p` / `--publish` accepts `[IPv4:]HOST:GUEST[/tcp|/udp]`, with TCP as
the default. Omitted IPv4 binds all host IPv4 addresses; use `127.0.0.1` for local
access only. Ports must be 1-65535; ranges and automatic port selection are not
supported. At most 128 publications are accepted. Publication requires `bridge`;
host, none and routed reject it. OCI EXPOSE never publishes a port automatically.
Port reservation and rules commit before guest execution. Conflicts or any
preparation error roll back the entire setup, including earlier reservations.
Cancellation, ordinary exit and abnormal guest exit release the launch's ports.

Bridge DNS defaults to the installed resolver's usable non-loopback IPv4
servers, retaining search/options lines in a private read-only view. Loopback
stubs in another launch are not reachable. With no usable server, startup fails
explicitly; use repeated `--dns IPv4` or prepare the stored resolver first.
No public resolver is silently substituted. Explicit launch DNS also works with
host/routed; none rejects it. This snapshot is not an Android Private DNS/VPN
proxy. See [DNS](#dns) for its distinction from persistent installation policy.

Bridge and routed use the same backend for logical bridges, veth pairs, addresses and routes.
Private TCP/UDP ports map to native ephemeral ports, so containers can reuse the
same internal port. Root-fabric binds can publish real ports. Android interfaces,
routes and firewall rules are not changed. Supported nftables chains apply
IPv4 TCP/UDP filtering, DNAT, SNAT and masquerading to logical flows. Rules and
published ports commit atomically; unsupported expressions fail explicitly.
Unfiltered internal/outbound streams retain native data IO. Filtered/NAT flows
use an event-driven relay with cached decisions, not syscall-by-syscall packet
interpretation. Root-fabric published ports also use this relay.

Changes apply to existing relayed flows. A rule that would deny an already-open
direct native flow is rejected atomically with `EBUSY`; Shroot cannot insert a
relay into that kernel connection retroactively. Close such connections before
installing the restrictive policy. Addressed UDP retains its mapping until
socket closure or relay idle expiry.

This is not full network isolation. Backing ports remain reachable, inherited
native descriptors retain access, and IPv6, raw packets,
multicast/broadcast and device-bound sockets are unsupported. Routed `recvmmsg`
and ancillary types other than supported IPv4 packet information/TTL/TOS also
have explicit limits. Anonymous nftables counters count logical data transfers
and payload bytes, not physical network packets. See
[network contracts](../native/shroot/networking.md#network-namespaces).

### Docker Engine

Shroot can run stock Docker Engine, containerd and runc inside a guest-root
launch with `--network routed`. This is separate from `shroot install/run`,
which executes OCI image contents without a Docker daemon.

Docker 29's nftables backend is checked with overlay2, logical cgroup v2 and
without a userland proxy:

```text
--firewall-backend=nftables
--ip6tables=false
--userland-proxy=false
```

The older explicitly firewall-disabled profile remains a separate supported
configuration using Docker's ordinary userland proxy:

```text
--iptables=false
--ip6tables=false
--ip-forward=false
--ip-masq=false
--userland-proxy=true
```

Prepare private API filesystems and logical cgroups as in the
[Docker fixture](../native/guest-exec-lab/probe_docker_runtime.py).
VFS and overlay2 checks cover concurrent containers, ordinary
`docker run -p HOST:CONTAINER[/udp]`, connections from another Android UID,
outbound DNS/HTTP, occupied-port rejection and port release. Overlay2 also covers
bidirectional inter-container TCP/UDP.

This is not an unconfigured Docker host: nftables is Shroot's supported logical
flow model, not Android kernel firewall management. Native cgroup resource
limits are not supplied. Missing subsystems remain errors rather
than silently successful operations.

### Podman

Stock Podman with crun/conmon is checked separately, not inferred from Docker
success. The passing workflow uses overlay storage, ordinary bridge networking,
netavark's nftables driver, enabled logical cgroups and the original application
seccomp policy. Coverage includes image pull, TCP/UDP `podman run -p`, outbound
DNS/HTTP, bidirectional peer connections by container name, occupied-port
rejection and removal of containers, network rules and published ports.
Its `nofile`/`nproc` limits are explicitly set to inherited shell limits, rather
than attempting to raise Android hard limits.
`nproc` is now enforced against guest real UIDs within the launch; `nofile`
and the physical Android task ceiling remain native. The fixture retains its
explicit limits so its resource policy is reproducible.

The [Podman fixture](../native/guest-exec-lab/probe_podman_runtime.py) runs inside
a routed Shroot launch. No `--network host` bypass or Podman-specific runtime
branch supplies bridge connectivity. This does not certify arbitrary nftables
rules or general rootless-Podman configurations; supported operations and flow
semantics are described in the [network contracts](../native/shroot/networking.md#nftables-and-flow-forwarding).

For both engines, guest root is still real Android UID 2000. Enabled cgroups
provide logical membership and permissive settings, not enforced resource or
device limits.

Libc preparation is independent of daemon setup. See
[Alpine containers inside SteamOS](#alpine-containers-inside-steamos) for the
shared-registry workflow and the distinction between selection and acceleration.

## Guest Credentials

`--user NAME|UID[:GROUP|GID]` selects a launch-local guest identity from that
store's `/etc/passwd` and `/etc/group`. An explicit group suppresses automatic
supplementary groups; numeric UID:GID needs no account entry. Raw launches
without this option retain executor IDs. Preserved-ownership images use their
configured User, or guest root when it is empty; `image run --user current`
explicitly keeps Android IDs.

Real/effective/saved/filesystem IDs, groups, capability sets and `no_new_privs`
follow fork, threads and exec. Guest operations check this identity; the actual
Android UID, SELinux domain and kernel capabilities do not change. Package
managers can create users/groups, set ownership and configure services without
granting those users Android privileges.

Filesystem access checks include directory search, DAC/ACLs, sticky/setgid
directories, timestamps and executable mount policy. Read-only native
attachments retain their native checks. Account and capability changes authorize
only implemented guest operations; arbitrary device access and kernel-module
loading are not granted. Logical device nodes map supported device numbers to
explicit endpoints; unsupported data opens fail.

Authenticated Unix IPC uses captured guest credentials within the supported
transport; external peers see actual Android credentials. Session D-Bus works
as guest root and across independent clients without disabling authentication.
See [Unix credentials](../native/shroot/ipc-credentials.md) for implicit-message
and cross-launch limits. General set-ID metadata or stored file capabilities
do not automatically grant executable admission; sealed helpers use the explicit
[browser/image admission contract](#application-filters-and-browsers).

## Filesystem Restrictions

**Landlock is an enforced guest filesystem policy, not just a successful API
probe.** Arch pacman's default filesystem sandbox uses it even when the host
kernel has no Landlock support. Shroot implements the three Landlock syscalls
with ABI 1 filesystem rights.
Mutable ruleset descriptors use the existing typed-file transport. Applying a
ruleset installs an immutable thread-local domain; up to 16 domains intersect.
Fork/exec inherit the domain, whereas an existing sibling sharing files or cwd
does not acquire another thread's restrictions. Closing or adding rules to the
original descriptor cannot remove or widen an installed domain.

Rules retain logical object identity and store lifetime. File operations check
the selected dentry and its ancestry within the same namespace transaction,
before mutation or writable-open publication. Directory rename and backing
copy-up do not retarget the grant. ABI 1 rejects cross-directory rename/link.
Already opened data descriptions retain their authority; proc-FD reopening and
executable preparation recheck it. Ordinary data IO adds no policy RPC, and
tasks without a domain allocate no Landlock state.

Explicit rules currently require inode-backed targets. Native providers can
inherit grants through retained guest mountpoints; unsupported native rule
targets/mutations fail explicitly. Ambiguous descriptor hardlink ancestry is
denied rather than selecting a permissive alias. Cross-store mount ancestry and
full native-provider rules are not established. This is filesystem policy within
Shroot's compatibility model, not native LSM isolation: Landlock ptrace-domain
confinement is not implemented. Network/scoping and newer filesystem rights are
not advertised; existing network and debugger behavior is unchanged.

The ABI 1 fixture checks positive and negative access, attribute/FD validation,
hardlinks, symlinks, retained directory identity, policy stacking, preopened FDs,
proc reads, thread sharing and fork/exec including descriptor execution. A native
Linux VM runs the same assertions independently of the Android kernel.

## Application Filters And Browsers

Stock Debian Chromium has headless JavaScript/DOM and PNG-rendering checks
without `--no-sandbox`. Both its automatic user/PID namespace route and its
explicit set-ID helper route retain the application's original seccomp filters.
Firefox has a separate headless screenshot workflow. These are execution tests,
not a claim that every browser feature or security boundary is complete.

SteamOS Flatpak Chromium has been installed through Discover and launched inside
the Plasma Wayland session without disabling its sandbox. The GUI check loaded
an external page; `chrome://sandbox` reported Flatpak, PID/network namespaces and
Seccomp-BPF with TSYNC, with installed filters also observed on renderer processes.
Bubblewrap's `--disable-userns` uses enforced per-user, ancestor-scoped namespace
quotas, not a successful no-op. These checks do not establish kernel-equivalent
isolation or complete Flatpak support. The initial run used software graphics;
a subsequent local Flatpak GL extension with the installer's patched Mesa passed
three hardware Zink/Turnip WebGL pixel checks without GPU-process crashes, plus
Wayland GUI presentation, pointer input and normal closure. Sandbox and watchdog
remained enabled. The Turnip recipe now prepares the local GL.host extension
automatically, with runtime ABI admission and install/update triggers; see
[Flatpak GPU drivers](graphics.md#flatpak-gpu-drivers). Ordinary Flatpak launches
also pass the GPU checks without test-only driver selection or environment flags.
Shroot supplies a guest `/dev/fuse` and asynchronous FUSE mounts without native
Android FUSE permission. The stock document portal has passed temporary export,
read/write from Flatpak and live permission revocation on SteamOS. This is
separate from the browser/GPU check and does not establish every desktop file
chooser workflow. Stock `rofiles-fuse` and `squashfuse_ll` are also covered;
ELF/script execution, dynamic loading and private mappings work from the tested
SquashFS image. Concurrent append and inotify are supported, including changes
to append flags, rename cookies and open-but-unlinked watch lifetimes. Shared
mmap supports read-only shared views with daemon-confirmed write/truncate
updates; writable shared mappings and general external-data invalidation remain
unsupported.
See [FUSE ownership and limits](../native/shroot/fuse.md).

Stock snapd has a separate Debian/systemd fixture covering hello-world install,
run, refresh and complete removal, including a run under strace. Its launcher
sets `mount --make-rshared /` inside the private guest mount namespace before
snapd creates image mounts. This is not a change to Android's mount topology.
The tested kernel has no AppArmor; this verifies execution with snapd's reported
reduced confinement, not strict Snap isolation or arbitrary snap compatibility.
Ubuntu's stock Firefox Snap also passes Wayland GUI checks with its content
sandbox enabled. Prepared Turnip/Zink can be supplied through the official
`mesa-2404` GPU content provider, without rebuilding Firefox or copying host
paths into its namespace. See [Snap GPU drivers](graphics.md#snap-gpu-drivers)
for preparation and the distinction between WebGL and browser composition.

CPU topology is now available through the shared read-only native sysfs projection,
also checked inside Flatpak. Initial Discover setup also needed guest system
services and a user remote not yet fully covered by the installation recipe.
The [Flatpak browser fixture](../native/guest-exec-lab/desktop-workflows.md#flatpak-chromium)
also checks JavaScript and repeated normal exits inside that desktop session.
An independently activated KDE service can keep a separate supervised launch
alive after the browser exits; that is not itself evidence of a browser hang.

The supervisor preserves application signal handlers, alternate stacks,
non-dumpable state and installed seccomp filters. ERRNO/TRAP/KILL actions remain
effective. It prepares required descriptor interception before admitting an
application filter, rather than removing that filter when later IO needs it.
Guest namespace support does not require native unprivileged user namespaces.

`--admit-elf /absolute/guest/path` explicitly selects a sealed ELF snapshot with
logical set-ID metadata for one launch. Initial entry and reexec use that same
admission; actual Android credentials do not change. General stored set-ID
metadata is insufficient, and actual host set-ID executables are rejected.
Chromium's explicit helper test selects `--disable-namespace-sandbox` to choose
that route; its automatic namespace test needs no helper admission. The negative
control rejects an unadmitted helper before rendering.

Execution does not establish native-Linux sandbox equivalence. Interpreter and
library admission, mapped-code protection, complete descriptor/root confinement
and authenticated filesystem authorization remain incomplete. The same-UID
filesystem service does not automatically enforce a caller's seccomp domain.
Unadapted syscalls and inherited descriptors retain host authority. Chromium
child SIGTRAP exits are recorded independently of successful page output.

Guest GDB, LLDB, gdbserver and strace use the supervisor's
[nested debugger contract](../native/shroot/debugging.md), including attach/seize
within the same supervised launch. Another physical tracer cannot attach
concurrently; external attach and arbitrary crash reporters are not supported
by that contract. See [browser fixtures](../native/guest-exec-lab/browser/README.md)
and [interception](../native/shroot/interception.md) for exact assertions.

## Graphical Connections

The selected command service owns a session-scoped abstract Unix endpoint and
admits only that executor's actual UID. It transfers each accepted connection
over Binder to the app-UID protocol server. Binder carries admission and FD
ownership only; protocol bytes and SCM_RIGHTS buffers travel directly through
the connected Unix socket. There is no stream proxy or privileged renderer.
Closing the session or losing its owner closes admission; outstanding FD handoff
has a bounded acknowledgement deadline.
`ExecutorSocketEndpoint` serves both graphics and guest-file admission. File
connections retain per-session authentication and bounded IO; socket options
are configured by the executor before FD handoff, not by the app-UID receiver.
The helper releases its imports when its channel closes or its wrapped command
exits. It must not keep an otherwise completed guest launch alive.

Explicit `--socket-path SOURCE ENDPOINT` and `--socket-abstract SOURCE ENDPOINT`
arguments map exact guest connect addresses to that endpoint. Routes survive
fork/exec and environment replacement. The syscall adapter preserves the original
socket descriptor and kernel open-file description; no socket-node fabrication,
per-data-operation allocation or descriptor registry is involved. Other destinations
retain their normal permission checks. General guest pathname sockets use the
inode namespace described below, independently of graphical routes.

Wayland clients receive an absolute `WAYLAND_DISPLAY` and may establish separate
connections, rather than share one inherited stream. X11 maps both the pathname
and abstract display address using `--socket-resource-path` and
`--socket-resource-abstract`. These routes add a bounded attachment channel,
capturing the connecting task's guest credentials and IPC namespace. The embedded
server resolves legacy MIT-SHM IDs through that capability and receives real
backing and lifetime-lease FDs; it does not open the guest store or require host
SysV IPC. Read-only permissions, `IPC_RMID`, shared pixmaps and process death use
the common [shared-memory ownership](../native/shroot/shared-memory.md#embedded-x11-attachments).
Ordinary X11 and modern `ShmAttachFd` remain independent of this channel.
Its normal MIT-MAGIC-COOKIE-1 handshake remains
mandatory. Each guest launch writes the supplied authority into its private
runtime directory before starting D-Bus, so activated services inherit the same
authority. Session cookies are not persisted in `.desktop` recipes.

## Gamepad Input

[Linux gamepads](gamepads.md) attach to Shroot graphical launches through an
executor-authenticated, launch-owned endpoint. Android host focus selects the
input recipient independently of X11 or Wayland. The native input bus exposes
evdev/joydev, sysfs/libudev discovery and guest-private uinput with asynchronous
rumble handshakes. It never creates Android input devices or requires root.

The private device inventory does not hide CPU/NUMA topology. All launches,
including consoles without gamepad transport, and guest sysfs mounts project
native `/sys/devices/system/cpu` and `/sys/devices/system/node` read-only, when
available to the selected Android UID.
Their opened files retain native IO; network and device inventories remain owned
by their guest providers. This grants neither hardware write authority nor access
to other Android device trees, and does not make missing GPU drivers available.

## Prepared Userspace

The store must contain the application's complete matching libraries, data and
configuration. The runtime does not invent a Linux user, package records, DNS
servers, certificates or a machine ID. In particular, D-Bus needs an NSS entry
for the selected guest UID in the prepared system. Network clients need its
resolver configuration and CA trust store. GUI toolkits need fonts, icons and
their normal GSettings/GdkPixbuf/MIME caches.

`LinuxGraphicalEnvironment` owns one graphical-session wrapper for guest,
PRoot and chroot recipes. The distribution supplies `dbus-run-session` and
`dbus-daemon`, with its standard session configuration, listen address,
credential authentication, activation and limits. `dbus-run-session` owns
readiness and shutdown; the wrapper owns a private `XDG_RUNTIME_DIR`.
MagicDesk ships no D-Bus daemon and does not reuse Android's or Termux's bus.

## Coverage And Limits

The device baseline for these results is RM11/NX809J, Android API 36,
Linux 6.12.23, 4 KiB pages and actual UID 2000. The minimum supported kernel
remains 5.15; build and injected-error checks are not device coverage for another
kernel, firmware, page size or executor identity.

The fixture guide records commands, inputs and assertions. A rendered window,
successful API probe or passing package installation alone is not a complete
application, init or isolation test.

| Area | Checked workflows | Scope/details |
| --- | --- | --- |
| ELF and libc | Debian glibc, Alpine musl, static PIE/ET_EXEC, raw SVC, threads, signals, fork/vfork and exec | [Runtime fixtures](../native/guest-exec-lab/README.md#prepared-runtime-fixtures) |
| Files and IPC | Hardlinks, copy-on-write, overlays, watches, FIFOs, shared memory, SysV IPC and authenticated D-Bus | [Native contracts](../native/shroot/README.md#contracts) include failure and lifetime checks |
| Packages and development | APT, APK, DNF, pacman; accounts, compiler builds, Git/SSH, npm and Python environments | [Packages](../native/guest-exec-lab/desktop-workflows.md#distribution-packages-and-applications) and [developer workflows](../native/guest-exec-lab/developer-workflows.md#developer-workflows) |
| Systemd managers | Debian 257, Ubuntu 255, Fedora 259, Arch 262 and SteamOS; system/user managers and service activation | Focused targets are distinct from default-target boot |
| Distribution boot | Ubuntu, Fedora, Arch, openSUSE, Deepin and Manjaro default targets; Debian/openKylin with explicit module-capability drop | [Init matrix](../native/guest-exec-lab/init-matrix.md); SteamOS hardware units remain degraded |
| OpenRC and runit | Alpine PID 1, default runlevel and restart/stop; Void/Armtix stock stages and supervised services | Userspace service lifecycle, not complete hardware initialization |
| Docker Engine | Docker 29.9.1, containerd 2.4.2, runc 1.5.2; overlay2, nftables bridge and TCP/UDP publication without userland proxy; older VFS/proxy profile retained | [Explicit daemon configuration](#docker-engine), logical IPv4 flow filtering, not Android firewall management |
| Podman | Podman 5.8.7, crun 1.28, conmon 2.2.1; overlay, nftables bridge, TCP/UDP publication, DNS/HTTP, named peers and cleanup | [Routed launch and inherited limits](#podman); cgroups and application seccomp enabled |
| Browser sandboxes | Stock Chromium JavaScript/DOM/PNG with installed filters, Firefox screenshot, Electron/VS Code workflow | [Browser contract](#application-filters-and-browsers), not complete security isolation |
| Landlock and Bubblewrap | Positive/negative filesystem access, stacked domains and inheritance; pacman, Glycin and stock Bubblewrap workflows | [Filesystem policy](#filesystem-restrictions) and [namespace fixtures](../native/guest-exec-lab/namespaces.md#namespace-clients) |
| Debugging | GDB/LLDB breakpoints, stepping and locals; attach/seize, gdbserver and strace workflows | [Same-launch ownership and request limits](../native/shroot/debugging.md) |
| GUI and content | Debian/Ubuntu/Alpine editors through X11 and Wayland, input, clipboard, save/readback and actual process exit; GIMP and LibreOffice checks | [Application fixtures](../native/guest-exec-lab/desktop-workflows.md#distribution-packages-and-applications) |
| Desktops | Xfce in a retained X11 viewer, Weston, Plasma; Fedora GNOME devkit with private services | GNOME is llvmpipe/devkit coverage, not GDM login or GPU certification |
| GPU | Turnip Vulkan on Adreno 840 through X11/Wayland, GTK GLArea, X11 Blender, private KWin Wayland composition | [GPU fixtures](../native/guest-exec-lab/desktop-workflows.md#linux-gpu-fixture) and [installer profiles](#graphics-drivers) |
| SteamOS | Nested Plasma, Steam client and selected FEX game workflows; private-memory/JIT and audio-continuity checks | [Steam fixtures](../native/guest-exec-lab/desktop-workflows.md#holo-arm64-userspace); not arbitrary game compatibility |
| Application integration | Concurrent named environments, catalog identities/icons, retained PTY, CLI/MCP cancellation, file helpers, backup/restore and interrupted publication | [Environment workflows](../native/guest-exec-lab/README.md#named-environment-workflows); no Desktop required |

### Known workflow limits

- The installer launches applications and desktops directly; successful systemd
  or OpenRC fixtures do not mean the installer boots those managers.
- Packaged RTKit starts with its original chroot, credentials, process limit and
  watchdog threads, but real RT-priority requests can still return Android's
  `EPERM`. The PipeWire recipe does not require this privilege. See
  [process limits](../native/shroot/process-resources.md#process-limits).
- Qt 6.8.2's strict Wayland surrounding-text correction check can fail because
  the client omits the final text-input-v3 commit. Other tested IME, clipboard
  and dialog operations pass. See [Wayland coverage](wayland.md).
- LibreOffice Writer's X11 fixture uses xfwm4. GIMP's individual X11 dialog-close
  fixture and Calc's X11 insertion check have unresolved focus/editing results;
  these are not classified as Shroot defects without isolating the host/client.
- Galculator's rapid repeated-digit check encounters its 100 ms toggle-button
  reset even though both key pairs reach the client. No runtime input delay is
  applied to conceal that behavior.
- Driver enumeration is not rendering proof. Unpatched Zink Wayland can produce
  blank frames; the installer supplies the explicit non-DRM patch. Debian Mesa
  25.0.7 can deadlock during automatic X11 probing after failed Vulkan instance
  creation. Selecting a valid prepared ICD or explicit software rendering is
  a separate configuration, not a silent runtime fallback.
- Graphics helpers support guest file exchange, but live appearance updates are
  not integrated for Shroot launches. GUI profiles and GPU results do not certify
  every desktop service, driver or firmware.
- Minimal Astra userspace, Gentoo stage3/compiler checks and Docker inside a
  QEMU TCG VM are narrower fixtures, not distribution-boot or native-container
  certification. Full Gentoo package builds are not covered.

### ABI and isolation limits

Cgroups are permissive, not resource enforcement. Logical tmpfs is disk-backed
and its capacity options do not impose quotas. Proc/sysfs are bounded providers,
not complete virtual kernel filesystems. ID-mapped mounts, general native-device
creation, POSIX `mq_*` IO and arbitrary BPF facilities are unsupported. Mount
propagation and cross-supervisor descriptor transfer have documented limits;
private-provider descriptors cannot be transferred to an independent launch.

Adapted message batches also have an output-copy-fault timing limitation: a
native operation can consume data before later copying into the application's
memory fails. See [batch publication](../native/shroot/ipc-credentials.md#batch-publication-boundary).
Filesystem watches have [hardlink/rename and delivery limits](../native/shroot/watches.md#limits).
An unsupported operation remains an explicit error, not permission to disable
an application sandbox, switch to Android root or fabricate a successful result.

The [native runtime map](../native/shroot/README.md) is the entry point for syscall,
filesystem, process and descriptor contracts. Keep implementation invariants
there rather than duplicating them in installation instructions.
