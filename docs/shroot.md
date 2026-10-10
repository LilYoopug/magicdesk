# Shroot

Shroot is MagicDesk's experimental native ARM64 Linux execution runtime.
It runs prepared ARM64 ELF programs with glibc or musl through the explicitly selected shell or root
executor, without PRoot, chroot or Termux. It is not a
security sandbox: guest programs retain the caller's authority and unadapted
syscalls can access Android resources. Use trusted programs and prepared stores.

## Boundaries

`native/shroot` is C/assembly plus a standalone CMake build. It has no
Java tree, JNI entry points, Android framework policy or display ownership.
The app owns typed launch recipes, `.desktop` storage and lazy helper staging.
The existing shell, PTY and graphical services own invocation and presentation.
Renderer processes remain unprivileged.

Each launch captures its store, guest user, guest home, guest cwd, argv and graphics
connection. There is no current distribution, global guest root or singleton
per launch method. Separate guest stores and independent PRoot/chroot entry
scripts can be used concurrently. Each guest launch owns a supervised process tree
and one native namespace worker inside its supervisor; cancelling it does not cancel another launch.
Stores persist independently of those processes. Metadata operations on the
same store acquire a kernel file lock before entering SQLite and release it
after commit or rollback. Separate launches can share a store without exposing
ordinary internal transaction contention to guest syscalls. There is no polling
or transaction replay; data IO through opened descriptors stays native. An
external database writer that bypasses this gate still produces an explicit error.
Initial store admission prepares indexes for every foreign-key child lookup,
so collecting an overlay view does not repeatedly scan the whole store.
Retained worker reconnects and ordinary filesystem operations do not prepare
indexes; the schema format and file contents remain unchanged.
The supervisor handles regular-file seeks through retained kernel descriptors
without namespace RPC; directory cursors remain namespace-owned. Filesystem
RPC replies retain their connection until exchange completion, task cancellation
or client release, with event-driven progress and a bounded peer lifetime.
Ordinary open/stat and directory-read requests are handled directly by that worker through seccomp
notifications, without invoking a guest-side RPC. Protected accesses, O_PATH,
namespace mutations and directory seeks retain the task-affine adapter. Direct
broker directory reads prepare their bytes without advancing the shared cursor.
The existing OFD turn spans copying and kernel reply acceptance; only an accepted
successful reply commits the cursor. Cancellation after copying and failed or
partial output leave the cursor unchanged, without replaying a committed read.
Path and metadata requests with captured cwd/dirfd inputs use bootstrap-mapped
shared input/output and register control, without a temporary guest descriptor
or service socket per call. The file-table and filesystem turns capture retained
input origins before worker execution; later close/reuse cannot retarget the
accepted request. Origins retain backing-store and lower-layer maintenance
leases independently of the worker's SQLite connection, without duplicating
their directory descriptors or retaining data open descriptions. Store identity
uses the retained root, not its path or connection address; a sequential worker
may reopen the same store without accepting origins from another store.
Unknown explicit dirfds and stateful inputs use actual kernel
description capture, never pathname reopening or fabricated origins. When kernel
inspection is denied, a lazy table-owned send endpoint exports the exact inputs
to a supervisor-owned queue. Admission consumes one CLOEXEC infrastructure FD;
a full table returns EMFILE before execution. Subsequent exports need no free
guest slot. The endpoint follows dup, close, fork, unshare and exec ownership;
application descriptions are retained only for their accepted request.
After an ambiguous terminal mutation, channel reuse checks the actual socket
cookie and descriptor flags under the same table turn. A replaced/closed slot
loses only its annotation, never the application's replacement FD. Denied or
cancelled observation retains uncertainty rather than admitting another channel.
Both transports share request and result validation.
Protected metadata and restricted proc lookups use the same table-owned channel
through register-only control, without acquiring a mapped filesystem slot.
The file-table turn retains their borrowed input through original-site admission
and output publication. A verified proc-FD directory open uses a fixed task-local
path and returns its FD directly to the application; no scratch proc-root/result
descriptor or per-request socket is inserted into the shared guest table.
File opens, reopens and executable-object access use the same transport.
For `O_PATH`, the worker retains the open result
until the caller reopens it through the provider's proc FD; the existing
file-table publication gate observes completion, including caller death.
`O_DIRECTORY`, `O_CLOEXEC` and `O_NOFOLLOW` are preserved. Nofollow delivery uses
the stable physical backing name under the store/source lease, or `/.` for a
retained native directory. Backing identity is checked independently of logical
metadata, including retained lower objects after copy-up and unlink. A pure
O_PATH lookup without such a source uses the same table-owned channel to return
the retained result through SCM_RIGHTS, without repeating the lookup or opening
a private RPC socket. Output turns span fork-copied tables sharing that channel.
A kernel-written receipt in the existing shared mapping publishes installed
origins even when the receiver dies before acknowledgement. The supervisor owns
the receive queue and drains unreceived rights on cancellation, without closing
an installed application FD. Cold admission needs the infrastructure slot plus
the result slot; admitted channels need only the result slot. Native quota and
application filter denials remain errors.
Typed descriptor dispatch captures its annotation under the same file-table
turn as close/dup publication. A reused number cannot be classified from a
preceding descriptor's uncommitted close. The turn ends after retaining the
object, before application IO. Interrupted queued FD installations retire their
expired notification independently of queue readiness; a restarted proc request
releases the old unpublished carrier before creating another admission.
Temporary-file and mount-table results use atomic ADDFD_SEND under the
destination table turn, without a guest service FD.
Deferred FIFO opens retain their pin and rendezvous resources outside the guest
table. A short-lived supervisor child completes the blocking open without holding
the filesystem worker or table turns. It closes unrelated inherited descriptors,
returns one endpoint and is reaped through the existing SIGCHLD loop. Cancellation
kills the exact child and releases queued results; ordinary files create no child.
Guest-root changes retain the CLONE_FS turn through worker publication.
The guest adapter has no filesystem RPC client; native host clients retain RPC
for their own engine access. Other temporary adapter descriptors still require
terminal-lifetime coverage.
Namespace exec prepares the ELF, script-interpreter chain and loader on the
filesystem worker under the captured task context. The worker owns every image
descriptor from acquisition; only a pointer-free argument recipe returns to the
guest before kernel exec. The new bootstrap receives the retained images after
the kernel has separated its file table. Death during preparation, failed exec
and task teardown release the leases without leaving temporary image descriptors
in a surviving CLONE_FILES peer. Initial loading and worker preparation share
the same ELF and shebang parser.
Foreign `/proc/PID/exe` execution resolves the selected task image through that
same worker preparation. The supervisor captures its executable identity after
the process-access check; anonymous images retain their readable description.
Absolute paths, symlinks and relative proc dirfds share this selection, including
logical PID proc mounts. No temporary image FD enters the caller's file table.
Anonymous memfd ELF images retain their actual readable description through
exec, fork and process teardown. Their `/proc/.../exe` views use the common
typed control-file provider, preserving inode identity, seals, independent open
positions, shared dup positions and readonly/private mappings without reopening
the memfd through a host proc path. Image replacement publishes only after
confirmed exec; failed preparation releases its candidate. Ordinary store-backed
exec does not acquire this extra owner.
Proc-image snapshots use the same mapped request lifecycle. The worker owns the
writable construction file, accepts captured chunks, and delivers only the final
read-only/O_PATH result. Task death or rejected copying releases construction
resources without changing a surviving shared guest table. Reading the kernel
umask likewise opens status only on the worker, without caching or modifying it.
Mount-table opens deliver read-only/O_PATH results directly, with retained
provenance for subsequent metadata calls. Each guest mount view lazily retains
the native proc/dev mount entries and their kernel mountinfo descriptor.
Nonblocking POLLPRI generation observation invalidates those bytes on native
mount changes; failed observation invalidates the snapshot and returns an error.
Guest mount IDs, root visibility and mount policy are evaluated on every open,
not cached with the native entries. The namespace owns final descriptor release.
Proc-image snapshots retain the same
provenance. Path-based chmod/chown/utimens and statfs execute in the selected view
without temporary guest FDs. Inotify registration similarly resolves the watched
path on the worker while capturing the actual queue description; native proc
aliases retain task-affine lookup. Current-thread proc-FD reopening captures the
original descriptor once and delivers only the final open result. Native and
attached objects share the retained-object reopening primitive, preserving
independent offsets, deferred FIFO completion and readonly mount policy.
Regular-file/FIFO creation keeps its intermediate descriptors on the worker.
Guest capability sets retain Linux 5.15's credential bits independently of
backend availability. Dropping or inheriting them changes guest authority only;
no capability is added to the Android process. Each operation still checks its
namespace ownership, implementation and native access. Creating character/block
devices returns EPERM because native device creation is not authorized.
Existing native devices can be bind-mounted with their real
access permissions and per-mount nodev policy; no device-creation rights are granted.
Path chdir and truncate retain the selected object there; the caller executes
the final syscall through its leased proc path. This preserves CLONE_FS state,
RLIMIT_FSIZE and SIGXFSZ without a private guest FD, including current-thread
proc-FD aliases. Completion or task death releases the exact lease. Typed
control files reject native path mutation rather than exposing their carrier
for truncate; internal metadata selection retains their mount provenance.
Descriptor-based fchdir retains the original file-table and CLONE_FS turns from
input capture through task-local execution and adapter acknowledgement. Its
worker-owned origin publishes only after confirmed success; native rejection
preserves cwd and terminal loss leaves it unknown. Received, unannotated directory
FDs therefore need no temporary guest slot to establish the new cwd.
Current-thread proc-FD metadata, readlink and suffix traversal borrow the original
input instead of installing a temporary anchor. Cwd suffixes use the captured
filesystem context; proc-root paths use the selected guest root. Another guest's
executable readlink returns bounded mapped bytes after the existing process-access
check, without a guest file or a read syscall.
Proc-FD paths naming another thread retain logical mount provenance only when
the captured target shares the exact held file table. Kernel proc access and
backing identity validation still apply. Foreign pipe readlinks retain their
native pipe identity instead of requiring a filesystem path.
Current executable metadata and watches use a captured store-object identity;
the worker opens and releases its own target even after unlink. Mapped and native
RPC requests share this operand contract. Stateful operations still require the
actual open file description, not an inode or pathname substitute.
Xattr and POSIX ACL requests use bounded byte values in the shared mapping,
not guest memfds or returned data FDs. The worker captures input bytes before
execution and owns target selection, permission checks and copy-up.
The store's Android SELinux label is not a guest inode attribute: reads/removals
return ENODATA, writes return EOPNOTSUPP, and enumeration omits it. Native bind
attachments retain their real xattrs and kernel permissions. Guest file
capabilities and POSIX ACLs remain independent logical metadata.
Descriptor variants capture the actual input description and reject O_PATH. Both mapped
and native RPC transports support values up to 64 KiB and explicit output-copy
failure. Ordinary requests clear only their header, not unused value pages.
Protected regular-file seeks also stay native; table ordering prevents close/dup
from replacing the description between its type check and seek.
Socket identity, watch registration and watch delivery use the mapped transport
when their actual input descriptions can be captured. Watch reads reserve records
until task-local copying is acknowledged. Rejected copying restores readiness;
loss after offering the reply retires possibly delivered records without replay.
The worker owns completion, with no resource turn held across client delivery.
Peer credentials and all supplementary groups return as mapped bytes, without
a temporary identity FD. Full-table ordinary/protected callers retain short-buffer
and output-fault semantics. Connection and explicit-message snapshots retain
namespace-relative process numbers after sender reaping. External endpoints
retain native UID/GID authority; incoming PIDs are mapped into the receiver's
namespace, with zero for an invisible process.
Directory seeks use the same captured-description path, retaining the shared
kernel position across dup and descriptor-number replacement without a guest
RPC socket or a free guest FD slot. Task-affine directory enumeration uses mapped
output with copy acknowledgement before cursor commit. Active operations retain
the exact OFD; dup/fork aliases share its turn while independent opens remain
independent. Native self-kcmp identifies descriptions, not file names or inode
numbers. The ordinary worker path allocates no cursor entry when no asynchronous
read is active. Rejected copying preserves position; cancellation after offering
retires possibly delivered records without replay. Filesystem RPC joins the same
ordering and acknowledgement contract. Neither file-table turns nor SQLite
transactions span user copying.
Fork shares the buffer allocator for inherited mappings; exec prepares a new
mapping. Task and worker leases independently retain each request's storage
through cancellation. Unknown cwd and kernel-path operands use a short-lived
same-TGID helper with a private file table and copied FS context. It returns
captured O_PATH descriptions directly to the supervisor; no temporary guest
slot or retry of the filesystem operation is needed. FS/table turns remain held
through capture and exact helper reaping. Application filters remain effective.
After the helper opens a path, ordinary O_PATH custody uses its stopped private
table's proc-FD alias, not another pathname lookup or data open. Restricted proc
access and nofollow descriptions retain exact SCM_RIGHTS transfer. This lets
bind mounts retain an existing device even when Android denies data access;
subsequent device IO still obeys that denial. Stateful FDs are never reopened
through this path.
Native fchdir stays in the caller with the ordinary cwd-completion observer.
These paths use the same namespace engine and sealed-image catalogue.
Operation results and caller-owned output are independent of RPC framing; direct
directory reads use one reusable 64 KiB worker buffer rather than an RPC-sized batch.
The namespace owner reuses compiled queries and transaction programs, never cached
metadata or transaction snapshots. Node reads include transactionally maintained
name and child-directory counters; stat and directory membership need no counting
subqueries or second logical lookup. Native attributes and access checks remain live.
Optional `--statistics` profiles syscall stops, filesystem
operations, SQLite and CPU costs without per-call logs or clock sampling
on ordinary launches.

Actual UID 2000 and UID 0 are accepted without switching identity. Root is a
user choice, not a fallback or prerequisite. Neither the renderer nor a failed
command is elevated. PRoot continues to use the explicitly selected Termux
executor; prepared chroot scripts retain their existing root requirements.

## Commands

`shroot` manages Linux environments and launches their programs. Standalone
file downloads use `magicdesk download`; no Linux environment is required.

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
`/data/local/tmp/magicdesk-root/home`. Release tags retain their exact
installer, for example
[`v2.0.2/scripts/install_linux.sh`](https://raw.githubusercontent.com/mekhontsev/magicdesk/v2.0.2/scripts/install_linux.sh).
An older APK may lack commands required by a newer installer; use a matching
release tag when keeping an older MagicDesk version.

The script itself asks for the distribution, independent environment name,
GUI profile, graphics driver, locale, timezone and fonts. Additional questions
cover an optional guest account, X11/Wayland application entries, extra packages,
DNS, package-download cleanup and Arch's filesystem sandbox. The same choices
are command-line options; `--yes` suppresses questions. `--list` is read-only.

| Distribution | Source | GUI recipes |
| --- | --- | --- |
| Debian 13 | `debian:trixie-slim` | apps, Xfce, Weston, Plasma 6 |
| Ubuntu 24.04 | `ubuntu:24.04` | apps, Xfce, Weston |
| Alpine 3.23 | `alpine:3.23` | apps, Xfce, Weston |
| Fedora 44 | `registry.fedoraproject.org/fedora:44` | apps, Xfce, Weston, experimental GNOME devkit |
| Arch Linux ARM | `menci/archlinuxarm:base` (community image) | apps, Xfce, Weston |
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

Images and repository packages are trusted executable inputs, not sandboxed
content. `--image REF` selects another OCI source of the same distribution and
version; the guest architecture and OS are checked before package setup. Arch
uses a community publisher and performs a complete rolling userspace upgrade.
Package signing remains enabled; `--arch-sandbox disable-filesystem` is an
explicit, reported pacman opt-out, not required by the tested stock Arch workflow.
Package output and errors stay in the console.

Package setup uses the guest root account, without granting Android root or
changing the executor UID. `--create-user developer` creates a password-locked
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
it preserves GUI entries, locale, timezone, fonts and graphics profile. It does
not remove previously installed desktops when another profile is added. After an
interrupted image installation, inspect `shroot list` before choosing a
new installation or resuming. A package failure leaves the environment available
for diagnosis and retry.

New installs default to system DNS. Private DNS/VPN requires an explicit
`--dns IP[,IP...]` choice or a prepared image resolver with `--dns preserve`;
plain guest DNS does not reproduce Android's encrypted resolver policy.
No public resolver is selected automatically. For a new environment, system or
explicit DNS replaces the image's resolver through the existing offline DNS
command; `preserve` leaves it alone. Resume retains existing DNS.

#### SteamOS recovery image

```sh
sh ~/install_linux.sh --distro steamos --name steamos --yes
```

The installer downloads the pinned Valve ARM64 recovery archive with SHA-256
verification. A temporary, digest-pinned official `python:3.14-alpine3.23` OCI
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

Graphics default to software rendering through a guest-owned
`/etc/profile.d/magicdesk-graphics.sh`. A supported Adreno GPU with accessible
KGSL can use the optional Turnip profile:

```sh
sh ~/install_linux.sh --name debian --resume --gpu turnip
sh ~/install_linux.sh --name debian --resume --gpu software
```

Turnip setup installs distribution-specific build dependencies and compiles Mesa
26.2.3 inside the guest. The HTTPS source archive has a pinned SHA-256; the
non-DRM Wayland/Zink and capability-probed KGSL timestamp changes are embedded
in the installer and applied without fuzz. Turnip, Zink, EGL,
GLX and GBM come from that same build. Its GLX loader advertises the capabilities
of the effective backend when an application disables Kopper or its X server
lacks DRI3. Zink retains GPU rendering in that case and presents through the
frontend's CPU readback path. Its display buffer belongs to the rendered resource
and is reused across frames; direct Kopper presentation remains unchanged.
This is accelerated rendering with a frame copy, not zero-copy presentation.
Steam's CEF interface and animated GLX output have coverage in nested Xwayland
on Adreno 840. `--jobs N` controls compiler parallelism
(1-8, default 2). Allow several GB of space for sources, build files and libraries.
Build work stays in `/var/cache/magicdesk/mesa/` for resuming; completed libraries
have an immutable recipe-addressed prefix in `/opt/magicdesk/mesa/`.

A temporary profile explicitly selects that Vulkan ICD, DRI directory and EGL
vendor. Bounded Vulkan enumeration must report Turnip before an atomic profile
replacement enables it for new launches. Failure preserves the previous profile;
existing programs are not restarted. This suitability check is not proof that
every OpenGL application renders correctly. The complete build/render workflow
is verified on Debian; other distribution toolchains require separate validation.
Software fallback uses the distribution's
unchanged libraries. Neither profile replaces Android libraries, distribution
drivers or the APK renderer, and no privileged identity switch is performed.
`--gpu auto` first checks access to KGSL, then builds and probes Turnip when it
is available. An unavailable or incompatible GPU selects software rendering with
a visible diagnostic. Download, package and compilation failures stop setup;
they are not classified as unsupported hardware. Explicit `--gpu turnip` fails
instead of selecting software when its GPU probe fails.
The lab obtains the identical patch with `sh scripts/install_linux.sh --print-mesa-patch`.

The `plasma` profile adds both `Plasma Desktop (x11)` and
`Plasma Desktop (wayland)`. With Turnip selected, it additionally builds pinned
KWin 6.3.6 for Debian 13 or 6.2.5 for SteamOS from a checksum-verified KDE archive.
The shared DMA-BUF adapter and version-specific API changes are embedded
in the installer (`--print-kwin-patch [VERSION]`); no semantic patch engine, KWin fork,
APK dependency or system compositor replacement is involved. The recipe includes
Debian's Plasma dependency minimum. Work stays in `/var/cache/magicdesk/kwin/`,
and complete builds use immutable `/opt/magicdesk/kwin/` prefixes. Only the
Wayland desktop launcher selects those libraries, plugins and executables.
An unsuccessful KWin build retains the previous KWin selection. Explicit
`--gui plasma` also prepares this path when adding Turnip to an existing desktop;
`--gui keep` does not build a new compositor.

```sh
sh ~/install_linux.sh --distro debian --name plasma --gui plasma --gpu turnip
sh ~/install_linux.sh --name plasma --resume --gui plasma --gpu turnip
```

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

Focused RM11 checks under UID 2000 cover package setup, guest settings and resume
for all five distributions. Without managed Desktop, catalog-launched Mousepad,
Thunar and Xfce Terminal render through both X11 and Wayland on Debian, Ubuntu
and Alpine. Debian Xfce and Ubuntu/Alpine Weston also produce desktop content.
These launch/render checks do not certify every desktop feature. Fedora/Arch
GUI failures remain recorded, not counted as passes.

### Named environments

In a newly opened MagicDesk Shell console or terminal:

```sh
shroot install debian:trixie-slim --name work
shroot install alpine:3.23 --name tools
shroot list
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

The named-environment manager runs entirely through MagicDesk's selected shell
executor. It needs neither an installed Termux nor Python, external download tools,
PRoot or a Docker daemon. `GuestEnvironmentLibrary` owns names and dependencies;
`GuestOciRegistry` owns bounded HTTPS acquisition; the native image utility owns
validated import, snapshots, maintenance and launch configuration. Java management
is a short-lived child. The original shell execs the native runner, preserving
its controlling PTY and inherited graphical descriptors.

`install` accepts a public OCI registry reference, a local layout with `--oci`,
or a tar/gzip/zstd rootfs archive with `--rootfs`. Registry acquisition selects
Linux ARM64, supports anonymous Bearer challenges, verifies SHA-256 and sizes,
and never forwards registry credentials to another origin. Private registry
credentials, Docker-save archives and other rootfs compression formats are not
supported. Registry rate limits and authentication failures remain explicit errors.

Each name selects an independent writable store. Registry images and rootfs
archives reuse content-addressed sealed images; OCI images additionally share
verified layer bodies. `path NAME` returns the immutable store location for
existing shell/PTY/X11/Wayland recipes. `inspect NAME` includes that location,
source, image config and lower dependencies. Reusing a removed name creates a
new storage identity, never retargets an already resolved launch.

`launches NAME` lists live native launch owners from CLI, PTY and graphical
recipes alike. Each has an opaque launch ID, initial program/cwd, optional
application label and actual/guest UIDs. `stop NAME ID` requests cancellation of
that exact supervised tree. A pidfd and the supervisor's retained record FD
validate ownership; PID reuse cannot redirect cancellation. Acceptance is not
completion: list again to observe removal. Kernel lifetime locks distinguish
live records from stale records after a crash. This is an on-demand launch
catalog, not a process scan or a second supervisor. The terminal environment
picker exposes the same list with an explicit stop confirmation.

`run` retains Entrypoint/Cmd. `exec` overrides both with the explicit command;
it starts a new supervised process tree, not Docker-style entry into an existing
one. `login` uses the selected account's home and login shell from `/etc/passwd`
and accepts an explicit shell after `--`. Numeric users absent from that file
use `/`, `/bin/sh` and a numeric username; no account is created. Image launches
also supply HOME, SHELL, USER and LOGNAME defaults. Image environment and explicit
`--env` values override exec/run defaults; login uses account values unless
explicitly overridden. `--cwd` always selects the requested guest directory.
All three share user, environment, cwd, hostname and directory-attachment options.

`--magicdesk` explicitly enables the shared [Linux command channel](automation.md#linux-command-access):

```sh
shroot exec work --magicdesk -- magicdesk get_state
shroot login work --magicdesk
```

The supervisor borrows a launch-scoped key and read-only client mount at
`/run/magicdesk`, separate from image contents. It retains the owner connection
until the supervised tree ends; no heartbeat or per-syscall command work is added.
The image receives only empty mountpoint directories, not a secret or client copy.
Normal launches omit both the attachment and command environment. The same option
works with raw `--store`, local `image` launches and the terminal/shortcut picker.
Native Termux and PRoot reuse the same channel via `magicdesk-connect`; neither
depends on the guest runtime's kernel capabilities.

Installation accepts `--dns system` (default), `--dns preserve` or up to three
comma-separated numeric addresses. System DNS is a one-shot active-network
snapshot under the selected command identity, not a live Android resolver proxy.
Private DNS/VPN require an explicit policy because copying addresses cannot
preserve those semantics. No public resolver is chosen implicitly. Nonempty or
symlinked `/etc/resolv.conf` is retained. `shroot dns NAME POLICY --replace`
explicitly replaces it in an inactive environment; without `--replace` the same
preservation rule applies. Restore preserves the backed-up configuration.
The guest owns later DNS changes, certificates, accounts and optional services;
installation never executes package scripts.

The default library is `$MAGICDESK_RUNTIME/guest-environments`;
`MAGICDESK_GUEST_HOME` selects another executor-accessible, executable filesystem.
Catalog mutations are serialized and report busy rather than wait behind another
operation. Launch resolution and listing do not wait for downloads. `remove`
requires an inactive store. Explicit `prune` uses persistent dependencies and
native lifetime locks before deleting unused stores, images, layers and cached
downloads. Busy or uninspectable resources stop cleanup. Attached host directories
are never removed. Do not create unmanaged snapshots referencing library-owned
images: the catalog cannot discover dependents outside its library. Use portable
backup/restore for independent storage. Interrupted native removals retain a
retryable tombstone. Native import and backup share private, lifetime-locked
staging directories: the next publication or explicit recovery removes only
recognized abandoned staging, never an active writer or a published result.
Java management helpers terminate with their owner; `prune` reclaims abandoned
library work and download staging under the catalog lock. An interrupted name
publication does not expose a partial environment. Inspect published resources
before retrying an operation whose result was lost. There is no background GC.

Low-level prepared-store commands remain available:

```sh
shroot --probe
shroot --import /absolute/prepared-rootfs /absolute/new-store
shroot --store /absolute/store --home /tmp --cwd / -- /bin/sh -l
shroot --store /absolute/store --user root -- /bin/sh -l
```

`--import` accepts an immutable prepared tree, not an archive or distribution name.
It publishes atomically into an empty store and retains real metadata checks.
The default import bounds are 2 GiB and 200,000 entries. Unsupported objects,
metadata, source mutation, overlap and an existing populated store are errors.
It runs no package scripts, downloads nothing and does not manage mounts.
`--preserve-ownership` on import retains source UID/GID, permission and set-ID
metadata in the inode store, including the root directory. Physical backing
files still belong to the executor and never acquire kernel set-ID bits.

Local OCI layouts use the separate offline image command:

```sh
shroot image import /absolute/oci-layout /absolute/image --preserve-ownership
shroot image create /absolute/image /absolute/instance
shroot image run /absolute/instance -- /bin/sh
shroot image import /absolute/oci-layout /absolute/another-image --preserve-ownership --layers /absolute/layer-pool
shroot image rootfs /absolute/rootfs.tar.gz /absolute/rootfs-image
shroot image backup /absolute/instance /absolute/backup.tar.zst
shroot image restore /absolute/backup.tar.zst /absolute/restored-instance
```

Instances share immutable file bodies and copy up on mutation. Shared-layer reuse
and independent names do not require kernel mounts. An optional
pool shares regular files across imported images, with one final namespace per
image and no runtime traversal of layer chains. Backup requires a stopped store
and contains its shared data; restored instances have no lower dependencies.
Image Env,
WorkingDir, Entrypoint and Cmd feed the ordinary guest runner. `--bind HOST GUEST`
and `--bind-ro HOST GUEST` attach existing directories to one launch, also for
ordinary `--store` commands. Nested targets use declaration order, parent first;
each attachment retains its own readonly policy. Import/staging does not probe
guest-execution kernel capabilities; execution does. See
[images and filesystem views](../native/shroot/images.md)
for formats, explicit ownership mapping, source lifetimes and limitations.
This provides OCI image execution, not Docker Engine or a container isolation boundary.
The [application-image checks](../native/shroot/images.md#checks) exercise
stock entrypoints, network requests and persistent data, separately from import
and base-image shell execution. Unsupported image metadata and kernel interfaces
remain explicit errors.

The terminal picker and shortcut editor's Shell Linux method share the named
environment catalog with the CLI. Selection captures the immutable store path;
removing and reusing a name cannot retarget an existing shortcut. Raw prepared
stores and user-owned entry scripts remain explicit alternatives.
Its optional User field accepts the same guest user/group selection as the CLI.
Installed guest applications also feed Start's shared application catalog.
Discovery reads `.desktop` files from the image account's XDG data directories
without starting guest processes. Application identities include the immutable
environment ID; duplicate names in different environments remain independent.
The same recipe builder handles terminal, X11 and Wayland entries. Bounded PNG
icons use the shared bitmap decoder; unavailable icons use the ordinary fallback.
The cached snapshot refreshes explicitly through Start's refresh control or
MCP discovery, not on every menu opening. Package changes inside a running guest
require that refresh. Discovery does not supply Android file arguments or a new
MIME-handler bridge to guest applications.

Terminal commands use the shared retained PTY. An empty managed terminal command
opens the account login shell. Both X11 and Wayland recipes resolve XKB from
`/usr/share/X11/xkb` in their selected store, without a copied path in the UI.
`guest:/absolute/store` is the shared keyboard-source representation. The native
data exporter bounds depth, entries and total bytes, skips symlinks and publishes
atomically; Android copies the verified result into its private keyboard cache.
An explicit host-visible XKB directory remains available for prepared entry scripts.
`X-MagicDesk-GraphicsConnection=routed` selects independent guest connections;
ordinary recipes select `auto`. Each graphical launch prepares
its own guest `XDG_RUNTIME_DIR` and D-Bus session. File-environment identity remains distinct from
host paths; an unavailable guest-file helper is an error, never host fallback.
The packaged static file helper runs inside the selected guest filesystem and
identity. Imports stream into a private guest temporary directory and return the
actual guest URI; exports return read-only descriptors. No rootfs path guessing,
Termux bind directory or virtual-inode-to-host-name conversion is involved.

`guest.list` and `guest.inspect` expose the same catalog through MCP.
`guest.launches` and `guest.stop` address native launch ownership independently
of the caller that initiated a launch and of process-local MCP receipts.
`guest.start` runs explicit CLI arguments, `guest.status` observes bounded output
and completion by operation ID/revision, and `guest.cancel` closes only that
operation's owned command tree. Disconnecting MCP does not cancel work. Process
restart discards operation receipts; cancellation does not roll back committed
resources or authorize blind retries. These tools require the selected shell/root
executor, never Desktop, Termux or guest kernel support merely to start MagicDesk.

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
per-syscall allocation or descriptor registry is involved. Other destinations
retain their normal permission checks. General guest pathname sockets use the
inode namespace described below, independently of graphical routes.

Wayland clients receive an absolute `WAYLAND_DISPLAY` and may establish separate
connections, rather than share one inherited stream. X11 maps both the pathname
and abstract display address. Its normal MIT-MAGIC-COOKIE-1 handshake remains
mandatory. Each guest launch writes the supplied authority into its private
runtime directory; session cookies are not persisted in `.desktop` recipes.

## Guest Credentials

`--user NAME|UID[:GROUP|GID]` selects a launch-local guest identity. Names and
supplementary groups are resolved from that store's `/etc/passwd` and `/etc/group`,
not Android or another distribution. An explicit group suppresses automatic
supplementary-group membership; numeric UID:GID needs no account entry. Ordinary
launches without this option retain the executor's IDs and supplementary groups.
Preserved-ownership OCI images use their configured User, or guest root when it
is empty. `image run --user current` explicitly retains the Android identity.

`guest_identity` owns real/effective/saved/filesystem IDs, supplementary groups,
credential drops, virtual capability sets/securebits and no_new_privs. The supervisor tracks them per task across
fork, threads and exec. Libc's process-wide set-ID coordination remains libc's
responsibility. Auxv and admitted-image transitions use this same model.
`task_registry` publishes coherent identity, filesystem-root and retained
mount-view snapshots to the worker; both USER_NOTIF and RPC use them.
RPC checks the actor TID against the kernel
peer TGID. The registry lock protects snapshots only, not filesystem IO, and
ordinary requests allocate no group arrays or mount-tree copies. Mount views
are task resources independent of CLONE_FS, retained across fork and exec.

Guest `chroot` selects an inode-backed or explicitly attached native directory
through the common filesystem walker, with search/CAP_SYS_CHROOT checks,
CLONE_FS sharing, transactional unshare and exec inheritance. Absolute symlinks,
root-clamped `..`, getcwd and mount-table paths use the selected root.
Its identity includes the mount and
backend object, preserving native readonly policy. Existing cwd/descriptors remain
usable, so chroot alone is not confinement. Guest mount views support local
bind/move/remount, unmount and initial/attached-root pivot operations, with
user, mount, PID, UTS, SysV IPC, cgroup and offline network namespace owners. PID namespaces select
process/thread IDs, child admission, wait/signal translation and mounted proc
views through retained process resources. PID 1 adopts orphaned children and
closes namespace admission when its last thread exits. Namespace-aware proc
mounts and explicit native `/dev` binds can prepare a new root without host
mount privileges. Typed namespace-file binds retain their setns/ioctl authority after the
creating process exits. Mount-namespace copies prevent cyclic ownership.
New network namespaces expose a logical loopback control plane,
not Android interfaces or external connectivity. Anonymous Unix socketpairs and
inherited descriptors retain their IO authority. Private devpts views expose only
their allocated terminals, with native terminal IO and caller-owned controlling
sessions. Launch-local cgroup2 membership and permissive cgroup v1 devices views
do not enforce resource limits or modify Android cgroups. Cgroup namespaces
retain roots independently of membership; proc paths and new mounts use that
view, while existing mounts keep their roots. Cgroup2 device-BPF program IDs,
FDs and attachments have logical lifetime and query support, but the permissive
provider does not execute device filters or grant native BPF access. Other BPF
facilities and network hooks remain unsupported. Arbitrary unattached
native roots remain unsupported. See the
[process resource contract](../native/shroot/process-resources.md).

Offline IPv4 sysctls for unprivileged ports, ping groups and local port ranges
belong to the selected network namespace. Their ordinary proc IO uses the shared
typed descriptor transport, with namespace authority, retained mount policy and
explicit unsupported operations. These settings do not implement packet transport
or change Android's network settings. Namespace-mounted proc omits host-global
`sysrq-trigger`, `kcore`, `kmsg` and `keys`, which have no guest provider.

Logical sysfs mounts retain their opening network namespace. The offline view
exposes `class/net/lo`, its device attributes and a mountpoint for cgroups,
without binding Android `/sys`. Loopback attributes share the ioctl/netlink
state and remain live through setns, bind mounts and retained descriptors.
Host-network sysfs, additional device classes and attribute mutations are not
implemented and return explicit errors. This is a limited provider, not a full
kernel device tree.

The limited `mqueue` provider retains the selected IPC namespace and supports
directory metadata, enumeration and mount lifetime, including fsopen capture,
bind aliases and detached descriptors. It does not implement POSIX queue IO:
all `mq_*` syscalls return ENOSYS, and filesystem creation returns EOPNOTSUPP
instead of creating ordinary files. Android queues are never delegated.

`inode_metadata` enforces directory search, file access, ownership changes,
sticky directories, setgid-parent inheritance, watch registration and timestamp permissions against
logical inode owners/modes. `access()` checks real credentials for the whole
path; `faccessat2(AT_EACCESS)` uses effective filesystem credentials. File data
and already-open descriptors retain native kernel semantics; executable mappings
also enforce the selected mount's noexec policy. Metadata is
shared by hardlinks and retained across copy-up and independent launches.

This is virtual guest root, not Android root or a security boundary. Native
attachments, `/proc`, `/dev`, resource limits and SELinux retain real kernel
authority. Virtual capabilities authorize only implemented guest operations;
they do not become Android kernel capabilities. Guest capget/capset, KEEPCAPS,
bounding/ambient sets and exec share the same credential model, including
UID-before-GID service entrypoints. Internal Unix connections publish captured guest peer IDs
and groups; explicit SCM_CREDENTIALS messages use the same identity model.
External peers still see real Android credentials. Unmodified session D-Bus can
run as guest root, including independent clients sharing the store, without
disabling authentication. See the [IPC credential contract](../native/shroot/ipc-credentials.md)
for ownership, implicit credential messages and transport limits.
General set-ID metadata is not executable admission: only explicitly admitted,
sealed ELF helpers receive a set-ID transition. Stored file capabilities are
logical metadata, not Android capabilities or ordinary-exec admission.
POSIX access/default ACLs use the same guest identity model for named users,
groups, masks, chmod and parent inheritance. Their numeric IDs never become
ACLs on Android backing files. Objects without ACLs retain the ordinary mode
check without an extra ACL query. No kernel permission denial is fabricated as success.

Guest kernel audit is not implemented. `socket(AF_NETLINK, ..., NETLINK_AUDIT)`
returns EPROTONOSUPPORT before reaching Android's global audit service, regardless
of the selected real or guest UID. Stock account tools use their normal no-audit
path. This neither disables Android audit nor claims that a record was logged;
other socket protocols and real kernel denials retain their normal behavior.
Application seccomp ERRNO/TRAP/KILL actions still take precedence.

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

## ELF And IPC

The bootstrap maps the main ELF and its optional absolute `PT_INTERP`, validates their
load segments before exec and supplies a kernel-style initial stack and auxv.
The initial stack has explicit inaccessible guards and a grow-down mapping,
preserving the kernel's stack gap when applications reserve adjacent address space.
There is no distribution or loader-name allowlist. The selected stock dynamic
linker owns relocations, dependencies, TLS and `dlopen`. A native supervisor uses
selective seccomp TRACE and USER_NOTIF for adaptation; hot data IO, memory, futex
and signal operations stay native. Guarded scratch-stack leases are recycled per
address space, independently of libc thread-stack size. Fork, vfork and thread
clone retain kernel lifetimes. The application owns SIGSYS and alternate stacks.

Process resources have independent sharing rules. Root/cwd context follows
`CLONE_FS`; sparse descriptor-origin annotations follow `CLONE_FILES`;
semaphore undo follows `CLONE_SYSVSEM`. The kernel owns the actual descriptor
table, open descriptions, cwd and umask. `unshare(CLONE_FS|CLONE_FILES|CLONE_SYSVSEM)`
supports those flags separately or together. Guest-owned state is prepared
before the native call and committed only on its successful syscall exit.
Kernel errors and cancelled operations preserve the previous ownership.
Exec and `close_range(CLOSE_RANGE_UNSHARE)` also separate the annotation owner
alongside the kernel table without detaching shared filesystem context or
semaphore undo. Origin owners retain only O_PATH anchors. Filesystem opens from
both transports publish their origins in the same per-file-table order as native
dup/fcntl/close, close_range, fork and exec observation. Task-affine FD replies use
a retained shared kernel receipt, including receiver death before acknowledgement.
Data IO and open-file-description lifetime remain kernel-owned. Cwd changes and
relative-path capture use the same short-resource queue mechanism with an
independent CLONE_FS owner. Native completion publishes cwd provenance; failed
changes retain it. Initial namespace cwd uses this same path before guest code
loads. Current-thread proc cwd/FD aliases retain their origins through native
O_PATH capture; aliases of another thread's resources remain unknown instead of
borrowing the caller's metadata. Inherited/native descriptors and general
application SCM_RIGHTS tracking remain incomplete. Guest `CLONE_NEWNS` copies
the mount view and rebases root/cwd without retargeting existing descriptors.
Guest UTS names and SysV IPC have independent retained owners. CLONE_NEWUTS
copies hostname/domainname; CLONE_NEWIPC starts empty semaphore, message and
shared-memory namespaces. Fork/exec retain the selected owners. Existing SHM
mappings retain their original authority across namespace changes. These calls
do not change Android's UTS/IPC namespaces. CLONE_NEWUSER creates a nested
credential owner with writable proc ID maps, irreversible setgroups policy and
namespace-scoped capabilities. Metadata and IPC credentials use canonical IDs
internally and translate at the guest ABI. Proc UTS controls select the caller's
current UTS namespace, while map FDs retain their target and opening authority.
Typed proc FDs retain shared offsets across dup, fork and local SCM_RIGHTS;
cross-supervisor transfer remains unsupported. No ordinary data IO is intercepted
merely to identify these control descriptors.
Bind, recursive bind, move, readonly remount, detach and initial/attached-root
`pivot_root` use the same worker-owned graph. Normal unmount accounts for open
origins, queued/imported message references and other process roots. Exported
views publish immutable revisions through a retained single-writer stream;
receivers preserve their local object identities while applying topology updates.
Detached entries are reclaimed on subsequent mount admission only after their
origins, roots and children are released. Reused slots carry a new generation.
`fsopen`/`fsconfig`/`fsmount`/`move_mount` use those same filesystem providers
and mount graph. A typed context retains opening credentials and provider
namespace ownership; CREATE prepares the filesystem before placement. The
returned O_PATH mount descriptor can access its detached root and attach it in
the creating mount view. Dup, fork and local SCM_RIGHTS retain these owners.
Supported flag/string parameters cover the admitted tmpfs, overlay, proc,
devpts, cgroup, sysfs and limited mqueue providers. Reconfiguration, binary/path/FD parameters and
unsupported mount attributes fail explicitly; contexts cannot be transferred
between independent supervisors. Closing a context releases its unpublished
filesystem; detached mount storage follows the ordinary origin/graph lifetime.
`mount_setattr` updates the same readonly/nosuid/nodev/noexec policy by path or
mount FD, including recursively. All selected mounts are checked before any
policy changes; inherited locked attributes cannot be removed. Atime options
remain compatibility hints. ID-mapped mounts, nosymfollow and shared propagation
are not implemented.
Independent mounted inode stores retain their
backing leases across namespace copies and authenticated FD transfer, including
publisher exit and backing-directory rename. A watch instance can observe multiple
mounted stores through independently retained observation sources. Logical tmpfs
uses transient disk-backed inode storage. Its `size`, `nr_blocks` and `nr_inodes`
options are validated but permissive: they do not limit allocation, and statfs
reports backing capacity. Logical mounts accept atime flags as compatibility
hints while retaining backing timestamp behavior. Neither per-mount atime
guarantees nor kernel-memory accounting are provided. Overlay supports lower-only and writable upper/work mounts,
copy-up, whiteouts, opaque directories and retained descriptors. Publication of
the merged and upper namespaces shares one transaction. See the
[resource contract](../native/shroot/process-resources.md).
Mount nosuid/nodev/noexec and readonly policy follows the selected mount, not the
backing inode alone. Noexec covers executable/interpreter admission and mapped
execution, including retained FDs, fork, remap and later mprotect. Native data IO
is unchanged; file mappings and executable permission changes are observed by
the address-space owner.

The native memory owner retains captured private-file backing descriptions and
offsets independently of application FD numbers. Splits, replacement, remap and
fork retain or release that provenance through the mapping transaction; commit
allocates no metadata. Optional proc-memory access belongs to the exact address
space: CLONE_VM shares it, while fork and exec require independent capture.
The supervisor captures proc access while each fresh image is stopped before
entry, and independently at a non-CLONE_VM child's initial stop. Private file
mmap captures its source under the existing address-space and FD-table turns.
Protected tables and kernels without exact-task descriptor access use the
existing private-table SCM_RIGHTS helper, retaining the source-table turn until
its clone captures the description. Capture failures, memory pressure and lost
provenance disable repair; they do not relax mandatory noexec policy or revoke
otherwise native execute permission.
The task-affine private-memory preparer admits a clean executable file mapping
and materializes only the original COW pages through retained proc-memory access.
Unchanged pages keep their file relationship; file truncation and DONTNEED remain
kernel-owned. It validates the original VMA's permissions and supported advice
before constructing a candidate.
VMA policy is read once with writers quiescent; no pre-barrier snapshot is reused.
The unpublished candidate's pagemap soft-dirty bit preserves cleared-original
semantics without another address-space-wide smaps scan or a cached policy.
The replacement transaction retains the original
VMA at a reserved address until installation or rollback is confirmed. Cancellation
before publication restores the original; cancellation after confirmed publication
finishes cleanup. Failed restoration or missing syscall observation retains custody
and forbids resuming the address space without reconciliation or termination.
The supervisor applies this path automatically after native `mprotect` rejects
executable permission with EACCES on a tracked private-file range. Successful
native transitions are unchanged. It needs no preload, application-specific
patch or JIT-disable setting. A cold launch-tree barrier stops guest threads and
existing private helpers, then acknowledges a namespace-worker pause. Real wait
events retain their status, ordering and rusage; synthetic interrupts resume with
their original ptrace continuation. Interrupts already requested by syscall or
debugger owners are deferred to those owners, never consumed as barrier stops.
An interrupt acknowledgement may arrive after an ordinary stop won the race.
Helpers and replacement calls continue their current execution in place;
they neither replay the syscall nor mistake the pause for its result.
The worker uses existing eventfds, holds no
database/queue locks while paused, and leaves queued callbacks for normal dispatch.
Kernel-blocked `vfork` parents are already quiescent: mandatory VFORK_DONE
observation precedes their return to userspace. The barrier does not wait for
an interrupt that depends on resuming the stopped child.
Only the request's mapping helper runs during preparation. The original caller
executes each replacement syscall with an individually observed result. Expired
barriers or lost publication observations terminate the owned launch rather than
resuming an uncertain address space. Ordinary file IO needs no barrier or new
thread. Unsupported special VMAs retain the native error; an already protected
fork child without independently captured proc authority likewise remains native.
Focused device checks cover concurrent ordinary/nondumpable JIT writers, JIT
during `vfork` with child exit/exec and subsequent parent compilation, stock
SteamOS Plasma QML and repeated generated-code execution under guest GDB/strace.
Stock Chromium's sandbox-enabled JavaScript workflow is a separate regression
check; these results do not certify every application's mapping semantics.

Static PIE and fixed-address ET_EXEC use the same loader. ELF load alignment is
retained, including 2 MiB alignment; an occupied fixed-address range fails without
replacing existing mappings. Large valid images are bounded by address arithmetic
and the kernel's mapping limits, not a separate image-size cap. Freestanding ELF
without an interpreter or mapped program-header table is also supported. This
does not admit set-ID or writable/executable load segments.

Exec preparation retains both the validated ELF and its optional interpreter
across bootstrap exec. The resumed bootstrap maps those exact descriptors without
reopening names or repeating command preparation; failed exec releases both.
Path opening returns the canonical dentry path and object ID from the same namespace
transaction. That identity travels with the image across exec, rather than being
resolved again after opening or entering the new process. Descriptor exec captures
the retained object's identity independently of its current names.
Descriptor and relative-dirfd exec include open-unlinked programs. CLOEXEC scripts
fail rather than losing their interpreter input. Bounded shebang parsing accepts relative interpreters and a
short header without a newline, preserves the optional argument as one string,
and rejects a truncated interpreter name. `AT_EXECFN` retains the caller's spelling; descriptor exec uses
the Linux `/dev/fd/N[/suffix]` form. Namespace `openat2` validates its extensible argument structure
and supports scoped beneath/in-root resolution, symlink restrictions and mount
boundaries. Cache-only resolution returns EAGAIN; unavailable host-crossing
semantics fail explicitly. The direct backend does not implement scoped resolution.

Pathname Unix sockets are namespace inodes whose native transport is an
abstract kernel socket. The filesystem service commits bind and name publication;
ordinary payload traffic and SCM_RIGHTS stay in the kernel. Connection identity
and explicit credential messages use the separate IPC metadata authority. Names, permissions,
relative addresses, returned addresses, rename, stale listeners and unlink/rebind
are tested. Unlinking a name does not invalidate existing connections. Different
stores have independent names; explicitly abstract sockets retain the host's
shared abstract namespace and are not isolated.
Named pipes use the same namespace and kernel pipe payloads, without requiring
native FIFO creation under Android shell policy. Peer-open rendezvous belongs to
a cancellable supervisor operation outside namespace transactions. See the [FIFO contract](../native/shroot/fifos.md)
for readiness and watch limitations.
Unix `sendmsg`, `sendmmsg` and addressed `sendto` share captured outgoing custody.
Ordinary connected payload-only sends remain native. The worker owns address
resolution, credential validation and creation-time ancillary format. Adapted
peers use authenticated origin capsules; sockets inherited from or passed to
unadapted consumers retain native format. Exporting an already adapted socket to
a native peer fails explicitly rather than exposing its private protocol.
Application-filtered IO captures exact inputs through the table-owned channel,
without requiring another guest thread. Ordinary IO reuses an already admitted,
unambiguous channel under the same file-table turn. Without one, it retains
private-table helpers rather than consuming a new infrastructure FD. Native
peers retain task-affine sending and their actual kernel credentials.
Small messages use inline mapped storage; larger messages use owner-scoped host
buffers and bounded copy chunks, without splitting a datagram. Interruptible
readiness waits retain no FD-table turn. Stream WAITALL/low-water receives and
filtered recvmmsg use one native syscall on a cancellable host IO job, preserving
kernel batch completion, socket timeouts and credential boundaries. Publication
into application memory remains separate and has the limitations below.
Received rights have one supervisor-owned vector shared with worker inspection.
One typed request per message classifies identity tokens and managed watches,
without FD duplication or file-table/FS turns. Cancellation retains its sources
and mapped output until worker completion; publication installs only application
rights. Annotated rights use the same kernel-written mapped receipt as file
results, including O_PATH; neither manual FD-number selection nor a receiver's
proc-FD directory is needed. Terminal cancellation publishes the installed
prefix and drains only queued rights. Tests cover protected receivers, output
faults, full tables and unchanged application filters. See
[Unix IPC credentials](../native/shroot/ipc-credentials.md) for custody,
resource-limit and batch-publication contracts.

`/dev/shm` belongs to the guest store, including access relative to a `/dev`
descriptor or cwd. Execution preparation creates this directory with mode 01777
and guest-root ownership when absent; it does not overwrite existing metadata
or change the sealed image. POSIX shared memory, mmap, descriptor passing and unlinked
data work across independent launches. Store-scoped System V shared memory uses
native mapped backing files and a separate lazy IPC authority; it does not require
kernel SysV IPC support. A task-affine helper shares the address space but has a
private file table, so backing/transport descriptors never occupy application
slots. Mapping publication, detach and fork share an address-space turn; caller
death and exec retain helper ownership until kernel reaping. Application filter
denials remain errors. See [shared memory](../native/shroot/shared-memory.md)
for supported operations and lifecycle limits.
Store-scoped [SysV semaphores and message queues](../native/shroot/sysv-ipc.md)
support atomic vectors, SEM_UNDO, typed messages and signal-interruptible waits.
Argument/result copying is task-affine, including nondumpable programs; IPC
transactions do not span guest waits. Filesystem and SysV adapters share the
bootstrap-mapped buffer allocator, with typed protocol views and no per-call
packet FD. Blocked IPC calls release their buffer before waiting; the supervisor
owns the watcher and wakes the exact guest wait without inserting a guest FD.
No native SysV kernel support is required.
Inotify combines native backing-inode
data events with transactionally committed directory/name events. Independent
watchers sharing a store receive create/link/unlink/rename events without polling.
Subscriptions and bounded queues belong to the existing namespace worker; watch
reads use lazily armed descriptor classes and retained kernel-object identity.
Protected readers copy in their own task without changing dumpability; queue
delivery is acknowledged before consumption is confirmed. See the
[watch contract](../native/shroot/watches.md) for descriptor, hardlink,
protected-copy and kernel limits. The current store format is 13;
older stores are rejected, not migrated or deleted.

## Optional Kernel Support

Shroot's minimum supported Linux kernel is 5.15. Interfaces newer than that
baseline, their fallbacks and verification limits are recorded in
[kernel compatibility](../native/shroot/kernel-compatibility.md).
The version alone does not prove the selected executor's capabilities or firmware
permissions.

Guest executables are never loaded into the app or shell service with
`System.loadLibrary`. `shroot` stages a content-addressed immutable
version only when invoked. A launch first probes pidfds, subreapers, faccessat2,
executable mappings, selective ptrace and seccomp notifications in a child process.
It also exercises atomic descriptor publication and a private-table helper through
complete teardown before reporting readiness. Probe failure reports
the failed operation and errno. Other tools, Desktop, Termux and prepared chroot
remain independent; the APK and Desktop SDK floors remain API 34 and API 35.

The same bootstrap binary must remain available throughout a guest tree because
exec reenters its syscall gate. New APK versions therefore stage new bundles,
never repair or replace a live version. Old bundles are retained rather than
garbage-collected while detached terminals or descendants may still use them.

## Coverage And Limits

Device coverage is RM11/NX809J, API 36, Linux 6.12.23, 4 KiB pages, actual
UID 2000. Build and injected missing-syscall checks do not emulate old kernels,
API 34, root execution or 16 KiB devices. Those remain separate validation needs.

The native fixtures exercise Debian bookworm/trixie glibc and Alpine 3.23 musl, shell/exec, threads/signals,
namespace hard links and package transactions, process-tree cancellation and
software Wayland/GTK rendering with input. The installed runtime also runs
unchanged Debian Mousepad and Galculator on a private virtual display without
Desktop. Checks cover Mousepad editing and saving, fresh-process file readback,
keyboard quit with actual zero process exit, D-Bus activation of dconf and
settings persistence across independent sessions. Prepared NSS lookup, DNS and
HTTPS with certificate verification work on the tested device.
Routed X11 and Wayland both run Mousepad and Galculator, including repeated
independent clients in one retained session. The X11 negative check rejects an
incorrect cookie before a window is mapped.

Prepared Holo Core ARM64 preview (`mash-20251118.3`, glibc 2.42) passes SysV IPC,
FIFO, user/PID/mount namespaces and HTTPS as guest user `steamlab` under shell.
With compatible external Mesa bundles, captured changing frames confirm
Turnip Vulkan through Wayland, Freedreno OpenGL 4.6 through X11 and GLES 3.2
through Wayland on Adreno 840. GLES client lifetime beyond these short probes
needs further coverage. The ARM64 Steam client updates, identifies its local
CEF connection with unmodified `lsof`, and renders the sign-in form through X11.
Process-access checks remain active; no sandbox-disable flags are supplied.
These are prepared-userspace checks, not a booted SteamOS session, Plasma
desktop, Steam login or game compatibility claim.

Installed `.desktop` recipes use the shortcut editor's actual launch builder.
Both protocols pass bidirectional Unicode clipboard exchange, Mousepad saving
with fresh-process readback, simultaneous Mousepad/Galculator launches sharing
one store, recipe reuse, and protocol close followed by actual zero-status
process exit. Window destruction alone does not end a still-running launch
command. File workflows check child-dialog cancellation, opening another guest
file, Save As, overwrite confirmation, directory creation and inaccessible paths.
Document titles and actual contents are checked independently. Input awaits the
dialog's Android host and focus, not merely its native map; X11 transients use
native-family events rather than assuming entries in the toplevel catalog.
The separate rapid repeated-digit Galculator check exposes the application's
100 ms toggle-button reset: a second accelerator can toggle the digit off and
be ignored by its handler. Client-side Wayland tracing confirms both key
press/release pairs; repeated digits work in Mousepad. No input pacing or
application-specific runtime workaround is applied. These checks do not
establish compatibility with arbitrary toolkits or GPU clients.

The Debian trixie Qt 6.8.2 software fixture passes real Android IME composition,
Unicode commit, append, field switching, private PINs, caret geometry and IME
insets, plus bidirectional Unicode clipboard exchange, a dependent dialog and
zero-status protocol closure. The strict surrounding-text correction check
fails: Qt can omit text-input-v3's final commit after deletion. A separate run
explicitly omits that stage; it is not counted as a correction pass. The same
client behavior and protocol boundary are documented in [Wayland IME coverage](wayland.md).

Alpine's stock Mousepad passes the same X11 and Wayland window, pixel, keyboard,
save/readback and zero-exit checks. Both libc fixtures cover tiny thread stacks,
nested signal file calls, failed exec, vfork, spawn file actions/masks and 64 execs
without accumulating seccomp filters. Independent launchers share pathname IPC,
POSIX SHM, file-data notifications and open-unlinked lifetimes; another store
does not resolve their names.

The prepared Debian Xfce session runs in one retained X11 viewer without
MagicDesk Desktop: xfwm4, panel, desktop, terminal and Mousepad. Tests check
editing, saving, WM resize, viewer detachment/reopening and zero-status logout.
Readiness awaits both shell surfaces and Xfce's D-Bus Idle state, not a delay.
This fixture selects software rendering and lacks optional system-bus services;
it is not a complete booted Linux system or a GNOME certification.

The Fedora 44 GNOME 50.5 devkit fixture runs stock GNOME Shell/Mutter with a
private PID namespace, proc mount and `/run`, a system D-Bus daemon, and a
developer-owned session bus, PipeWire and WirePlumber. It checks rendered pixels,
Alt+F2 and a real GNOME Text Editor window inside the desktop, then releases the
graphics session and virtual display. The renderer is llvmpipe. This is not a
GDM/systemd/logind login session, hardware-acceleration certification or a claim
that every GNOME system service is available. A separate service fixture checks
system-bus authentication and an actual PipeWire protocol query.

A separate Linux Mesa 26.2.3 Turnip/KGSL fixture runs `vkcube` on Adreno 840
under UID 2000 through both Wayland and X11. It checks changing Android pixels, 600 submitted
frames and zero process exit. The driver is built from unmodified Mesa sources
and installed only in the test store, not Android or the APK. Device enumeration
alone is not this check. Other GPUs, drivers, zero-copy presentation and performance
comparisons remain unverified.

Fresh preserved-ownership images run ordinary Debian APT and Alpine APK as guest
root under actual UID 2000. Focused checks cover signed repositories, dependency
installation, scripts/triggers, reinstallation, removal and subsequent installation,
without force-not-root or package-manager sandbox overrides. Debian installs
hello, curl, jq and ca-certificates including certificate update triggers; Alpine
installs curl, jq and D-Bus including its logical set-ID helper metadata.
`test_credentials_runtime.py` records exact images, commands and build identity.
These are bounded package workflows, not arbitrary maintainer-script or
complete-distribution compatibility. Kernel mounts, device creation, capabilities
and system-service startup may still fail. Executable-memfd scripts remain subject
to the actual Android execution policy.

Additional image checks cover Ubuntu 24.04 APT with systemd package configuration,
CentOS Stream 10 DNF, logical account management and authenticated session D-Bus.
Ubuntu Mousepad is checked through X11 and Wayland with editing, saved-file readback
and clean exit; QEMU user-mode runs an x86-64 ELF with file IO and fork/wait.
These are userspace workflows, not booted systemd or virtual-machine certification.
The [image coverage](../native/shroot/images.md#checks) also records server,
language-runtime and compiler checks. Stock GDB live debugging uses the
[nested debugger contract](../native/shroot/debugging.md), with explicit
request and lifecycle limits. Stock Arch pacman retains its filesystem sandbox
on a host without Landlock through the guest filesystem policy.
Minimal Astra ARM64 userspace and Docker inside a QEMU TCG virtual machine have
separate checks; neither establishes booted-distribution compatibility on Android.
Gentoo ARM64 stage3 passes userspace and GCC/pthread/fork/file checks. Image import
reports omitted native `/dev` nodes instead of creating devices. Its signed repository download
passes; complete Portage synchronization and package builds remain unverified.

Official ARM64 VS Code with its Electron sandbox flags retained and Microsoft
C/C++ uses stock GDB through both the integrated-terminal FIFO transport and
stdio pipe transport. The fixture checks a breakpoint, stack/local inspection,
step, changed value and normal exit; it does not establish full sandbox isolation.
Ubuntu developer workflows cover authenticated Git clone/push over loopback SSH,
CMake/Ninja build/test/install/incremental rebuild, npm install/ci with workers,
filesystem notifications and HTTP, and pip venv/PEP517 C-extension wheel workflows.

The named-environment workflow checks fresh Debian and Alpine installation,
APT/APK GUI packages, account login and concurrent operations through the
installed APK under UID 2000. X11 and Wayland checks cover simultaneous editors,
keyboard input, bidirectional clipboard, saved-file readback and client closure.
File-helper checks verify import, descriptor export and owner-loss cleanup.
Backup, deletion and restore retain saved content under new storage identities
and support graphical relaunch. These checks use a virtual display without
Desktop, HOME acquisition or a Termux executor.

Installed-catalog checks cover independent Debian/Alpine application identities,
X11/Wayland rendering, terminal ownership and exact CLI/MCP cancellation without
stopping another launch. Recovery checks kill MagicDesk during a native restore,
reopen it, verify helper termination and intact catalogs, then prune and restore
the same archive successfully. Native fixtures separately interrupt import and
backup, preserve active staging and reject staging symlinks. These are process
failure checks, not power-loss guarantees.

Virtual-root IPC checks run stock Debian and Alpine session D-Bus, independent
root clients and a rejected different-user client. Debian additionally passes
GDBus service activation, caller-UID lookup and bidirectional FD delivery.
Kernel-generated implicit credentials are not translated. Debian account-tool
checks cover group/user creation, modification, supplementary membership, named
launches, home ownership and deletion. A non-root guest is denied and leaves
group files unchanged. D-Bus package configuration creates the messagebus account
and completes with a clean dpkg audit. The prepared image's service-start policy
remains in force; this is not system-bus or init-system certification. The daemon's
FD-limit warning retains the real kernel denial.

Static glibc and musl fixtures cover ET_EXEC/static PIE, 64 KiB/2 MiB alignment,
constructors, TLS, pthreads, heap, fork and descriptor exec. A separate
freestanding assembly program verifies raw SVC without libc or mapped ELF headers.
GIMP's Wayland fixture checks rendering, a keyboard-opened dialog and zero exit.
LibreOffice Writer/Calc Wayland checks edit an ODT/ODS document, verify client text through
the clipboard, save it, close with zero process exit and read the saved XML through
a fresh guest process. Writer readiness uses its actual text-input publication,
not a settling delay. The Wayland clipboard filters unsupported private MIME
entries individually, retaining valid text offers from the same source.
Writer also passes the edit/save/readback workflow in an X11 viewer with xfwm4.
The X11 checks use WM_CLASS rather than assuming a Wayland app_id. Without the
window manager, Writer does not publish a window within the test deadline.
GIMP's individual X11 host without a window manager opens its new-image dialog,
but the keyboard-close fixture times out with native focus still on its parent.
This fixture does not establish successful dialog interaction; host/client focus
and event readiness need separate investigation.
The Calc X11 insertion check fails: the cell contains the typed text instead of
that text followed by the original content. Neither observation is classified
as a guest-runtime defect without isolating client, input and window-manager behavior.

Debian Blender 4.3.2 renders its viewport through X11/GLX with Linux Mesa 26.2.3
Zink/Turnip on Adreno 840 and exits normally. The Debian installer's profiles
are checked without test-injected driver overrides: Blender X11 closes with
zero status under both Turnip and llvmpipe; GTK GLArea checks four colored
regions, an input-driven frame and closure through X11/GLX and Wayland/EGL.
The Turnip profile uses the explicit
[non-DRM Wayland patch embedded in the installer](../scripts/install_linux.sh).
The tested Debian Blender package has only the X11 display backend.
The unmodified Zink Wayland control produces blank frames despite reporting the
hardware renderer. Patched sources and libraries stay in isolated fixture paths;
neither Android nor APK drivers are replaced. These checks are not complete
Blender editing or arbitrary OpenGL application certification.

Linux driver discovery belongs to the prepared userspace. A Turnip library in
`/opt` is not discovered without a Vulkan ICD manifest in a standard guest
directory or an explicit `VK_DRIVER_FILES`. Debian Mesa 25.0.7's automatic X11
Zink probe deadlocks when `vkCreateInstance` fails: its error cleanup reacquires
the still-held instance lock. This can block GTK before window creation, even
for a text editor. Selecting the prepared Turnip manifest, or registering that
same manifest under `/usr/share/vulkan/icd.d`, passes the Mousepad edit/save/close
workflow without forcing software rendering. An explicit llvmpipe run is a
separate control, not the runtime's default or an automatic fallback.

## Filesystem Restrictions

Shroot implements the three Landlock syscalls with ABI 1 filesystem rights.
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

The production supervisor preserves application signal handlers, alternate stacks
and installed seccomp filters. Focused tests cover ERRNO/TRAP/KILL precedence,
protected descriptor metadata, nondumpable exec, non-leader exec, job control and
retained descriptors. Kernel-only calls share one policy definition between the
domain checker and the seccomp fast path; argument-dependent permissions compare
all 64 bits. Identity, namespace and filter-state changes retain their observers.
Before an application installs its own seccomp filter, the runtime prepares
future typed-descriptor IO for that thread group. Receiving or duplicating a
virtual file then needs no later filter installation or RLIMIT_NOFILE query.
The application filter is replayed unchanged; its denials remain effective.
This broadens FD interception only for application-filtered workloads. Other
programs keep the lazy descriptor-class path. Restricted proc roots preserve
already-opened descriptions and ordered publication of their duplicates.
Implicit and mounted proc views retain the target's nested PID-number chain.
Protected access uses task-affine export and same-site replay
without restoring dumpability. A second physical tracer cannot attach concurrently.
Guest debuggers within the same launch use the supervisor-owned
[nested debugger contract](../native/shroot/debugging.md); external attach
and arbitrary crash-reporter compatibility are not established.

`--admit-elf /absolute/guest/path` explicitly selects an ordinary ELF for a
launch-scoped sealed snapshot with logical set-ID metadata and credentials.
Initial entry and reexec use the same contract. Real credentials remain UID 2000
in the tested shell scenario; the source file is not modified, and actual set-ID
files remain rejected. Logical credential drops and no_new_privs are enforced
by the supervisor. Other operations retain real permission denials.

The [production browser fixtures](../native/guest-exec-lab/browser/README.md)
check stock Debian Chromium with its selected ordinary helper, three fresh profiles,
calculated JavaScript/DOM results and PNG output. The explicit set-ID route
(`--setuid-route` in the fixture, Chromium's `--disable-namespace-sandbox` selector)
passes with real installed application filters, admitted helper credentials and
process completion. Automatic selection uses the user/PID namespace route,
including nested PID namespaces and a run without helper admission. Both routes
retain Chromium's application filters and do not use `--no-sandbox`.
The set-ID negative control rejects an unadmitted helper before rendering.
Firefox has a separate headless screenshot workflow.

These results establish application execution, not complete security isolation.
The restricted proc-root policy and ordinary guest chroot do not establish
native Linux sandbox equivalence. Interpreter/library admission,
mapped-code protection, complete descriptor/root confinement and authenticated
filesystem authorization remain unfinished. The same-UID filesystem service does
not automatically enforce a caller's seccomp domain. Unadapted syscalls retain
host semantics, and Chromium child SIGTRAP exits are recorded separately from
successful page execution. See the [interception contract](../native/shroot/interception.md).

Guest file sharing uses the selected guest's authenticated helper; live appearance
updates are not integrated for this launch method. Kernel permission denials
remain failures. Native unprivileged user namespaces are unavailable in the
tested shell control. The guest user-namespace model does not require their
kernel implementation and does not establish equivalent security confinement.

The focused watch suite checks Debian GIO directory notifications from an
independent writer and stock D-Bus config-watch registration/session requests.
Installed-APK Debian and Alpine workflows verify Mousepad's external-change
notification and actual reloaded text, plus Thunar's live external file creation,
selection/rename and reaction to moving the viewed directory. Both close with
zero process status. These prepared images lack some optional desktop services;
working session buses and GUI workflows do not certify system-service startup
or arbitrary package configuration actions under virtual root.
Wayland publishes a logical monitor before client
startup and replaces it when an Android host attaches; GTK's initial
monitor-scale warnings are absent in these checks. The kernel process name identifies the guest executable after
each exec. Current-process/thread `cmdline` and `auxv` opens produce guest-image
snapshots with native read/seek afterwards; the worker allocates an unlinked
construction file only on those explicit opens, not on ordinary IO. The caller
needs only the final result slot, including when nondumpable. Namespace `/proc/self/exe`
open/stat retains executable inode identity after unlink, path reuse and close_range,
without a permanent hidden FD. General foreign-process proc aliases, snapshot stat metadata and
descriptor-exec readlink's original dentry identity remain incomplete. The direct
backend retains path-based executable reopening. This is not a fully virtualized procfs.

The installed CLI also retains the shared terminal's controlling PTY: interactive
dash job control, Ctrl+Z/fg/Ctrl+C, detachment and return to the Android shell
were checked on the device above, without Desktop.

The [native contracts](../native/shroot/README.md) describe syscall,
filesystem, execution-policy and lifetime limits. The
[fixture tools](../native/guest-exec-lab/README.md) retain signed package inputs
and exact device observations separately from the shipped runtime.
