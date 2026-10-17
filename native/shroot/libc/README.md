# Libc Source Integration

This directory owns Shroot's AArch64 libc hooks and their source integration.
The laboratory builders and the Linux installer consume these same files.
Nothing here is loaded into ART or replaces Android's Bionic libc.

## Hybrid Integration

There are two adapters, not one adapter per distribution:

- `integrate_musl.py` transforms the seven ordinary syscall wrappers, checking
  arities and parameter declarations. Whitespace and parameter names may vary.
- `integrate_glibc.py` transforms only `DO_CALL`, `INTERNAL_SYSCALL_RAW` and the
  `syscall.S` entry. Its shared wrapper definitions live in `glibc_syscall.h`.
- `musl.patch` and `glibc.patch` hold the shared lifecycle, TLS and fork changes.
  `glibc-private.patch` is an optional private-loader
  search-path change, with its directory supplied through a generated header.
- Glibc's cancellation implementation selects `glibc-cancellation.patch` only
  when its modern syscall boundary is present. Older async-cancellation wrappers
  are checked and retained; calls while async cancellation is enabled take the
  native route. Build-list insertions are checked structural transformations.
- `musl_entry.c`, `glibc_entry.c`, `glibc_entry_asm.S` and the common
  `../src/cooperative_entry.h` are copied as complete files, not duplicated in
  the patches.

`source_integration.py` stages the complete manifest. Every regexp has an
expected match count and wrapper-specific checks. GNU patch checks full hunk
context with `--fuzz=0`; line offsets are allowed, omitted context is not. A
missing boundary, extra match, changed signature, rejected hunk or unexpected
output file aborts before publishing any source changes. Reapplying to an
integrated tree is rejected. An IO failure during publication requires a fresh
source extraction; these trees are disposable build inputs, not an installed
libc. Installer build markers are written only after integration succeeds.

There is no global `svc` substitution and no heuristic fallback when matching
fails. Clone/vfork, signal-return and cancellation assembly retain their kernel
paths. This is bounded structural integration, not a C/assembly semantic parser
or a promise that arbitrary later libc releases are compatible.

## Delivery And Builds

`scripts/embed-libc-integration.py` generates the compressed **source** payload
inside `scripts/install_linux.sh`. It includes the adapters, patches, headers
and hooks. The user downloads one installer; no separate MagicDesk binary or
patch download is needed. Compilation takes place inside the guest on the
user's device with repository build tools. Python and GNU patch are guest build
dependencies, not Android or Termux prerequisites.

`build.sh` identifies the installed AArch64 musl/glibc version and the exact
original interpreter/libc bytes. It reuses a matching registry entry before
installing build tools. Otherwise it downloads the corresponding upstream source
release, applies the shared adapter, builds and runs an entry-ABI/file-IO probe
and a shell probe. Musl 1.2.5 and glibc 2.41 have pinned source digests; other
numeric releases use HTTPS and the same structural admission, printing their
downloaded digest. A changed source boundary fails rather than guessing.

Preparation checks for a cache hit in the selected environment first. A miss
installs build tools and compiles directly there, using explicit work/cache
bindings. No backup, restore or full-environment copy is needed. Named targets
are identified again after dependency installation, including another cache
lookup, so package upgrades cannot leave the build matched to an obsolete libc.
A changed libc during compilation rejects publication. Build packages remain
installed; failures do not roll back package-manager changes.
Source extraction uses `--no-same-owner`: archive UIDs are not part of a build,
and guest root cannot change Android ownership on the explicit work binding.
Rootfs/OCI imports and backups keep their separate metadata-preserving path.
OCI preparation uses one temporary environment from the requested image and
pins the original image's libc identity even if build dependencies are upgraded.
This never mutates the source image or adds an OCI layer. Successful build files
are removed; failed work is retained with its path for inspection. Each retry
uses a fresh work directory unless the registry already has a matching complete
artifact; partial work is not an incremental checkpoint. Glibc exports its own
`gconv` modules, but uses the distribution's locale and timezone data. Its private
loader searches the matching runtime libraries before application RPATHs; the
distribution libc is never overwritten.

## Shared Local Registry

The executor's environment library owns `libc/artifacts/KEY`, independently of
image/store format 17. `KEY` hashes a ten-line `shroot-libc-1` manifest: entry
ABI, family/version, recipe digest, original interpreter and libc paths/hashes,
and the relative replacement-loader path. This is a rebuildable local cache,
not an OCI layer or a downloadable MagicDesk runtime package. The downloaded
installer registers its own copy as the explicit `shroot libc prepare` recipe.
See the [user commands](../../../docs/shroot.md#optional-libc-acceleration) and
the [Alpine-in-SteamOS walkthrough](../../../docs/shroot.md#alpine-containers-inside-steamos).

`libc_registry.c` owns validated publication, discovery, hash caching and leases.
Publication copies regular files into the existing image-publication staging
owner, checks the exported ELF and atomically renames the complete build. A
builder retaining writable descriptors cannot mutate that published copy.
Root mutation events refresh the catalogue at exec, including in an already
running container engine. Hash caching combines file identity with inotify
invalidation; timestamps alone are insufficient on f2fs. Unavailable observation
recomputes hashes; it never treats an unknown state as unchanged.

`libc_selection.c` runs only for an admitted ELF interpreter, inside the caller's
captured filesystem context. It matches original paths and bytes plus entry ABI,
then attaches `/opt/shroot/libc/KEY` through the existing mount owner with locked
readonly/nodev/nosuid policy. The loader opens through the same filesystem and
noexec checks. Newer matching publications are preferred. Nested roots select
their own libc, not their parent's distribution or the daemon's libc.

An artifact's shared flock follows its directory FD and mounted duplicates.
Pruning takes an exclusive nonblocking artifact lock, retaining active mounts
even after the selecting registry closes. It removes all unused builds; it is
not a garbage collector for only unreferenced installed environments. Future
launches without a build use Base until it is prepared again. Shutdown releases
all registry, watch and mount descriptors through their existing owners.

`keep` preserves selection; `base` writes `/etc/shroot/libc-base` in that guest;
successful preparation clears it. Selection never downloads, compiles or changes
OCI source layers. Missing/incompatible builds and inaccessible attachment points
retain the original loader. A non-root/readonly guest needs a prepared empty
mountpoint; a new attachment after Landlock restriction is declined. Already
prepared inherited mounts remain subject to ordinary guest access policy.
Static executables and direct SVC calls retain the Base route.

This deployment remains experimental. Upstream version agreement alone does
not preserve distribution patches, build flags or every private-library ABI.
The installer currently selects preparation by default; release acceptance must
validate the full installed-environment path, not just source integration.
Source-patching tests and exact input hashes do not prove every distribution
program's private ABI compatibility. Explicit absolute library dependencies,
preloads, custom loaders and minimal images without a shell/build tools need
separate validation. The stock loader remains available through Base.

## Checks

After editing canonical sources, regenerate the installer:

```sh
python scripts/embed-libc-integration.py
python scripts/embed-libc-integration.py --check
python -m unittest scripts.tests.test_libc_integration
python -m unittest scripts.tests.test_install_linux -k libc
```

The first suite is device-independent: checked transformations, failure before
publication, exact-context patches, unrelated syscall preservation and embedded
source equality. CI runs it with the installer suite.

Apply both adapters to verified source archives without compilation:

```sh
python native/guest-exec-lab/test_libc_sources.py \
  --musl build/cooperative-musl/musl-1.2.5.tar.gz \
  --glibc build/cooperative-glibc-toolchain/glibc-2.41.tar.xz
```

The runtime fixtures and fresh-OS installer checks are separate stages; see
[the laboratory guide](../../guest-exec-lab/cooperative-entry.md). Musl's build
stamp includes its structural adapter and patch. Glibc resume receipts include
the structural integration digest and reject stale build trees after changes.

`test_mounts` includes registry publication, malformed entries, exact matching,
write invalidation, Base, readonly attachments, lease/prune ordering and FD
cleanup. `test_installer_libc.py` checks a fresh official rootfs; its
`--prepared-musl` mode reuses a compiled fixture and covers the unmodified
installer's cached preparation, repeated ordinary exec, a clean environment
and nested chroot without a heavy rebuild. This mode does not validate the full
compiler/package workflow or glibc deployment. The source check's
`--glibc-release VERSION` option fetches only the required integration inputs
from upstream release tags to test both lifecycle variants without a build.
Source integration has been checked against glibc 2.35, 2.38, 2.39, 2.40, 2.41
and 2.42; this is not a runtime-compatibility claim for those releases.
