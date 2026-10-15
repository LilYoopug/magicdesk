# Guest Browser Fixtures

These fixtures build and test the production native runtime in
`native/shroot`. They do not contain a second syscall implementation.
Use a prepared disposable Debian or Alpine store with matching browsers, libraries, fonts
and helper fixtures, never a personal browser profile.

The runtime supports application filters but is **not a complete security
sandbox**. Real executor credentials remain UID 2000 in these tests. The
[interception contract](../../shroot/interception.md) defines ownership,
logical image admission and remaining isolation limits.

## Build And Run

`build.sh` builds the production execution helpers. SQLite uses the pinned
production dependency, with `MD_SQLITE_BUILD` optionally selecting its existing
build directory.

```sh
sh native/guest-exec-lab/browser/build.sh build/guest-browser
python native/guest-exec-lab/browser/run.py --build build/guest-browser --store DEVICE_GUEST_STORE --expect-artifact /tmp/NEW_FIREFOX_PROFILE/page.png -- /bin/sh -ec 'mkdir /tmp/NEW_FIREFOX_PROFILE; exec /usr/bin/firefox-esr --headless --no-remote --profile /tmp/NEW_FIREFOX_PROFILE --window-size 800,600 --screenshot /tmp/NEW_FIREFOX_PROFILE/page.png "data:text/html,<h1>MagicDesk guest browser</h1>"'
python native/guest-exec-lab/browser/test_browser.py --build build/guest-browser --store DEVICE_GUEST_STORE
```

The full-browser fixture defaults to Debian's packaged helper at
`/usr/lib/chromium/chrome-sandbox`; `--helper` selects another guest path. It must
match the helper actually used by Chromium: the browser prefers a sibling
`chrome-sandbox`, while `CHROME_DEVEL_SANDBOX` is a fallback for eligible
user-managed builds, not an override of that sibling. See Chromium's
[helper selection](https://chromium.googlesource.com/chromium/src/+/main/sandbox/linux/suid/client/setuid_sandbox_host.cc).
The test explicitly admits that ELF with `--admit-elf`. Guest set-ID metadata
does not turn its backing into a host set-ID executable or grant Android root.
All four runs explicitly select the same guest user, `2000:2000`: three admit
the helper and the fourth does not. With the automatic user/PID route, all four
must render; no helper is executed or elevated. With the explicit set-ID route,
the fourth must reject the unadmitted helper before rendering, installing
application filters or changing its proc root. Omitting both `--user` and
`--admit-elf` would omit the explicit guest-credential check and is not an
equivalent admission control.

`--setuid-route` explicitly selects Chromium's set-ID sandbox using
`--disable-namespace-sandbox`, while retaining its seccomp filters and helper
admission checks. It does not use `--no-sandbox`. Automatic selection uses guest
user/PID namespaces, including the zygote's PID 1 and nested child namespaces.
Report the selected route; an explicit set-ID pass is not an automatic
namespace-sandbox pass.

The separate credential and retained-resource fixtures use an ordinary mode-0755
copy at `/tmp/md-chrome-helper-ordinary`, invoked directly for helper IPC and
renderer controls. Full-browser helper selection and admission rejection belong
to `test_browser.py`.

Each run stages an immutable helper bundle and records device/build identity,
actual UID, hashes, command, output, exit status and console cleanup. The
supervisor owns only its newly created process tree. An event deadline fails and
cancels it after `--deadline-seconds` (5 to 120); an outer bound covers cleanup.
No Android task is traced, no display acquired and no kernel policy changed.

Exit zero alone is not rendering success. `--expect-artifact` rejects an existing
path and checks the resulting PNG signature; visual content needs separate
inspection. `--expect-output` requires an explicit marker. `workloadCompleted`
requires a successful exit and expectations. `sandboxSupportEstablished` and
`layerOneEstablished` remain false: no test here certifies full isolation.

## Regression Groups

- `test_browser.py`: three stock Chromium launches with fresh profiles, computed
  JavaScript/DOM values, real installed filters, PNG output and zero exit. The
  selected route is recorded independently of sandbox admission. A fourth run
  verifies helper-independent automatic startup or rejection of the unadmitted
  set-ID helper under the same guest identity. Child signal exits and diagnostics remain
  in reports.
- `test_credentials.py`: explicit sealed-image catalogue, first-entry and exec
  logical credentials, secure auxv/loader, irreversible drops, no_new_privs,
  denied real credentials and retained descriptors.
- `test_retained.py`: protected metadata and exec, nonleader exec, descriptor
  and cwd ownership in threads with private FD tables, page-boundary paths,
  read-only output buffers, CLOEXEC, open-unlinked inode identity and immediate
  broker revocation after a sibling changes the shared CLONE_FS root,
  offsets, regular/directory/O_PATH/pipe FD reuse, shared dup/fork/thread seeks,
  seek, kernel-fast-path and internal-transport ERRNO/TRAP/KILL precedence,
  restricted-domain argument checks, failed exec descriptor cleanup, signals, group death,
  job control, sockets and three stock zygote/renderer starts.
- `test_renderer.py`: a separately labelled layer-two experiment. Its parent
  uses `--no-sandbox`, while `renderer-prefix.py` removes that flag from
  renderer children. This does not satisfy full-browser acceptance and must not
  be used for browsing.

```sh
python native/guest-exec-lab/browser/test_credentials.py --build BUILD --store DEVICE_GUEST_STORE
python native/guest-exec-lab/browser/test_retained.py --build BUILD --store DEVICE_GUEST_STORE
```

`build-control.sh` builds `control.c` for the prepared guest libc.
`broker-directories` checks shared dup/fork cursors, failed and partially copied
output, application-filter denial, nondumpable fallback and native procfs reads.
`build-identity.sh` tests the production logical-credential model.
`zygote_stage.py` exercises helper IPC, renderer fork, real filter installation
and nonempty Mojo startup independently of a displayed page. Prepared stores
supply these explicitly; they are not downloaded by the runtime.

## Coverage And Limits

Device coverage is NX809J, Android 16, Linux 6.12.23, 4 KiB pages, actual
UID 2000 in the shell SELinux domain. Firefox's headless screenshot and
Chromium's three-profile JavaScript/PNG workflows establish execution, not
arbitrary browsing, network/GPU compatibility or confinement.

Alpine 3.23.6 with Chromium 149.0.7827.53-r0 passes both automatic namespace and
explicit set-ID routes. The latter exercises retained proc directory opens with
musl's `O_LARGEFILE`; the runtime preserves read-only open flags instead of
requiring one libc-specific combination. The matching native/guest metadata
fixtures also check nofollow, nonblocking, CLOEXEC on/off, O_PATH, one available
FD slot and flag-specific seccomp denial. The negative browser control requires
the helper's denial and actual child exit status, not version-specific wording
from the parent zygote diagnostic.

Protected metadata uses task-affine descriptor export, notification ADDFD and
original-site replay without relaxing dumpability. A second native kernel tracer
cannot attach; guest GDB/strace use the supervisor's
[virtual debugging contract](../../shroot/debugging.md).
The logical proc-root restriction is not general chroot. Interpreter/library
admission, mapped-code protection, full descriptor/root confinement and
domain-authenticated filesystem authorization remain unverified or incomplete.
The [native boundary controls](../sandbox-research.md) record separate kernel
experiments; their results are not substituted for these production workflows.
