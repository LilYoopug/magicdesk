# Browser Isolation Controls

These fixtures distinguish native Android kernel authority, bounded broker
experiments and production Shroot browser execution. They concern Linux
browsers, not the Android Chrome APK. For current launch routes and acceptance
criteria use [the browser guide](browser/README.md); for implemented isolation
limits use [Shroot](../../docs/shroot.md#boundaries).

## Native Kernel Baseline

The independent native fixture excludes the guest loader, syscall adapter,
ptrace and its seccomp filters:

```sh
sh native/guest-exec-lab/build-isolation-fixture.sh BUILD
python native/guest-exec-lab/test_isolation.py BUILD
```

It records the actual UID, capabilities, no_new_privs and seccomp state, kernel
configuration when readable, and exact results. Namespace/chroot/credential
changes occur only in owned short-lived children. An observation timeout is a
failure, never a capability result. No APK install, root or Desktop is involved.

On RM11/NX809J, Android 16, Linux 6.12.23, 4 KiB pages:

| Native check | Result |
| --- | --- |
| Entry identity | UID/EUID 2000; permitted/effective capabilities zero; no_new_privs=0; seccomp=0 |
| User namespace via unshare, clone and clone3 | EINVAL |
| PID, network and mount namespaces via those three calls | EPERM |
| Combined user/PID/network namespace | EINVAL |
| chroot to the child's own proc fdinfo directory | EPERM |
| Changing real/effective/saved UID to zero | EPERM, still UID 2000 |
| Landlock ABI query | ENOSYS |
| seccomp USER_NOTIF and TRACE actions | Available |

The readable kernel config confirms USER_NS, PID_NS and SECURITY_LANDLOCK are
not compiled in; NET_NS, SECCOMP and SECCOMP_FILTER are enabled. A PID namespace
request returning EPERM does not prove its implementation exists: another
permission check can fail before feature-specific handling. Conversely, the
user-namespace EINVAL is corroborated by config, not guessed from errno alone.
These observations apply to this kernel, not every Android device. Shell's
Android service permissions do not imply Linux CAP_SYS_ADMIN or CAP_SYS_CHROOT.

## Stock Browser Contracts

Chromium's namespace/helper layer is distinct from its per-process seccomp
filters. User/PID namespace startup requires coherent UID/GID maps, capability
drops, proc visibility, process identities and lifecycle. Returning a successful
clone result alone is insufficient.

The set-ID helper route additionally requires logical image admission, secure
loader behavior, root/cwd restriction, dumpability changes, credential drops and
the helper's IPC/lifetime protocol. Guest root-owned metadata does not create a
host set-ID executable or grant Android capabilities.

Reference implementations for the prepared Chromium 154.0.8037.57 fixture:
[zygote selection](https://github.com/chromium/chromium/blob/154.0.8037.57/content/browser/zygote_host/zygote_host_impl_linux.cc),
[credentials](https://github.com/chromium/chromium/blob/154.0.8037.57/sandbox/linux/services/credentials.cc),
[namespace entry](https://github.com/chromium/chromium/blob/154.0.8037.57/sandbox/policy/linux/sandbox_linux.cc),
[helper](https://github.com/chromium/chromium/blob/154.0.8037.57/sandbox/linux/suid/sandbox.c)
and [client](https://github.com/chromium/chromium/blob/154.0.8037.57/sandbox/linux/suid/client/setuid_sandbox_client.cc).
These source references are versioned controls, not a promise about every
distribution's browser build.

## External Domain Fixture

```sh
sh native/guest-exec-lab/build-domain-fixture.sh BUILD
python native/guest-exec-lab/test_domain.py BUILD --repeat 10
```

A default-deny filter and external USER_NOTIF broker expose a bounded read-only
root to owned children. Admitted descriptors are installed through ADDFD_SEND;
ordinary data IO remains native. The fixture checks independent roots,
path/symlink escape rejection, invalid pointers, descriptor reuse, listener loss
and application ERRNO/TRAP/KILL precedence.

An intentionally inherited host descriptor still reads its host object.
That negative control is essential: pathname mediation alone does not revoke
existing authority. The base fixture refuses protected-memory access rather
than relaxing dumpability.

This is not a general Linux root: writable operations, devices, mounted procfs,
arbitrary process creation, FD imports and exec are outside its reduced
surface. A successful read-only control is neither a rendered browser nor
complete hostile-workload confinement.

An application-owned USER_NOTIF listener also needs a separate contract.
The native [duplicate-listener rule](https://github.com/torvalds/linux/blob/v6.12/kernel/seccomp.c)
cannot be inferred away from successful ERRNO/TRAP controls.

## Helper And Protected Memory Control

```sh
python native/guest-exec-lab/build-suid-context.py BUILD
python native/guest-exec-lab/test_domain.py BUILD --fixture suid-context --repeat 10
python native/guest-exec-lab/test_domain.py BUILD --fixture suid-context --suid-main --repeat 10
```

This static Bionic fixture combines retained root/cwd ownership with protected
argument/result copying. It exercises helper-compatible IPC, dumpable=0,
restricted fork children and native exec to a fixture client. It does not
itself execute a set-ID Debian ELF or render a page. Its bounded helper ABI
must not be used as the current production namespace capability declaration.

The [production retained-resource tests](browser/README.md#regression-groups)
exercise actual helper/zygote/renderer chains against the shared ELF loader,
inode store and credential model. Keep their evidence separate from this control.

## Acceptance Boundary

- Full-browser checks retain the selected sandbox route and real application
  filters. A renderer-only diagnostic deliberately omits parent/zygote isolation
  and cannot satisfy that requirement.
- Verify actual JavaScript/DOM or rendered artifacts, child lifecycle and cleanup,
  not only a zero parent exit or a successful filter-install syscall.
- Validate original syscall arguments and call-site policy after protected
  copying; preserve dumpability, application signal handlers and native restart
  semantics.
- Keep authority outside guest-writable memory. Audit inherited/imported FDs,
  raw-gate/proc access, mapped code and alternate filesystem service entry points
  before claiming strong confinement.
- Treat native controls, production execution compatibility and security
  equivalence as separate results. No fixture here certifies complete isolation.

Ownership is specified by [interception](../shroot/interception.md),
[resource contexts](../shroot/process-resources.md),
[guest credentials](../shroot/ipc-credentials.md) and
[namespace execution](../shroot/namespace-execution.md), not by a separate
browser-specific implementation.
