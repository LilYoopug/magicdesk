# Seccomp And Ptrace Controls

These native fixtures isolate kernel behavior under the selected shell executor.
They are not a second production backend or a browser-certification suite.
Production Shroot uses selective TRACE/USER_NOTIF interception; application
SIGSYS handlers and alternate stacks belong to the application. See the
[interception contract](../shroot/interception.md) and
[production browser workflows](browser/README.md).

## Reproduction

Use a disposable prepared glibc store and an immutable staged runtime:

```sh
sh native/guest-exec-lab/build-sandbox-fixtures.sh BUILD
python native/guest-exec-lab/test_sandbox.py BUILD \
  --runtime IMMUTABLE_STAGED_HELPERS --store DISPOSABLE_GLIBC_STORE
sh native/guest-exec-lab/build-hybrid-fixture.sh BUILD
python native/guest-exec-lab/test_hybrid.py BUILD --runs 50
```

The runners record device/kernel identity, actual UID, helper hashes, output
and cleanup. Synthetic-policy controls affect owned child processes only.
A completed observation suite is not a passing arbitrary-browser workload.
`test_notifications.py` supplies separate notification-lifecycle controls.

## Policy Boundaries

| Control | Meaning |
| --- | --- |
| TRAP versus ERRNO; multiple TRAP filters | Kernel action precedence and data-cookie selection are not a runtime policy choice |
| USER_NOTIF with application ERRNO/TRAP/KILL | A denial must win without executing the external operation |
| Listener loss | Notified calls fail; they must not become unmediated host operations |
| Cooperative SIGSYS and blocked SIGSYS | Signal ownership, alternate stacks and masks are part of the application ABI |
| Replay at a different instruction address | Instruction-pointer filters can produce a different decision |
| Native namespace creation | Host capability evidence is separate from logical Shroot namespaces |
| Direct filesystem RPC | An external broker is an authority boundary, not automatically confined by its caller's seccomp filter |

Do not use observations from the in-process TRAP controls as claims about the
current runtime. In particular, reserving SIGSYS/altstack and bypassing an
application's open denial are not its supported execution contract.

Copied arguments, thread identity, filter inheritance and original call-site
semantics matter independently. A guest-writable secret or caller-supplied
syscall/PC is not trusted authorization. An external broker must also account
for alternate RPC paths, inherited descriptors and raw host access; successful
filter installation alone does not establish complete confinement.

## Selective Ptrace Hybrid

`test_hybrid.c` is a bounded static native control. It uses USER_NOTIF for
selected operations and TRACE for register/exec changes, with ordinary
`PTRACE_CONT` between them. Single-stepping is a signal-delivery test control,
not its normal execution mechanism.

Its supervisor owns only its child tree through SEIZE/EXITKILL and event-driven
signalfd/notification observation. Thread-specific INTERRUPT cancels the exact
pending notification. Process-directed SIGSTOP does not provide that identity.

The fixture checks:

- Original ERRNO/TRAP/KILL decisions, nested application SIGSYS and an
  application-owned alternate stack.
- Register-only exec redirection, including after dumpability is disabled.
- ARM64 `orig_x0` rechecking: replacing x0 alone is not equivalent to a fresh
  entry through the original SVC instruction.
- Protected parent/fork-child memory access through bounded instruction-only
  copies, without changing dumpability or using the parent's memory FD for
  a replacement address space.
- Cancellation, copied pathname validation, original-site replay and ADDFD
  publication for a fresh kernel-validated request.
- Concurrent TSYNC denial after copying but before replay.
- Signal masks, original PC/result/siginfo, nested calls and kernel-owned
  EINTR/SA_RESTART behavior.
- Rejection of a second native tracer. Guest debugger compatibility is a
  separate [Shroot contract](../shroot/debugging.md).

Temporary copies are untrusted input. No stale notification ID authorizes work.
Cancellation before an external operation is not permission to replay a mutation
whose completion is unknown. The fixture's known code sites and bounded mappings
do not establish arbitrary exec, signal or process-lifetime compatibility.

## Real Browser Boundaries

Use [browser/README.md](browser/README.md) for stock Firefox/Chromium workloads.
It distinguishes automatic user/PID namespace startup, the explicitly selected
set-ID helper route, admission rejection and renderer-only diagnostics.
Renderer-only tests and version strings are not full-browser passes.

The [isolation controls](chromium-isolation.md) separately exercise native
namespace admission, a deliberately restricted read-only broker and
helper/protected-memory mechanics. Their reduced syscall surfaces must not be
confused with a general Linux execution environment or native sandbox equivalence.

## Primary References

- [Linux seccomp contract](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux 6.12 notification implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/seccomp.c)
- [Firefox signal/filter integration](https://github.com/mozilla/gecko-dev/blob/master/security/sandbox/linux/Sandbox.cpp)
- [Chromium Linux sandbox](https://github.com/chromium/chromium/blob/main/sandbox/linux/README.md)
- [Android 16 common-kernel ptrace](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/kernel/ptrace.c)
- [ARM64 syscall arguments](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/arch/arm64/include/asm/syscall.h)
- [ARM64 signal delivery](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/arch/arm64/kernel/signal.c)
