# Process Resources

`task_resources` owns independently shared guest state in the supervisor.
Its lifecycle follows successful kernel process/resource transitions, not
Android Activities, named environments or launcher configuration.

| Resource | Clone sharing | Unshare | Exec |
| --- | --- | --- | --- |
| Filesystem context | `CLONE_FS` | `CLONE_FS` | Retained |
| Descriptor table | `CLONE_FILES` | `CLONE_FILES` | Kernel detaches it |
| Semaphore undo | `CLONE_SYSVSEM` | `CLONE_SYSVSEM` | Retained |

The kernel owns cwd, umask, descriptor tables and open-file descriptions.
The supervisor's filesystem context owns only guest state: the admitted
proc-root restriction and its retained descriptors. This is not general
`chroot` support. See [namespace execution](namespace-execution.md) for the
launch filesystem and [interception](interception.md) for restricted domains.

Copying a descriptor table does not copy open-file descriptions: offsets remain
shared, while close-on-exec flags and descriptor closure become independent.
There is no supervisor mirror of every descriptor or new interception of
ordinary close/read/write operations.

## Resource Changes

`unshare` prepares candidate guest-owned resources before resuming the kernel
call. The syscall-exit observer commits them only if the kernel succeeds.
Failure, cancellation or task death releases the candidate; no partial guest
change is published. The kernel validates `CLONE_VM`, `CLONE_SIGHAND` and
`CLONE_THREAD` constraints. Unsupported namespace flags fail before changing
any resource, including when combined with otherwise supported flags.

An unshared filesystem context copies retained root descriptors only when
there are other owners. A sole owner needs no copy. Semaphore undo starts empty
when split; leaving the old undo group applies its adjustments only when the
last owner leaves. Ordinary fork starts an independent empty undo group.

Fork ownership is published from the kernel's birth event before either
participant resumes guest execution. Nonleader exec transfers the executing
thread's resources to its resulting process identity; teardown of the replaced
leader must not release the executing thread's owners. Kernel exec detaches
shared descriptor tables, but not shared filesystem context or semaphore undo.

## Boundaries

Concurrent named environments and launch-local attachments are not Linux
namespaces. `CLONE_NEWNS`, `CLONE_NEWUSER`, `CLONE_NEWIPC`, `CLONE_NEWUTS`,
`CLONE_NEWPID`, `CLONE_NEWNET`, cgroup/time namespaces and `setns` are not
implemented. Their creation is not reported as successful. General guest
mount mutation, per-process root selection and user-namespace mappings require
their own resource and authority contracts.

This resource model does not establish security isolation from Android, other
launches or peer guest processes. Programs retain the executor's host authority;
successful browser execution is not proof of complete sandbox equivalence.

## Verification

With `MAGICDESK_GUEST_FIXTURES=ON`, `test_task_resources` checks independent
ownership, transaction rollback, retained-root copies and descriptor leaks.
`resource_guest` compares native Linux and Shroot cwd/umask/FD semantics,
failed-unshare rollback and exec inheritance. Guest-only cases check proc-root
sharing and semaphore-undo splitting, final-owner cleanup and exec retention.
Pipe acknowledgements order observations; an alarm is only a failure bound.

`test_resources.py BUILD --compare-installed` stages a disposable store under
the selected shell UID and compares the same static metadata/spawn fixtures
against the installed runtime. Uninstrumented samples alternate execution order;
opt-in counters are separate runs. Reports preserve both timings and operation
counts without treating scheduler variation as a throughput guarantee.
