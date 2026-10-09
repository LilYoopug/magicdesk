# Shared Memory

POSIX shared-memory names use the ordinary inode namespace beneath `/dev/shm`.
Execution preparation creates missing `/dev` and `/dev/shm` directories in the
writable instance, retaining existing permissions and sealed-image contents.
Already-open descriptors, mmap and descriptor passing use native data IO.

System V shared memory has a separate namespace authority in `sysv_shm.c`.
The supervisor opens it lazily through `ipc_namespace` on the first request. `shm_calls.c` adapts the
ARM64 Linux ABI in the calling task. `task_helper` owns a short-lived same-TGID
helper with CLONE_VM but without CLONE_FILES. The helper closes its inherited
descriptor copies, receives a backing FD in its private table and executes mmap
against the shared address space. Kernel thread termination closes every private
FD, including after filters, caller death or exec. No temporary backing FD or
socket enters the application's table, and a full application table is supported.
IPC_STAT uses the common adapter-buffer lease, with no temporary guest FD.
No payload bytes pass through SQLite, RPC or the supervisor. Host UID and kernel
capabilities do not change, and the host kernel need not implement SysV IPC.

## Ownership

`ipc/v2/shm/segments.db` stores namespace-scoped keys, IDs, canonical owners and attachment references.
Mapped files carry data. Transactions hold a native file lock only while
updating metadata, not across guest execution or waits. Each supervisor holds
an owner lease; abandoned references are reaped using nonblocking file locks,
not PID reuse or periodic polling. Each address space owns its mapping records.
CLONE_VM shares them; fork copies them; exec/exit release them.
Each mapping retains its original authority even after CLONE_NEWIPC. Fork and
address-space release batch their metadata changes per authority; they do not
open a transaction for each mapping. An isolated namespace's last retained
authority retires its objects without invalidating mappings retained by another
address space.
The interception-memory owner orders attachment publication, detach, destructive
memory calls and non-CLONE_VM fork. Its resource queue does not hold a mutex
across a guest wait. Accepted helpers pin that owner, their scratch stack and a
buffer lease through exact kernel reaping, independently of the initiating task.
Only confirmed mappings enter the attachment model. A helper opens its own maps
file and transfers it before mmap; terminal loss of acknowledgement is reconciled
against the backing device/inode, offset and complete shared range while the
helper remains at PTRACE_EVENT_EXIT. A register resembling a successful fixed
mmap is not a commit receipt. Uninspectable terminal state is a runtime failure,
not inferred success. Normal returns do not scan maps.

Independent launches using the same store's initial namespace can attach to keyed
segments. Its unremoved segments survive the last launch within the same boot. A kernel boot
ID change expires them. IDs are monotonic within the IPC database. IPC_RMID
removes a key immediately and retains bytes until the last attachment disappears.
Logical removal commits before deleting data; a garbage table permits replay of
interrupted cleanup. This is not a power-loss durability guarantee.

Files are caller-owned, disk-backed mappings, not kernel tmpfs objects. The IPC
directory is not part of an OCI image or a filesystem snapshot. It follows the
store's host access boundary, not a kernel IPC namespace or isolation boundary.

## Operations

Supported calls are shmget (private/keyed, create/exclusive), shmat
(read-only/read-write, SHM_RND, SHM_EXEC subject to native execution policy),
shmdt and shmctl IPC_STAT/IPC_SET/IPC_RMID. Permissions use guest credentials;
CAP_IPC_OWNER bypasses access checks but does not grant host authority or ownership
changes. Protected memory is copied in the guest task with EFAULT semantics.

The first attachment installs a narrow memory-observation filter for munmap,
fixed mmap and mremap. Ordinary calls with no intersecting attachment continue
natively; successful replacement/unmapping updates the same attachment owner.
Partial unmaps retain surviving fragments. shmdt removes those fragments without
unmapping an unrelated mapping inserted in a hole. Fragment counts do not model
every VMA split, such as those caused by mprotect.

SHM_REMAP, huge-page selection, locking/statistics
commands and mremap involving an attached segment are not implemented. These
operations fail explicitly; POSIX semaphores and shared memory are separate APIs.
Application filters and native policy can deny helper creation, close_range,
maps inspection, descriptor transfer or mmap. Such denials remain errors; the
runtime does not relax filters or dumpability. Helper-only termination uses an
exact KILL_THREAD gate, never a group-directed kill for ordinary completion.
An application KILL_PROCESS filter still takes precedence. Nested debugger
events exclude internal helper birth/exit and syscalls; kernel proc enumeration
is not a virtualized thread list.
Namespace-scoped [SysV semaphores and message queues](sysv-ipc.md) have their own
authority and task-affine argument transport.

## Checks

`test_service_runtime.c` checks bytes shared across fork and independent launches,
store separation, permissions, read-only faults, fork/exec/exit, IPC_RMID, partial
munmap and unrelated mappings in holes. `test_oci_services.py` runs stock PostgreSQL
initdb, SQL traffic, shutdown and fresh-process readback. Device scope is recorded
in [guest coverage](../../docs/shroot.md#coverage-and-limits).

`test_sysv_runtime.py --case shm-slots --case shm-denied` checks repeated zero-slot
and one-slot attachment/detachment and rejected mmap, with ordinary and
nondumpable callers. Failed attachment leaves no logical reference or backing FD;
no protected metadata channel is primed and a real filter rejects guest fstat.
`shm-terminal` adds fatal helper filters before mmap/close_range, clone denial,
and surviving CLONE_VM/CLONE_FILES peers with full tables. `shm-concurrent` checks
six shared-memory callers with repeated attachments and forked readers.
`shm-owner-death` checks caller-group cancellation during repeated mapping work;
the next address-space turn verifies both kernel mappings and logical references.
`shm-exec` replaces the image while another thread repeatedly attaches/detaches;
the new image verifies retirement of the old address space's attachments.
The debugger suite's `gdb-shm` and `strace-shm` run stock tools against actual
attachments and check that internal helper events do not appear as guest work.

`test_resources.py --case mapping-task` is a kernel-only feasibility fixture,
not the production attachment path. A CLONE_VM helper with a private file table
can map a provider-owned file into the shared address space without changing
the caller's descriptors. Checks cover separate-process and same-TGID helpers,
nondumpable callers, full inherited and helper tables, fatal filters before mmap/close, and
caller-thread exit while another thread retains the address space. The provider
installs at a known private slot; no application slot is replaced.

The fixture also exposes two integration constraints. An application filter can
allow ordinary CLONE_FILES threads and mmap while denying this helper's clone.
For fixed mmap, terminal x0 may still contain the requested address when a fatal
filter prevented execution. On the covered kernel, the separate-process case
even publishes a syscall-exit stop with that unchanged value. Neither observation
alone proves a completed mapping. The helper can open its own maps file and
transfer it before the mapping; this file stays outside the application table.
Reading that retained file at PTRACE_EVENT_EXIT identifies the actual backing
device/inode, offset and shared range even for nondumpable callers. Checks include
death immediately after mmap, before any userspace acknowledgement. The native
PROCMAP_QUERY ioctl returns EACCES on the covered shell policy; text-map reads
pass independently and do not require that ioctl.

An explicit helper-only KILL_THREAD gate also terminates a private-table thread
without killing its surviving peers, including with a later ERRNO filter on exit.
This is not a general override of application filters: a stricter KILL_PROCESS
policy or denial of helper creation remains an independent limit. The 60-case
fixture checks exact caller FD balance and mapping bytes using the production
`mapping_observation` reader. Runtime helper admission, concurrent ownership,
exec and nested-debugger checks belong to the separate suites above.
