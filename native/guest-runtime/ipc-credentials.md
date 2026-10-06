# Unix IPC Credentials

Guest identity belongs to the supervised task, not Android. `socket_identity`
adapts connection credentials and `socket_ancillary` adapts explicit credential
messages. Both use the authenticated namespace request path and the same
`guest_identity` snapshots as filesystem permissions. There is no D-Bus-specific
authentication bypass, payload proxy or second process-identity model.

## Connection Identity

`ipc_credentials` is a lazy, store-scoped metadata authority owned by each
namespace worker. Workers sharing a store serialize metadata operations with a
kernel file lock. They never hold this lock across guest connect, accept or IO.
`<store>/ipc` is transient state, separate from image/inode metadata. A shared
live-owner lease makes the first owner discard stale records, including socket
cookies retained across a device reboot. No service or kernel probe is added to
MagicDesk startup, and ordinary filesystem calls do not open this database.

Kernel `SO_COOKIE` identifies a socket across dup, fork and SCM_RIGHTS. Listen,
connect and socketpair capture effective guest UID/GID and supplementary groups.
SO_PEERCRED and SO_PEERGROUPS read copied connection snapshots, not the peer's
current credentials. A later credential drop, peer exit or FD transfer does not
rewrite them. Native peer PID is checked before publishing a snapshot.
The worker returns that snapshot through the existing mapped byte output,
without installing an identity memfd in the application table. SO_PEERGROUPS
supports all 65536 groups; SO_PEERCRED returns only the fixed identity header.
Input capture retains the exact socket description. After channel admission,
both work with a full ordinary or protected FD table. Short buffers, ERANGE and
output-copy faults keep their syscall semantics. The unused mapped value pages
are not cleared by ordinary filesystem requests.

For a connection to a registered guest listener, an otherwise unnamed client
gets a private abstract transport address. Accept resolves that exact connection
without netlink permissions or guessing by PID. The address adapter hides this
implementation name. Existing user-bound names are preserved. Connect preparation
and completion validate the listener revision; an ambiguous snapshot fails with
ESTALE, without replaying a successful connection or inventing an identity.

Unregistered/external endpoints keep kernel credentials. Abstract socket names
remain in the host's shared namespace. These mappings do not provide network
isolation or protect mutually hostile processes sharing the real executor UID.

## Explicit Credential Messages

SCM_CREDENTIALS validates the claimed guest IDs against the sending task. PID
must identify that task's process; virtual root may select guest UID/GID, while
other users may select only their real/effective/saved IDs. The kernel receives
the actual Android credentials, plus a sealed memfd capability as one extra
SCM_RIGHTS descriptor. Its random nonce, connection identity and kernel file
identity are recorded by the metadata authority. The receiving adapter removes
that descriptor and publishes the validated guest credentials instead.

The namespace worker retains the sending capability; it never installs that FD
in the application's shared table. A same-process helper captures a private
table under the existing file-table/FS turns. Those turns end at the exact clone
event, before IO. The helper closes unrelated descriptors, validates the retained
socket and application rights, and receives the capability with atomic ADDFD_SEND.
It performs the native send and is reaped before completion. Helper/caller death
therefore releases temporary descriptors without closing remembered numbers in a
surviving CLONE_FILES peer. A concurrent close/reuse cannot retarget the send,
and a blocked send does not retain unrelated pipe writers or resource turns.
Kernel-generated SIGPIPE is forwarded to the original caller with its siginfo;
MSG_NOSIGNAL and an application filter returning EPIPE do not invent a signal.
Application filters still apply to private-helper setup and IO; rejection is an
error, not permission to bypass those filters or replay a send.

This keeps payload bytes, blocking/readiness, FD transfer, partial sends and
message ordering in the kernel. Ordinary read/write and credential-free sends
do not create capabilities. Common ancillary buffers use stack scratch; larger
buffers use bounded temporary mappings. Recvmmsg uses one native batch so its
timeout and partial completion are not replaced by a userspace receive loop.
MSG_PEEK does not consume identity metadata; truncation closes unpublished FDs.

Native receive runs in a same-process private-table helper. Its socket is captured
under the destination table turn; the turn ends at clone, before blocking IO.
Unrelated inherited descriptors are closed before receiving. The helper exports
the actual socket and received rights through an owned channel and is reaped
before the adapter resumes. Bounded vectors retain the source descriptions in the
supervisor; the worker borrows exact inputs for token authentication and watch
inspection, without installing temporary descriptors in the application table.
Caller death, fatal helper filters and export failure release the private table,
queued rights and retained sources. Later reuse of the original socket number
cannot retarget the accepted receive.

Receive publication has one owner for ancillary data, translated source address
and output header fields. Application rights use the existing table-owned return
channel. The final kernel recvmsg writes FD numbers directly to application
control memory, not a private receipt followed by a userspace copy. A later
control-header, source-address or message-header fault therefore cannot authorize
closing a kernel-published descriptor. Cancellation drains only queued rights and
releases retained sources; there is no cleanup by guessed application FD number.
Partially inaccessible control buffers retain the delivered prefix and native
MSG_CTRUNC semantics. Input-only message fields are not written back.
Received watch descriptors activate their FD-class selectors for available
destination slots under the same table turn, before kernel publication. Failure
releases only unpublished resources. Ordinary read/write does not use this path.

For recvmmsg, each private msg_len records kernel completion even if the syscall
then fails writing the remaining timeout. Such a failure does not suppress
publication of the completed messages or leak their descriptors.

Current limits are explicit:

- Kernel-generated SO_PASSCRED messages without an explicit SCM_CREDENTIALS
  send retain native credentials. Unconnected datagram addressing is not
  virtually authenticated; registered socketpairs are supported.
- The private capability consumes one kernel descriptor slot per explicit
  credential message. It does not remove kernel ancillary/FD limits.
- The private receiver and return channel consume infrastructure resources.
  Cold return-channel admission needs an extra application FD slot. Export from
  a protected private table is a real SCM_RIGHTS send, subject to the real UID's
  in-flight quota and RLIMIT_NOFILE; in particular, a queued MSG_PEEK can cause
  ETOOMANYREFS where a direct native receive succeeds. Failure releases custody,
  but does not undo delivered payload or consumed messages. Limits are not raised
  and an attempted receive is not replayed. This is not full native quota parity.
- Connection/message records remain until the last live owner exits. Long-lived
  workloads sending credentials continuously need lifecycle-aware reclamation;
  deleting records merely on receipt is unsafe with concurrent MSG_PEEK.
- Recvmmsg uses a private header vector. A fault publishing a user header or
  source address within that batch can therefore occur after later packets have
  already been consumed. The adapter does not reproduce the kernel's deferred
  socket error for this case. The comparative `rights-batch-fault` and
  `rights-publication-error` checks fail
  explicitly; a writable-memory preflight or replay would not establish the
  required receive/publication ordering. The native batch path is retained:
  a userspace receive loop must not replace socket-owned errors with a local
  errno cache. Errors generated inside the kernel retain native SO_ERROR,
  read/recv and poll/epoll behavior across duplicated and inherited descriptors.
- Kernel capabilities, SELinux, resource limits, SO_PEERSEC and native attached
  resources remain real. A denied kernel operation is not reported as success.

### Batch Publication Boundary

The publication comparison isolates header outputs, source-address copying and
the per-entry msg_len field. After one successful entry and a fault in the second,
native Linux consumes two of three messages, leaves the third queued, and exposes
one EFAULT through the socket. Shroot's private batch consumes all three before
the adapter encounters that fault. This is separate from FD custody: delivered
FDs remain caller-owned and later unpublished descriptions are released.

Linux's [recvmmsg loop](https://github.com/torvalds/linux/blob/v5.15/net/socket.c#L2562-L2666)
performs publication before advancing the batch and retains a deferred error in
the socket. [SO_ERROR is read-and-clear, not writable through setsockopt](https://github.com/torvalds/linux/blob/v5.15/net/core/sock.c#L940-L945).
A correct adapted batch needs per-message receive/publication ordering plus one
socket-owned error/readiness contract shared by aliases, fork and consumers.
Stopping a userspace loop alone does not preserve SO_ERROR, read/recv, poll/epoll
or native timeout behavior. Writable-memory preflights cannot replace the actual
publication event, and replay cannot restore consumed messages.

## D-Bus And Coverage

An unmodified distribution supplies dbus-daemon, dbus-run-session, policy and
NSS entries for the selected guest user. No daemon is shipped in the APK.
Session buses use ordinary credential authentication and service activation.

The UID 2000 device suite covers Debian/glibc and Alpine/musl session buses,
independent launches sharing a store, rejection of another guest user, connection
snapshots after credential drops and peer exit, groups, short output buffers,
full FD tables, maximum/empty group snapshots and inaccessible output memory,
queued explicit messages, rejected credential forgery, MSG_PEEK, recvmmsg and
ordinary descriptor transfer. Sending checks cover full ordinary/protected tables,
invalid input slots, SIGPIPE delivery/masking/suppression and filter-produced
EPIPE. A one-megabyte send into a bounded socket provides event-driven coverage of
blocking IO, concurrent table mutation, cancellation, retained message prefixes
and pipe EOF without timing-based synchronization. Receive lifecycle checks block
MSG_WAITALL on a bounded stream, replace the original socket slot, check unrelated
pipe EOF, complete or cancel the caller, and require an unchanged surviving FD set.
The opt-in `--custody` fixture compares native and guest ordinary/protected callers
with fatal fstat and post-receive export filters, including recvmmsg. Payload
delivery proves the export-kill case passed native receive before cancellation.
Channel tests cover 1/253-FD capture, cancelled queues and a partially published
prefix retained after terminal cancellation. A stock Debian bus activates a GDBus fixture,
reports its caller as guest UID 0 and exchanges usable FDs in both directions.
An external native endpoint still receives UID 2000 and rejects a root claim.
The same static ancillary fixture runs natively under shell and inside Shroot,
comparing stream/datagram/seqpacket peek, shared offsets, close-on-exec, the
253-FD limit, truncation, batch delivery, partial control writes, readonly input
fields, source-name errors and late header/timeout faults. Pipe EOF verifies
that discarded or closed descriptors leave no hidden writer references.
`rights-socket-error` compares a kernel payload-copy fault after partial batch
success, readiness through poll/epoll and one-shot error consumption through
SO_ERROR, read, recv and a forked peer. It is separate from the unresolved
adapter-publication fault above. `rights-publication-error` repeats those four
error consumers for all three adapter publication boundaries and remains failing.

A daemon may warn that its requested FD limit exceeds the executor's hard limit;
this does not justify fabricating a successful setrlimit. A working session bus
does not imply system-bus policy, arbitrary package configuration or full Linux
service startup. Device/build coverage remains that of the
[guest runtime](../../docs/guest-runtime.md).
