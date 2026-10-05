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

This keeps payload bytes, blocking/readiness, FD transfer, partial sends and
message ordering in the kernel. Ordinary read/write and credential-free sends
do not create capabilities. Common ancillary buffers use stack scratch; larger
buffers use bounded temporary mappings. Recvmmsg uses one native batch so its
timeout and partial completion are not replaced by a userspace receive loop.
MSG_PEEK does not consume identity metadata; truncation closes unpublished FDs.

Receive publication has one owner for ancillary data, translated source address
and output header fields. Each successfully copied SCM_RIGHTS descriptor number
transfers ownership to the caller. A later control-header, source-address or
message-header fault does not close it. Descriptors that do not fit, or whose
number cannot be copied, are closed; an empty rights header is not emitted.
Partially inaccessible control buffers retain the delivered prefix and native
MSG_CTRUNC semantics. Input-only message fields are not written back.
The adapter publishes directly from its receive scratch buffer, without a second
reconstruction buffer, per-FD allocation or extra data-description references.

For recvmmsg, each private msg_len records kernel completion even if the syscall
then fails writing the remaining timeout. Such a failure does not suppress
publication of the completed messages or leak their descriptors.

Current limits are explicit:

- Kernel-generated SO_PASSCRED messages without an explicit SCM_CREDENTIALS
  send retain native credentials. Unconnected datagram addressing is not
  virtually authenticated; registered socketpairs are supported.
- The private capability consumes one kernel descriptor slot per explicit
  credential message. It does not remove kernel ancillary/FD limits.
- Connection/message records remain until the last live owner exits. Long-lived
  workloads sending credentials continuously need lifecycle-aware reclamation;
  deleting records merely on receipt is unsafe with concurrent MSG_PEEK.
- Recvmmsg uses a private header vector. A fault publishing a user header or
  source address within that batch can therefore occur after later packets have
  already been consumed. The adapter does not reproduce the kernel's deferred
  socket error for this case. The comparative `rights-batch-fault` check fails
  explicitly; a writable-memory preflight or replay would not establish the
  required receive/publication ordering. The native batch path is retained:
  a userspace receive loop must not replace socket-owned errors with a local
  errno cache. Errors generated inside the kernel retain native SO_ERROR,
  read/recv and poll/epoll behavior across duplicated and inherited descriptors.
- Kernel capabilities, SELinux, resource limits, SO_PEERSEC and native attached
  resources remain real. A denied kernel operation is not reported as success.

## D-Bus And Coverage

An unmodified distribution supplies dbus-daemon, dbus-run-session, policy and
NSS entries for the selected guest user. No daemon is shipped in the APK.
Session buses use ordinary credential authentication and service activation.

The UID 2000 device suite covers Debian/glibc and Alpine/musl session buses,
independent launches sharing a store, rejection of another guest user, connection
snapshots after credential drops and peer exit, groups, short output buffers,
queued explicit messages, rejected credential forgery, MSG_PEEK, recvmmsg and
ordinary descriptor transfer. A stock Debian bus activates a GDBus fixture,
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
adapter-publication fault above.

A daemon may warn that its requested FD limit exceeds the executor's hard limit;
this does not justify fabricating a successful setrlimit. A working session bus
does not imply system-bus policy, arbitrary package configuration or full Linux
service startup. Device/build coverage remains that of the
[guest runtime](../../docs/guest-runtime.md).
