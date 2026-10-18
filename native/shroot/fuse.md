# Guest FUSE

Shroot provides FUSE as a native guest filesystem adapter. A stock guest daemon
opens `/dev/fuse`, negotiates the Linux wire protocol and serves ordinary guest
mounts. Android's real FUSE device and kernel mount permission are not used.
The selected executor identity, namespace owner, DAC, Landlock and mount policy
remain authoritative. This adds no persistent store format or APK dependency.

## Ownership

- `fuse_device` owns the typed character device and daemon IO. Final device
  closure aborts pending operations instead of leaving a sleeping worker.
- `fuse_transport` owns bounded requests, unique IDs, replies, cancellation and
  notification delivery. Completion callbacks run outside the connection lock.
  Invalidation handlers run under that lock to serialize context teardown;
  they only update view state and never call back into the transport.
- `fuse_session` owns INIT negotiation, credentials and advertised capabilities.
- `fuse_view` owns node IDs/generations, names, attributes and mount operations.
  Carrier names do not consume one retained host FD per node.
- `fuse_file` owns each open handle, IO and release. `fuse_image` prepares sealed
  private images for mmap and executable admission.
- `fs_continuation` and the existing filesystem worker own suspended operations.
  Captured operands remain valid across daemon waits. Mutations are not replayed
  after partial completion, and no store transaction or FD-table turn spans a
  guest daemon wait.

Namespace clones and bind mounts retain the provider. Lazy unmount removes its
placement but preserves open descriptions. Last-anchor release schedules mount
collection on the filesystem event loop; ordinary workloads need no periodic
collection. The provider closes only when its remaining owners are gone.

## Protocol and Policy

The offered protocol ceiling is 7.31; negotiation accepts compatible older
daemons down to minor 12. Unsupported capabilities are not advertised. Request
queues are bounded at 256 requests and 8 MiB; a packet cannot exceed 1 MiB.
File IO is chunked at 16 KiB. Queue saturation returns an explicit error.

The adapter implements lookup/attributes, regular files/directories/symlinks,
creation, rename, links, removal, xattrs, data IO, directory iteration, truncate,
sync and statfs. Daemon errors propagate. Mounts enforce owner/allow_other and
default_permissions, and are always nodev/nosuid. Private executable mappings
and execution still enforce noexec; guest FUSE cannot create a host set-ID path.
INVAL_INODE, INVAL_ENTRY and DELETE notifications invalidate relevant state.
Ordinary reads and permission-sensitive lookups query the daemon rather than
trusting a persistent content or authorization cache.

## Mapping Limits

MAP_PRIVATE and executable images use sealed snapshots, not a coherent Linux
page cache. Preparation checks attributes again after copying; detected changes
fail with EAGAIN. A new mapping revalidates metadata and the invalidation epoch.
Existing private mappings do not follow later daemon writes. Same-size writes
without observable timestamp changes or invalidation cannot be inferred.

MAP_SHARED, append IO and FUSE inotify are unsupported and return errors.
INTERRUPT, DESTROY and FLUSH protocol requests are not yet implemented; closing
the connection is the final cancellation boundary. Node metadata is bounded at
65,536 entries per view, retained until provider teardown rather than managed
by a kernel-style dentry eviction policy. Private images consume memory backing
proportional to the copied file. Cross-independent-launch provider transfer is
not supported. This is a useful subset, not full kernel FUSE compatibility.

## Verification

Native fixtures cover wire validation, queue bounds, device closure, deferred
worker progress, metadata/mutations, failed publication, cancellation, snapshot
invalidation and carrier FD limits. `test_fuse.py` exercises installed stock
clients in a private runtime under Android UID 2000:

- `rofiles`: mutations, descriptor IO and daemon-wait cancellation.
- `portal`: stock document export, Flatpak read/write and live revocation.
- `squashfs`: concurrent reads, ELF/script execution, shared-library loading,
  private mmap, noexec and a file retained through lazy unmount.

`test_snap.py` separately boots stock systemd and snapd in a disposable Debian
store and requires install, run, refresh and removal of hello-world. It uses a
shared root mount before snapd creates image mounts, as required by its
mount propagation. The fixture launcher establishes that topology; it does not
patch snapd or suppress unmount errors. This cycle passes both normally and
under strace. A refresh with no available update verifies the refresh command,
not migration to a different snap revision.

Testing Snap is not evidence of AppArmor confinement: the tested Android kernel lacks
AppArmor, and snapd reports its own reduced confinement capabilities. No
application sandbox is disabled to make a test pass.
