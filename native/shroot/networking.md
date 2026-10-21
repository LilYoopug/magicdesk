# Guest Networking

[Native architecture](README.md) | [Resource model](process-resources.md)

Namespace-local network configuration, supported nftables flow filtering and NAT. This is not an Android firewall or native-kernel isolation.

- [Launch Profiles](#launch-profiles)
- [Network Namespaces](#network-namespaces)
- [Namespace-Owned Sysctls](#namespace-owned-sysctls)
- [Namespace-Owned Sysfs](#namespace-owned-sysfs)

## Launch Profiles

`network_profile` owns the bounded native argument contract shared by image
run/exec/login, the low-level runner and supervisor: host (default), none,
bridge, the advanced routed backend, publications and DNS. Java's
`GuestNetworkProfile` only carries immutable launch arguments; native code owns
syntax, preparation and lifetime. MCP and shell CLI use that same runner. OS
boot inherits the profile through its ordinary launch and namespace setup.

`network_launch` prepares topology before guest execution. Host is a no-op.
None enables private loopback without an uplink. Bridge retains a routed gateway
and a private guest namespace in one fabric: gateway bridge `10.88.0.1/24`, guest
`eth0` `10.88.0.2/24`, loopback and a default route. Independent launches reuse
these logical addresses without sharing ports or owners. The supervisor owns
both namespaces; the fabric's peer list remains weak, avoiding a reference cycle.
Routed remains a supported low-level mode, not an obsolete bridge alias.

Published TCP/UDP ports become typed PREROUTING DNAT rules on the gateway;
private guest binds do not automatically publish. `network_filter_update`
shares validation, direct-flow compatibility, frontend reservation and commit
with the nftables adapter. It prepares all resources before state replacement;
the netlink adapter still publishes its ACK before committing. Failure aborts
all reservations. Teardown joins the existing forwarding owner and releases
ports on cancellation, guest failure or normal completion. No second proxy or
network thread is created for native/unfiltered data IO.

`network_resolver` runs once in filesystem-worker preparation. Explicit servers,
or bridge's filtered snapshot of the installed resolver, become a private
read-only file mount. Missing targets and unusable stub-only configurations fail
explicitly. `md_fs_mount_contents` uses an anonymous O_TMPFILE from the existing
store backend and the ordinary mount-view owner: no persistent name, inode
catalog entry, control FD or per-read resolver work. Last-FD closure reclaims the
backing file even after abrupt process exit. Persistent DNS installation and
launch-local resolver configuration remain separate operations.

The public [CLI contract](../../docs/shroot.md#network-modes) records limits and
isolation caveats. `test_launch_network.py` exercises independent native clients,
TCP/UDP publication, real resolver IO, outbound traffic and cleanup; native model
tests also cover partial reservation rollback and typed nft round trips.

## Network Namespaces

`network_model` owns a retained namespace identity and user-namespace
authority. Clone, unshare, setns and typed `/proc/PID/ns/net` handles use the same
resource transaction as the other namespace kinds. A new namespace is offline;
it never silently falls back to Android networking. Existing sockets retain
their original authority. Anonymous Unix socketpairs remain kernel IPC, with
namespace annotations retained through descriptor-table operations.

`network_calls` supplies bounded requests through the existing mapped transport;
`network_namespace` owns control-socket carriers and `network_route` owns the
NETLINK_ROUTE codec. Queries and CAP_NET_ADMIN-authorized mutations share one
model: loopback, bridge/veth, master assignment, IPv4 addresses, routes and
typed namespace-FD moves. Replies preserve sequence, port identity, ACK and dump
completion. Interface state and ACK publication share a fabric turn and mutation
journal; allocation, encoding or queue failure rolls back all affected namespaces.
The journal exists only for mutations, not queries or data IO. Netlink carriers
provide kernel readiness and queue options without changing Android interfaces.
`network_message` supplies common bounded replies and ACKs; `network_generic`
publishes the nlctrl family catalogue without claiming absent kernel families.
Route rule queries expose the IPv4 local/main/default policy; neighbor and
traffic-control dumps are empty and their unsupported mutations fail explicitly.
Strict queries validate complete headers and reject unsupported filters instead
of silently ignoring them. Route dumps accept the header's table selector and
the extended `RTA_TABLE` selector, with the latter taking precedence; unknown
tables yield an empty dump, not the main table. Kernel-peer connect/getpeername retain netlink
address semantics; non-kernel destinations are unsupported.
`network_packet` owns queued datagram framing and translates requested packet
information and kernel SCM_CREDENTIALS, including ancillary truncation. Protocol
membership and multicast delivery stay separate from native socketpair carriers.
Port identities are unique within each namespace/protocol until the last socket
description closes. User multicast snapshots sender credentials and PID ancestry
at enqueue, so delivery after sender exit cannot adopt a reused PID. Receivers
translate that snapshot in their own PID/user namespaces. Interface name/index,
flags and MTU ioctls use the socket's creation namespace, including the AF_UNIX
control sockets used by libc's `if_nametoindex`.
Control descriptor selection joins the close/dup table turn, including capture
of a namespace FD, and ends before guest output copying.

Default launches use native networking. Opt-in `--network routed` creates a
launch-owned fabric with an IPv4 uplink in its initial namespace. Children start
offline; configured bridge/veth routes grant connectivity. `network_endpoint`
retains creation-namespace provenance, logical bind/peer addresses and private
port translation, never a data OFD. The weak fabric endpoint list unlinks before
final release. Namespace peers can use identical internal ports. Root-fabric
explicit binds (including port zero) and listeners reserve real Android ports
through separate forwarding frontends; automatic outgoing binds do not publish
a listener. Guest backing sockets use ephemeral native ports. Conflicts and
final release belong to the same endpoint/forwarding owners.

`network_io` uses the shared exact-description capture and cancellable IO owner
for control, connect/accept and addressed TCP/UDP calls. No table/fabric turn
spans blocking IO or guest copying. Connect/accept jobs use the existing
completion event and interrupt/reap path; cancellation closes an undelivered
accepted FD. Ordinary stream IO remains native. Shared payload/vector helpers
serve both Unix ancillary transport and routed message IO; native networking
does not allocate these routed owners.

`sendto`/`recvfrom` without a peer-address operand also retain the original
kernel call, PC and signal mask, including on routed data endpoints. The
supervisor and both socket adapters share that classification. Netlink and
device-event carriers remain adapted; this shortcut neither translates an
address nor handles ancillary data. Keeping a blocking payload receive outside
the adapter lets a guest debugger interrupt and detach without waiting for
application data.

IPv4 `IP_PKTINFO` uses logical interface and destination addresses on receive,
including a missing `msg_name` and truncated ancillary buffers. Send accepts
local source/interface selection consistent with the supported route; unknown
interfaces, nonlocal sources and unsupported routing return explicit errors.
Native TTL/TOS ancillary settings remain available. IPv6, raw packets, multicast
subscriptions/broadcast, device-bound sockets, routed recvmmsg and other outgoing
ancillary types are unsupported.
This is not packet-level isolation: native ephemeral backing ports remain
reachable, and inherited native descriptions retain authority. Independent
supervisor transfer of these typed network owners is unsupported rather than
silently dropping their annotations.

### Nftables and Flow Forwarding

`network_filter` owns a lazy namespace-local ruleset and generation;
`network_nft` adapts `NETLINK_NETFILTER` requests to it. New namespaces begin
with an empty catalogue. Retained sockets still refer to their creation
namespace. No operation opens Android's netfilter socket or changes its firewall.
Queries and mutations require CAP_NET_ADMIN in the namespace's user owner.

The implemented ABI covers generation queries, tables, base/regular chains,
rules, exact-key sets and verdict maps, including dumps, deletion, userdata and handles.
`network_nft_objects` owns object operations; `network_nft_expression` validates
register use and translates the supported expression ABI to typed operations.
Complete begin/end batches use a private
snapshot; stale generation, invalid attributes, unsupported operations, encoding
failure or failed response publication cannot commit a partial batch. Only a
successful batch advances the generation. Mutation replies and state replacement
share the fabric lock; queries and ordinary data IO never clone the catalogue.
The shared netlink publication contract also serves rtnetlink mutations.

Requests and replies are bounded at 64 KiB in the mapped adapter slot. A ruleset
has at most 256 tables, 256 chains, 1024 rules, 64 expressions per rule and 1024
elements per set. Overflow fails explicitly. Incomplete batches are rejected,
not retained across socket calls. Loops, excessive jump depth and transitive
NAT placement in incompatible hooks are rejected before commit.

`network_filter_program` evaluates immediate/verdict, metadata, supported IPv4
address/protocol and TCP/UDP port payload, compare/range/bitwise, conntrack
state/mark/status, local/source-route classification, exact-set and verdict-map lookup, single-target
DNAT/SNAT and masquerade operations. ACCEPT ends a chain, not a hook; later
base chains may deny it. RETURN applies the base policy. Rule counters and
optional base-chain policy counters retain their values in transactional
snapshots. Cached flow decisions retain counter references for one generation,
without walking rules for each transfer. A base-chain counter applies only when
evaluation reaches its policy, not an explicit ACCEPT/DROP rule. Counters measure
logical UDP datagrams/TCP chunks and payload bytes, not kernel packets, headers,
retransmissions or connection attempts rejected before relay admission.
Logging, queues, dynamic/interval sets, flowtables, unsupported table flags,
monitoring groups and other netfilter subsystems return errors, not fake success.
The iptables-nft rule-compat attribute is validation metadata, not a packet
predicate; expressions still supply the matches. IPv4 revision-zero TCP/UDP
matches become typed transport predicates with inclusive source/destination
port ranges and inversion, without altering nft registers. DNAT/SNAT targets
translate a single address/port into the same typed NAT operation. Revision
queries advertise these supported adapters; TCP flags/options, NAT address/port
ranges, randomization and other xtables extensions are rejected. Rule/chain deletion accepts their dumped metadata but
uses the live handle/reference graph, never the caller's stale use count.

`network_flow` records logical OUTPUT/PREROUTING/FORWARD/POSTROUTING/INPUT steps,
original/translated tuples and reverse established traffic through bridge/veth
topology. Each translating step retains its before/after tuple and hook priority.
Revalidation replays the retained mapping between base chains, not before the
entire hook: early raw rules see wire addresses, later filters see translated
addresses. Reverse translation uses the corresponding destination/source NAT
hook priority. A retained flow does not reselect NAT after an allocating rule
changes; filtering still uses the current ruleset. Removing a publication or
namespace still closes the flows owned by it. The admission generation
also preserves a binding, including no NAT, when rules change before the first
payload. This is flow-level conntrack, not emulation of kernel packet queues or
TCP state tracking.
`network_forward` owns real frontend ports and a lazy epoll reactor,
separately from namespace/ruleset storage. It never retains a guest data OFD.
NAT publications are inferred from finite port predicates by abstract evaluation,
not a trial packet with guessed source fields. Unbounded publication is rejected.
Every real flow still evaluates the full predicates, including source addresses.
Port reservations are prepared before ACK; failed encoding/publication rolls
them back. Podman reservations and NAT share the same frontend lifetime.

Direct unfiltered TCP and outgoing native UDP keep native connected IO only when
neither direction has potentially denying hooks. Installing a policy that
revokes one returns atomic `EBUSY`; it cannot retroactively move
a kernel stream into a relay. Direct path records are bounded per endpoint and
retained until socket close, including accepted stream owners. Relayed flows
cache decisions by fabric policy generation and revalidate in both directions
after rules/topology changes. Private UDP uses the same relay even without
filter rules: its queued source identity must survive sending-socket closure.
The retained tuple does not authorize delivery to a reused native port; closed
peers cannot receive new traffic. Addressed UDP reuses its established translation
instead of interpreting NEW/NAT for each send. Removed/down interfaces and
disabled forwarding stop mediated traffic; established direct native IO is not
intercepted by such topology updates.

The reactor handles nonblocking native sockets, backpressure and TCP half-close.
TCP has two 64 KiB buffers per mediated flow. UDP preserves datagrams, queues
temporary EAGAIN up to 64 datagrams/256 KiB per direction, and expires idle
mappings after 30 seconds, including retained identity for unread queued data.
This is a bounded flow lifetime, not indefinite native datagram metadata retention.
Queue exhaustion drops datagrams, never reports a
fake protocol reply. Limits are 512 listeners and 1024 mediated flows per fabric.
Idle listeners have no polling timer. Weak namespace/event identities avoid
ownership cycles and stale FD-reuse events; namespace/endpoint teardown and
reactor join release all associated resources.

This is flow-level compatibility, not native packet conntrack or a host firewall.
Backing ports remain reachable outside the logical policy. There is no Android
firewall mutation, guest daemon, external library or shared-startup prerequisite.
The native model tests, stock nft traffic fixture and Podman bridge fixture
separately verify rules, data IO and lifecycle. Docker 29's nftables backend runs
through these same operations with userland-proxy disabled; its explicit
iptables-disabled userland-proxy profile remains a separate comparison.
`AF_BRIDGE` link queries expose bridge ports and their hairpin state. Hairpin
forwarding uses that state, not an engine-specific exemption.

## Namespace-Owned Sysctls

`network_sysctl` supplies the managed namespace's
`ip_unprivileged_port_start`, `ping_group_range`, `ip_local_port_range` and
`ip_forward`, plus per-interface `route_localnet`, `rp_filter` and `arp_notify`.
Validated updates share one namespace lock, including overlapping port bounds.
Opening captures the network owner; subsequent setns does not retarget that FD.
Writes require CAP_NET_ADMIN in its user owner, without touching host sysctls.
Host-network views retain native access and errors. Logical unprivileged-port
and ephemeral-range settings also govern routed endpoint allocation. Ping group
configuration does not imply an ICMP transport.
`bridge-nf-call-iptables=1` describes the shared IPv4 bridge filtering path;
disabling this separate hook model is unsupported, not silently accepted.
Forwarding starts enabled only in the explicitly selected routed launch root.
New/copied network namespaces default to zero. The boolean gates external
destination selection through a different routing owner, without blocking that
owner's own connections or intercepting data IO on established streams.
Interface controls resolve a name once to a namespace-local policy lifetime.
Rename retains the open description; deletion or movement out of its owner
yields ENODEV even after the same interface returns. Name reuse cannot redirect
it. Topology rollback restores the prior policy lifetime alongside its values.
`conf/default` initializes newly created interfaces;
`conf/all` participates in ingress policy. Strict and loose reverse-path checks
and loopback-source/destination policy apply at logical routing boundaries.
The fabric resolves live addresses directly, without an ARP neighbor cache;
`arp_notify` does not emit packets onto Android's physical network.
Mounted proc enumerates only the selected namespace's interfaces and supported
controls. Unknown controls are not implemented.

Rtnetlink veth creation can assign a generated local name and create its peer
directly in a namespace selected by an owned namespace FD. Both endpoints share
one topology transaction, including rollback when response publication fails.
Renaming is independent of cross-namespace move support. The single supported
IPv4 default route retains its metric for queries, notifications and matching
deletion; multiple default routes and policy routing remain unsupported.

Native rlimits retain the launch identity's real kernel ceilings. Virtual root
does not grant Android CAP_SYS_RESOURCE: requests exceeding a hard limit keep
the kernel's EPERM instead of reporting a fictitious successful increase.
Container launch limits must fit the inherited ceilings; the Podman fixture
records those ceilings and offers an explicit inherited-limit diagnostic mode.

Mounted proc controls are selected on the filesystem worker and retain a live
mount anchor. Readonly policy applies to future opens and already opened writers,
including after lazy detach. Ordinary proc spelling uses the same typed provider
without a logical mount anchor. The common descriptor host supplies dup/fork,
offsets and positional IO; numeric writes at a nonzero offset consume bytes without
changing the value. No additional service thread or per-IO FD is created.

`network_proc` supplies `tcp`, `tcp6`, `udp` and `udp6` through that same proc
descriptor contract. It snapshots only live tracked endpoints belonging to the
selected logical network namespace. Logical addresses, ports and guest owner IDs
come from the endpoint model; the matching native socket inode supplies kernel
state and queue counters. This is not a dump of Android's host sockets. The
current routed transport is IPv4, so IPv6 tables contain only their header.
Unowned terminal entries such as TIME_WAIT sockets are not synthesized.
An open retains its selected namespace across setns; dup shares the offset,
and reading from offset zero refreshes the snapshot. Unmanaged host networking
keeps the native proc path and its permission failures.

## Namespace-Owned Sysfs

`sysfs_view` retains the network namespace selected at legacy mount or fsopen.
Mount authorization belongs to that network namespace's user owner. The limited
offline tree contains `class/net/lo`, its relative device/subsystem links,
identity/MTU/flags/operstate/carrier attributes and `fs/cgroup` for separate mounts.
`network_namespace` supplies the same atomic link snapshot to sysfs, ioctl and
netlink. Mounted views do not follow the reader's later setns.

The private name tree supplies stable native inode identities and ordinary
directory enumeration, not attribute data or Android device access. Typed control
files use the common IO/cursor contract; retained mount origins keep both the
tree and network owner alive. Bind/copy/detach share ordinary mount ownership.
Closing the final owner retires the temporary tree. An unknown attribute returns
ENOENT; unimplemented mutations and host-network sysfs return EOPNOTSUPP.
Cross-supervisor export is rejected rather than flattening the provider into a
native bind. No host mount, background refresh or per-read descriptor is needed.
