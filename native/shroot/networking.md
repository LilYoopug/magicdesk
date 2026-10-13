# Guest Networking

[Native architecture](README.md) | [Resource model](process-resources.md)

Namespace-local network configuration, supported nftables flow filtering and NAT. This is not an Android firewall or native-kernel isolation.

- [Network Namespaces](#network-namespaces)
- [Namespace-Owned Sysctls](#namespace-owned-sysctls)
- [Namespace-Owned Sysfs](#namespace-owned-sysfs)

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

IPv6, raw packets, multicast subscriptions/broadcast,
device-bound sockets and routed recvmmsg return explicit errors. Outgoing
network ancillary data is rejected; incoming packet metadata is not translated.
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
rules and exact-key sets, including dumps, deletion, userdata and handles.
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
state/mark/status, local-route classification, exact-set lookup, single-target
DNAT/SNAT and masquerade operations. ACCEPT ends a chain, not a hook; later
base chains may deny it. RETURN applies the base policy. Packet counters,
logging, queues, dynamic/interval sets, flowtables, unsupported table flags,
monitoring groups and other netfilter subsystems return errors, not fake success.

`network_flow` records logical OUTPUT/PREROUTING/FORWARD/POSTROUTING/INPUT steps,
original/translated tuples and reverse established traffic through bridge/veth
topology. `network_forward` owns real frontend ports and a lazy epoll reactor,
separately from namespace/ruleset storage. It never retains a guest data OFD.
NAT publications are inferred from finite port predicates by abstract evaluation,
not a trial packet with guessed source fields. Unbounded publication is rejected.
Every real flow still evaluates the full predicates, including source addresses.
Port reservations are prepared before ACK; failed encoding/publication rolls
them back. Podman reservations and NAT share the same frontend lifetime.

Direct unfiltered internal/outgoing flows keep native connected IO only when
neither direction has potentially denying hooks. Installing a policy that
revokes one returns atomic `EBUSY`; it cannot retroactively move
a kernel stream into a relay. Direct path records are bounded per endpoint and
retained until socket close, including accepted stream owners. Relayed flows
cache decisions by fabric policy generation and revalidate in both directions
after rules/topology changes. Addressed UDP reuses its established translation
instead of interpreting NEW/NAT for each send. Removed/down interfaces and
disabled forwarding stop mediated traffic; established direct native IO is not
intercepted by such topology updates.

The reactor handles nonblocking native sockets, backpressure and TCP half-close.
TCP has two 64 KiB buffers per mediated flow. UDP preserves datagrams, queues
temporary EAGAIN up to 64 datagrams/256 KiB per direction, and expires idle
mappings after 30 seconds. Queue exhaustion drops datagrams, never reports a
fake protocol reply. Limits are 512 listeners and 1024 mediated flows per fabric.
Idle listeners have no polling timer. Weak namespace/event identities avoid
ownership cycles and stale FD-reuse events; namespace/endpoint teardown and
reactor join release all associated resources.

This is flow-level compatibility, not native packet conntrack or a host firewall.
Backing ports remain reachable outside the logical policy. There is no Android
firewall mutation, guest daemon, external library or shared-startup prerequisite.
The native model tests, stock nft traffic fixture and Podman bridge fixture
separately verify rules, data IO and lifecycle; Docker is also checked with its
explicit iptables-disabled userland-proxy profile.

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
