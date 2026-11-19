# ARES network bootstrap prototype (experimental)

This is **not production provisioning**. It is a separately executable diagnostic
binary. Existing `ares` PHOBOS supervisor is unchanged. No IP addresses, routes,
VLANs, DNS or sensor configurations are modified by this program.

## Assumptions

- IPv4 address convention `10.B.V.x`, router `10.B.V.1`.
- Management VLAN number `V` comes from TOML (default deployment value 18).
- One Ethernet access interface per VLAN. No 802.1Q trunk support yet.
- New ARES nodes are enrolled **one at a time**.
- At least one existing peer is online for subsequent allocations. Explicit
  `allow_first_node=true` is only for bootstrap of the first-ever node.
- Linux `CAP_NET_RAW`, direct layer-2 connectivity and a
  management-VLAN firewall/switch allowing local experimental EtherType 0x88B5.
- Authenticated packets require the same 32-byte HMAC-SHA256 pre-shared key
  on participating management nodes. Key compromise affects the entire site.

## Native ARP probe

The ARP check is implemented in Rust using Linux `AF_PACKET` and EtherType
0x0806. It sends ARP requests with sender IPv4 `0.0.0.0`, bound to a specific
Ethernet interface. It does **not** require any IPv4 address on that interface,
launch `arping`, or alter network configuration. It needs `CAP_NET_RAW`.

A valid ARP reply reports the address as **occupied**. No ARP reply means
**inconclusive**, not guaranteed free. Some routers do not answer probes whose
sender IPv4 is zero. Such devices cannot be discovered with this probe and
must be tested on real deployment hardware before using automated bootstrap.

On a development host without management VLAN 18 you can test the native
probe against its *real local gateway* without loading any ARES configuration:

```bash
sudo ./target/debug/ares-net arp-probe <interface> <gateway-ip>
```

The command sends ARP requests only, does not set any IPv4 address, and
reports either the responding MAC or an inconclusive timeout.

This is a prototype; no automatic HERA management, signature verification,
network IP assignment, or production allocation guarantees have been added.

## Install and test

```
cd /AI/apps/rdp-honeypot/ARES/ares
cargo fmt --check
cargo test --bin ares-net
cargo clippy --bin ares-net -- -D warnings
```

Create a test key with restrictive permissions on every test ARES (same key
across test participants; never commit it):

```
sudo install -d -m 0700 /etc/olymp /var/lib/olymp
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/olymp/ares-network.key'
```

Edit the sample TOML to match the **actual branch** `B` and real `BRANCH.tsv`
values. If `branch="auto"`, it tries `10.B.V.1` for every B in that table and
requires one unambiguous match. Use an IP-free test NIC if appropriate; some
routers do not answer ARP probes with source 0.0.0.0 and the program will
intentionally refuse to guess.

Safe first test (router/ARP only, no state writes):

```
sudo cargo run --bin ares-net -- probe config/ares-network.example.toml
```

After testing on an **isolated lab VLAN** with two ARES VMs, set the same key
on both, set `allow_first_node=true` **only on the first machine** and start:

```
sudo cargo run --bin ares-net -- run config/ares-network.example.toml
```

Then set `allow_first_node=false` on the second VM (and on first after bootstrap)
and run the same command. The first peer must remain running to answer
`CONF_REQ` and acknowledge `CLAIM_REQ`. Both show monotonic `IP_MAX` and
broadcast `IP_SYNC` every 60 seconds.

## Wire format

Ethernet broadcast, local experimental EtherType 0x88B5; signed JSON.
Message kinds: `CONF_REQ`, `CONF_RESP`, `CLAIM_REQ`, `CLAIM_ACK`, `CLAIM_NAK`,
`MAX_IP`, `IP_SYNC`. Common signed envelope: protocol, version, branch, VLAN,
node_id, nonce, assigned_x, ip_max, proposed_x. The node_id is generated and
persisted locally, never regenerated on normal restart. Each new allocation
has an ARP duplicate-address probe and requires a durable reservation ACK
from a previously discovered peer.

For a second machine, lack of live peers is **not** enough to decide that a
site is empty, even when the router replies. Thus it fails closed by default.

## Deliberate limitations

- No OS IP configuration yet. `assigned_x` in state only reserves an octet.
- No automatic sensor VLAN mapping yet; `VLANS.tsv` is illustrative.
- Does not support simultaneously enrolling two clones, snapshots with stale
  identities, malicious insiders holding the shared key, or partitions.
- If no online peer has the highest historical `IP_MAX`, even authenticated
  gossip cannot reconstruct it. An authoritative ledger (eventually HERA or
  offline deployment inventory) is necessary for a stronger guarantee.
- Gateway ARP proves local L2 reachability, **not** peer availability, nor
  complete allocator history.
- Do not place the same PSK inside a widely distributed public Golden Image.
- Never run `allow_first_node=true` on a newly cloned VM after a site exists.

Do not rely on this prototype to assign production IPs.
