# OLYMP Implementation Status

- Status date: 2026-11-17
- Repository: martelnov/Ares
- Branch: main
- Verified code baseline commit: 124eac1
Documentation source/base commit: 54cb0fb

Status labels:

- IMPLEMENTED: present in source code.
- TESTED: verified in a practical test.
- PLANNED: agreed direction, not implemented.
- PROPOSED: requires a decision.

## 1. PHOBOS

### Implemented and tested

- Standalone RDP honeypot process.
- RDP/X.224 negotiation.
- TLS.
- CredSSP/NTLM authentication path.
- NTLM Type 3 identity capture.
- No interactive RDP session finalization.
- FENIX JSONL authentication event.
- Log write, flush and sync_all before successful capture notification.
- Startup refusal if the forensic log cannot be opened and synchronized.
- Optional ARES IPC through inherited Unix datagram socket.
- READY event.
- HEARTBEAT every 5 seconds.
- CONNECTION event with source and destination addresses.
- DISCONNECT event.
- CAPTURED event.
- ERROR event.
- Maximum four concurrent connections.
- 30-second handshake timeout.
- Standalone operation when ARES_IPC_FD is absent.
- DenyOutbound implementation rejects outbound authentication network requests.

### Dependencies removed from PHOBOS configuration

- SmartCard support is optional and disabled for PHOBOS.
- cryptoki and winscard are absent from the tested dependency tree.
- reqwest, hyper and hyper-util are absent from the tested dependency tree.

DenyOutbound does not replace operating-system network isolation. It only
rejects requests made through the relevant authentication NetworkClient
interface.

### Not yet verified or implemented

- Multi-VLAN deployment test.
- Explicit multi-address listener configuration.
- Actual Security Onion ingestion test.
- IPC acknowledgement and retransmission.
- Globally unique connection identifiers.

## 2. ARES

### Implemented and tested

- Standalone Rust executable.
- Starts PHOBOS as a child process.
- Creates Unix datagram socketpair.
- Passes inherited IPC descriptor through ARES_IPC_FD.
- Receives READY.
- Receives HEARTBEAT.
- Receives CONNECTION.
- Receives CAPTURED.
- Receives DISCONNECT and ERROR.
- Restarts PHOBOS after successful identity capture.
- Exponential restart backoff after unexpected exits.
- 20-second heartbeat watchdog.
- Starts PHOBOS in a separate process group.
- Handles SIGINT and SIGTERM.
- Sends SIGTERM to PHOBOS during shutdown.
- Waits for child termination and uses a forced kill after the grace period
  if necessary.

Practical tests verified:

- Multiple successful RDP identity captures.
- Automatic PHOBOS restart after capture.
- Continued ARES operation across PHOBOS restarts.
- Graceful ARES shutdown.
- PHOBOS termination with SIGTERM when ARES receives Ctrl+C.

### Current limitations

- ARES currently supervises PHOBOS specifically.
- Child executable and arguments are supplied on the command line.
- No generic child registry.
- No configuration-driven child management.
- No generic sensor/worker distinction in code.
- No Incident Manager.
- No Task Manager.
- No HERA communication.
- No ZEUS communication.
- No DEIMOS integration.
- No router or firewall integration.
- No node identity, enrollment or certificate lifecycle.
- No inter-node mTLS or application-level message signatures.
- No durable incident outbox or inter-node acknowledgements.
- No package repository client or child update mechanism.

## 3. HERA

PLANNED

- Site-level coordinator for multiple ARES instances.
- Receives incident reports and task results from ARES.
- Correlates incidents across the site.
- Knows local topology, VLANs and network devices.
- Decides whether to request a DEIMOS investigation and sends tasks to ARES.
- Forwards new incidents to ZEUS promptly and sends subsequent updates.
- Coordinates local security responses.
- Manages Cisco and MikroTik integration.
- Hosts or caches a site-local repository of approved signed packages.
- Controls site-level software rollout and version policy.
- Continues local coordination and serves cached packages when ZEUS is
  unavailable.

## 4. ZEUS

PLANNED

- Global root.
- Receives incidents and updates from HERAs.
- Correlates incidents across sites.
- Provides global reporting and policy coordination.
- Approves or distributes software releases and policies to HERAs.
- Maintains global operational and version visibility.

## 5. Other children

### ATHENA

PLANNED

SMB honeypot offering decoy shares, directories and files.

### HADES

PLANNED

MSSQL honeypot.

### Additional sensor services

PLANNED

- FTP honeypot.
- NFS honeypot.
- SSH honeypot.
- MySQL honeypot.

### DEIMOS

PLANNED

Worker managed by ARES. HERA submits a task to ARES. ARES validates and
delegates it to DEIMOS. Results return through ARES to HERA and are then
reported to ZEUS. If HERA is unavailable, ARES may use only an explicitly
bounded local fallback policy.

## 6. Architecture and deployment decisions

PLANNED

- One universal Debian Linux ARES VM image; no separate Windows/Linux ARES
  operating-system images.
- ARES can enable any supported combination of honeypot services.
- Distinguish installed, enabled and running component states.
- Clone-safe first-boot provisioning with a unique node UUID and private key.
- Automatic connection to the configured HERA control-plane endpoint on
  VLAN 18; planned address convention `10.x.18.32/24`.
- Individual node certificates and mTLS for ARES-HERA and HERA-ZEUS.
- Application-level signatures for security-sensitive commands and
  provenance-sensitive incident/action reports.
- HERA decides on DEIMOS tasks when reachable; ARES has bounded local
  fallback behavior during HERA outages.
- HERA as site-local package repository/cache for approved signed releases.
- ARES verifies package signatures and installs approved child updates.
- Retention of a previous known-good package version and a rollback process.

The following design decisions remain open:

- Enrollment authorization method (pre-authorized inventory, single-use
  token or explicit HERA approval).
- PKI hierarchy and certificate issuance/revocation responsibilities.
- Final message-signature algorithm and canonical serialization.
- Whether an unregistered first-boot clone may start any honeypot before
  successful enrollment.
- Exact update policy for ARES self-updates.
- Provisioning metadata/seed mechanism for the HERA endpoint and optional site hint.
- Authoritative site/parent assignment and registration inventory workflow.
- OLYMP CA, message-signing and release-signing key ownership/custody, rotation and recovery.
- Incident lifecycle states, layer-specific correlation IDs and update ordering.

## 7. Network response

PLANNED

HERA, not ARES, manages network infrastructure.

One planned response is to block a suspicious source IP from other protected
VLANs while preserving access to the VLAN containing the contacted honeypot.

This requires topology-aware policy, exceptions, expiration, conflict
handling and verification of actual device state.

No production router or firewall changes are currently implemented.

## 8. Next development priorities

1. Review and modularize the current ARES implementation without changing
   existing PHOBOS behavior.
2. Define generic child process configuration and a child registry.
3. Separate long-running sensors from task workers.
4. Finalize the common local child IPC protocol.
5. Implement local event normalization and incident management.
6. Design durable incident/result storage and an outbound queue.
7. Define node identity, enrollment and the inter-node control-plane protocol.
8. Implement ARES-HERA communication over VLAN 18 using mTLS.
9. Implement HERA incident correlation and the DEIMOS decision/task flow.
10. Integrate DEIMOS as an ARES-managed worker.
11. Design HERA's signed package repository and ARES child-update workflow.
12. Implement HERA-ZEUS communication and global incident correlation.
13. Prepare and test the universal Debian Golden Image and clone lifecycle.

## 9. Important development rule

Documentation must distinguish implemented, tested, planned and proposed
functionality.

A successful compilation is not equivalent to a practical test.

A planned security response, enrollment mechanism or update process must
never be described as active until it has been implemented and verified.
