# OLYMP Implementation Status

Status date: 2026-11-17
Repository: martelnov/Ares
Branch: main
Verified baseline commit: 124eac1

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

DenyOutbound does not replace operating-system network isolation.
It only rejects requests made through the relevant authentication
NetworkClient interface.

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
- Waits for child termination and uses a forced kill after the grace
  period if necessary.

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

## 3. HERA

PLANNED

- Site-level coordinator.
- Receives events from ARES instances.
- Knows local topology, VLANs and network devices.
- Coordinates local security responses.
- Manages Cisco and MikroTik integration.
- Sends tasks to ARES, not directly to DEIMOS.

## 4. ZEUS

PLANNED

- Global root.
- Receives information from HERAs.
- Correlates incidents across sites.
- Provides global reporting and policy coordination.

## 5. Other children

### ATHENA

PLANNED

SMB honeypot offering decoy shares, directories and files.

### HADES

PLANNED

MSSQL honeypot.

### Linux services

PLANNED

- FTP honeypot.
- NFS honeypot.
- SSH honeypot.
- MySQL honeypot.

### DEIMOS

PLANNED

Worker managed by ARES.

HERA submits a task to ARES. ARES validates and delegates it to
DEIMOS. Results return through ARES to HERA.

## 6. Network response

PLANNED

HERA, not ARES, manages network infrastructure.

One planned response is to block a suspicious source IP from other
protected VLANs while preserving access to the VLAN containing the
contacted honeypot.

This requires topology-aware policy, exceptions, expiration, conflict
handling and verification of actual device state.

No production router or firewall changes are currently implemented.

## 7. Next development priorities

1. Modularize ARES.
2. Define generic child process configuration.
3. Separate long-running sensors from task workers.
4. Finalize the common IPC protocol.
5. Implement local incident management.
6. Implement task management.
7. Implement ARES-HERA communication over VLAN 18.
8. Integrate DEIMOS as an ARES-managed worker.
9. Implement HERA network-device adapters in dry-run mode.
10. Implement ZEUS-HERA communication.

## 8. Important development rule

Documentation must distinguish implemented, tested and planned
functionality.

A successful compilation is not equivalent to a practical test.

A planned security response must never be described as active until
it has been implemented and verified.
