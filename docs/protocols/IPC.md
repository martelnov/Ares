# OLYMP IPC Protocol

Version: 1
Status: Initial PHOBOS-ARES implementation

## 1. Purpose

This document describes the current local IPC protocol between PHOBOS
and its parent ARES.

The protocol is intended to become the common child-parent protocol
for OLYMP sensors and workers.

The current implementation is not yet a complete generic protocol.

## 2. Transport

Current transport:

- Unix domain datagram socket.
- Created by ARES using socketpair().
- One socket descriptor is inherited by PHOBOS.
- Descriptor is passed through ARES_IPC_FD.
- PHOBOS uses nonblocking sends.

If ARES_IPC_FD is absent, PHOBOS operates without IPC.

IPC failure must not block RDP processing.

## 3. Message envelope

Current JSON message structure:

    {
      "version": 1,
      "event": "CONNECTION",
      "timestamp": "RFC3339 timestamp",
      "pid": 1234,
      "data": {}
    }

Fields:

- version: protocol version.
- event: event name.
- timestamp: event timestamp.
- pid: sender process ID.
- data: event-specific payload.

Current maximum encoded message size is 4096 bytes.

## 4. Current PHOBOS events

### READY

Sent after the RDP listener is ready.

Payload:

- listen_ip
- listen_port
- max_connections

### HEARTBEAT

Sent every 5 seconds.

Payload:

- active_connections

### CONNECTION

Sent immediately after TCP accept, before RDP negotiation.

Payload:

- connection_id
- source_ip
- source_port
- destination_ip
- destination_port
- local_port
- protocol

The destination address is important because one honeypot host may
serve multiple VLANs and IP addresses.

HERA can use destination_ip to map the connection to the relevant VLAN.

### DISCONNECT

Sent when a connection ends or is rejected.

Payload:

- connection_id
- reason

Current reasons include:

- connection_limit
- closed
- handshake_failed
- handshake_timeout

### CAPTURED

Sent after FENIX has successfully persisted the authentication event.

Payload:

- connection_id
- source_ip
- source_port

PHOBOS exits after successful identity capture.

The parent must not rely solely on receiving CAPTURED. The forensic
JSONL record remains authoritative if IPC delivery fails.

### ERROR

Reports an operational error.

Current example:

- FORENSIC_WRITE_FAILED

## 5. Current delivery properties

The current transport uses nonblocking datagram sends.

There is no application-level acknowledgement or retransmission yet.

Messages may therefore be lost if the receiver is unavailable or the
socket buffer is full.

Forensic events must be persisted independently of IPC.

A future protocol version should consider:

- Message UUID.
- Acknowledgements for important commands.
- Retry and deduplication.
- Explicit child identity.
- Task identifiers.
- Cancellation.
- Graceful shutdown.
- Protocol capability negotiation.

## 6. Connection identity

connection_id currently starts from 1 in each PHOBOS process.

Until globally unique connection identifiers are introduced, the
combination of sender PID and connection_id identifies a connection
within the current implementation.

## 7. Planned common child protocol

The future common protocol may include:

Child to parent:

- READY
- HEARTBEAT
- CONNECTION
- EVENT
- TASK_RESULT
- DISCONNECT
- ERROR

Parent to child:

- TASK
- CANCEL
- SHUTDOWN
- CONFIG_UPDATE

This section describes planned functionality, not the current
implemented protocol.
