# OLYMP Inter-Node Control-Plane Protocol

Version: 0.1
Status: Planned design - not implemented
Date: 2026-11-17

## 1. Purpose and scope

This document describes the planned communication between OLYMP nodes:

- ARES to HERA.
- HERA to ARES.
- HERA to ZEUS.
- ZEUS to HERA.

It does not describe local communication between ARES and its child
processes. Local child IPC is documented in `docs/protocols/IPC.md`.

The inter-node protocol carries incident reports, task assignments, task
results, configuration, node status and software-update metadata.

All functionality in this document is planned unless explicitly marked
otherwise. No inter-node protocol is currently implemented in ARES.

## 2. Network endpoint and transport

The control plane uses VLAN 18.

The planned HERA address convention is `10.x.18.32/24`; `x` is site-specific.
The concrete endpoint must be configurable for an ARES instance and must
not require rebuilding the Golden Image when a site address changes.

The planned transport is TLS 1.3 with mutual certificate authentication
(mTLS):

- ARES verifies the HERA server certificate.
- HERA verifies the ARES client certificate.
- HERA and ZEUS authenticate each other in the same way.
- Plaintext control-plane connections are not permitted.

VLAN membership, source IP address or reachability of the HERA endpoint
must not be treated as proof of identity or authorization.

## 3. Node identity and first enrollment

Each node has a unique identity containing at least:

- `node_id` - stable UUID for the node.
- `node_type` - `ARES`, `HERA` or `ZEUS`.
- `site_id` - site assignment where applicable.
- `parent_id` - the node's parent in the OLYMP hierarchy where applicable.

On first boot, ARES generates its UUID and the private key used for its
mTLS node certificate locally. That private key never leaves the ARES host.
The image contains only the public OLYMP trust anchor needed to verify HERA.

If application-message signatures use a separate key pair, ARES must
generate that private key locally as well. Its public key and purpose must
be securely bound to the same authorized node identity. The enrollment and
key-registration workflow for this second key is not yet specified.

ARES first verifies HERA's server identity, then submits a certificate
signing request and enrollment information. HERA authorizes the enrollment
and arranges issuance of an individual ARES certificate.

The authorization method is not yet selected. Candidate methods include:

- a pre-authorized node record created by an administrator;
- a short-lived, single-use enrollment token;
- explicit approval in HERA.

A new node must not be trusted merely because it can connect to VLAN 18 or
to the HERA IP address. Re-enrollment, revocation and recovery after a
compromised node must also be defined before production deployment.

## 4. Transport security and message signatures

mTLS protects each network connection, authenticates both endpoints and
protects data in transit.

For security-sensitive commands and provenance-sensitive reports, the
protocol is also intended to support an application-level digital signature.
This is important when a message is forwarded from ARES through HERA to ZEUS:
the receiver should be able to distinguish the original ARES author from
the node that relayed the message.

The final signature algorithm, canonical serialization and key lifecycle
are open design items. Ed25519 is a candidate, not a frozen requirement.

A signed message envelope should include at least:

- message ID;
- message type and protocol version;
- original sender node ID;
- intended recipient or audience;
- creation time and expiry time where applicable;
- incident ID or task ID for correlation;
- payload;
- signature metadata and signature.

Commands must be protected against replay. The design must include unique
message/task IDs, expiry or sequence validation, deduplication and explicit
recipient checking.

### Key ownership and separation (proposed baseline)

OLYMP uses separate trust and key purposes. A key used to authenticate a
network node must not automatically grant authority to sign software releases.

- **Node identity / mTLS:** Each node generates and retains its own private
  key. ARES private keys never leave their VM. An OLYMP certificate authority
  issues individual node certificates. HERA may broker enrollment and relay
  certificate requests, but it must never receive an ARES private key.
- **Application message signatures:** Security-sensitive commands and
  provenance-sensitive reports use a node-specific signing identity. The
  preferred design is to keep message-signing keys separate from TLS
  transport keys. If this separation is adopted, the signing key is generated
  and retained locally, and its public key is registered/bound to the node
  identity through an authenticated enrollment process. The original
  sender's signature must remain verifiable when HERA forwards a message to
  ZEUS.
- **Software release signatures:** Package and repository signing keys belong
  to a centrally governed OLYMP release-signing authority under ZEUS release
  policy. Their private keys are held outside ordinary HERA and ARES runtime
  hosts, preferably offline or in an HSM-backed signing service. ZEUS
  authorizes/promotes releases; HERA mirrors and distributes the already
  signed artifacts and must not be able to create a valid release signature.
- **Trust anchors and recovery:** Public trust anchors are provisioned to
  nodes. Root-key protection, issuing-CA operation, key rotation, revocation,
  emergency replacement and compromised-key recovery must be documented
  before production deployment.

This is the proposed ownership model, not an implemented PKI. The final
certificate hierarchy, signing formats and operational custody arrangements
remain open design decisions.

## 5. Message classes

The following logical message classes are planned. Exact JSON schemas and
wire encodings are not frozen.

### 5.1 Incident reporting - upward

- `INCIDENT_REPORT` - new incident created by ARES.
- `INCIDENT_UPDATE` - new evidence or changed assessment for an incident.
- `TASK_RESULT` - result of a task performed by an ARES child such as DEIMOS.
- `ACTION_REPORT` - record of an action decision and its execution state.

ARES sends incident reports to HERA. HERA correlates reports across the
site and forwards the initial incident to ZEUS promptly. HERA must not wait
for a DEIMOS task to finish before sending the initial incident. Later
investigation results are sent as updates.

### 5.2 Task and policy delivery - downward

- `TASK_ASSIGNMENT` - HERA assigns a task to a specific ARES.
- `TASK_CANCEL` - HERA cancels a previously assigned task.
- `CONFIG_UPDATE` - HERA provides the ARES configuration or policy.
- `POLICY_UPDATE` - ZEUS provides site/global policy through HERA.

HERA sends DEIMOS tasks to ARES, not directly to DEIMOS. ARES validates
the sender, recipient, authorization, task parameters, target scope, expiry
and replay status before executing a task.

### 5.3 Node and software status

- `NODE_STATUS` - node health and connectivity status.
- `COMPONENT_STATUS` - installed, enabled, running and version state for
  each child component.
- `UPDATE_MANIFEST` - approved component versions and compatibility data.
- `UPDATE_RESULT` - success, failure or rollback result.

## 6. Incident and task identifiers

Incident IDs must be stable across ARES, HERA and ZEUS. An incident may
contain multiple source sensor events and may receive multiple updates.

Task IDs must be globally unique within OLYMP and idempotent. Re-delivery
of the same task must not cause the task to execute more than once unless
the task explicitly supports safe retries.

The protocol must preserve both:

- the original event/incident author;
- the immediate sender/relay of the current message.

This allows ZEUS to verify that an incident originated at a particular
ARES even though HERA forwarded it.

## 7. Delivery and offline behavior

Important incident reports, task assignments, task results and update
results must use durable delivery semantics.

The planned design includes:

- persistent outbound queue/outbox;
- acknowledgements for important messages;
- bounded retry with backoff;
- deduplication at receivers;
- persistent inbound task state;
- expiry and cancellation handling;
- reporting of delivery failures.

When HERA is unavailable, ARES retains events, incidents and results locally.
When ZEUS is unavailable, HERA retains site incidents and continues local
coordination. Queued messages are delivered after connectivity returns.

A connectivity failure must not silently convert a HERA decision into an
ARES decision. If ARES uses a local fallback policy to start DEIMOS, the
result must identify the decision as local/autonomous.

## 8. Software distribution relationship

HERA is the local distribution point for its site. It receives or mirrors
approved signed releases from ZEUS and exposes a local APT repository or
equivalent package source to ARES nodes.

ARES downloads packages from HERA but independently verifies repository
metadata and package signatures. mTLS does not replace package-signature
verification. Package-signing keys are separate from node identity keys.

The detailed provisioning and update flow is documented in
`docs/deployment/ares-vm.md`.

## 9. Open design decisions

The following items must be resolved before production implementation:

1. Enrollment authorization: pre-registration, one-time token or explicit
   approval.
2. PKI hierarchy and certificate issuance/revocation responsibilities.
3. Message-signature algorithm, canonical serialization and whether
   application-signing keys are separate from mTLS keys, including their
   enrollment/binding lifecycle.
4. Exact message schemas, size limits and protocol version negotiation.
5. Durable queue, acknowledgement, retry and deduplication semantics.
6. Certificate renewal, rotation, revocation and compromised-node recovery.
7. Control-plane ports, firewall policy and connection initiation direction.
8. Whether HERA-to-ZEUS uses the same transport and envelope as ARES-to-HERA.

## 10. Relationship to current implementation

The current ARES/PHOBOS implementation uses a local Unix datagram
`socketpair()` for child-to-parent IPC. That implementation is not the
inter-node control-plane protocol described here.

No ARES-HERA or HERA-ZEUS transport, enrollment, mTLS, message signature,
incident forwarding or package distribution is implemented in the current
baseline.
