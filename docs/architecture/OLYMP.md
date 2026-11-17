# OLYMP Architecture

- Version: 1.1
- Status: Architecture baseline - deployment and control-plane decisions added
- Date: 2026-11-17

## 1. Purpose

OLYMP is a distributed security and honeypot ecosystem.

Its purpose is to provide specialized honeypot services, local supervision,
forensic collection, investigation and coordinated defensive responses.

The system is intended to reduce dependence on Security Onion for honeypot
management.

Security Onion remains a possible independent monitoring and analysis
platform. Sensor-level forensic output must remain usable without OLYMP.

## 2. Hierarchical architecture

OLYMP is a tree.

ZEUS is the root. HERA manages a site. Each ARES manages one honeypot host.
Specialized sensors and workers are children of ARES.

    OLYMP
      |
     ZEUS
      |
    HERA (site)
      |
      +-------------------------------+
      |               |               |
    ARES-001        ARES-002        ARES-003
      |               |               |
      +-- PHOBOS      +-- SSH          +-- PHOBOS
      +-- ATHENA      +-- FTP          +-- ATHENA
      +-- HADES       +-- NFS          +-- DEIMOS (worker)
      +-- SSH         +-- MySQL
      +-- DEIMOS      +-- DEIMOS

The diagram is conceptual. Each ARES may enable any supported combination
of sensors. The number of sites, ARES instances and children is
configuration-dependent.

### 2.1 One universal ARES host image

The first deployment phase uses one universal Debian Linux VM image for
ARES and focuses on cloning that prepared image. Installation on a physical
Debian Linux host may be supported later using the same software packages.

There are not separate Windows and Linux ARES operating-system images.
The terms Windows-oriented and Linux-oriented describe the honeypot
protocols/services being presented, not the operating system running ARES.
The RDP, SMB and MSSQL honeypots are intended to run as services on the
Linux ARES host alongside SSH, FTP, NFS and MySQL honeypots.

The image is intended to contain ARES and the supported child packages.
The configuration assigned to an ARES instance determines which children
are enabled. A mixed profile is valid.

For every child, the following states are distinct:

- installed - package or executable is present on the host;
- enabled - policy/configuration allows the child to be started;
- running - the child process is currently active.

DEIMOS may be installed but is not a continuously running sensor. It is
started for an authorized task, or under a bounded local fallback policy
when HERA is unavailable.

## 3. ZEUS - global root

ZEUS is responsible for global coordination.

Planned responsibilities:

- Global view of all sites.
- Correlation of incidents across sites.
- Central incident history and reporting.
- Distribution of global security policies.
- Coordination of HERAs.
- Publication/approval of software releases for distribution to sites.
- Global operational and version status.

ZEUS does not directly manage individual honeypot processes or send tasks
directly to DEIMOS.

## 4. HERA - site-level coordination

HERA manages one site.

Responsibilities:

- Coordination of all ARES instances at the site.
- Knowledge of local network topology, VLANs, subnets and network devices.
- Correlation of incident reports from ARES instances at the site.
- Decision-making for site-level defensive actions, including whether to
  request a DEIMOS investigation.
- Forwarding new incidents and subsequent updates to ZEUS.
- Receiving policies and instructions from ZEUS.
- Coordination of local software rollout and approved versions.
- Hosting or caching the site's local package repository for ARES children.
- Communication with Cisco and MikroTik infrastructure.

HERA is responsible for network infrastructure actions. ARES must not
directly manage routers or firewalls.

HERA should report a new incident to ZEUS promptly. It must not wait for a
DEIMOS investigation to finish before reporting the initial incident.
Subsequent task decisions and results are sent as incident updates.

## 5. ARES - local honeypot controller

One ARES instance runs on each honeypot host. A host may be physical or
virtual. The target VM deployment is Debian Linux.

ARES responsibilities:

- Start and supervise configured local child processes.
- Receive events from children.
- Normalize and enrich sensor events with local host/sensor context.
- Perform local correlation and maintain local incident state.
- Monitor child health and heartbeat.
- Restart failed or intentionally terminated sensors according to policy.
- Retain events, incident reports and task results when the parent is
  unavailable, for later delivery where required.
- Receive tasks and configuration from HERA.
- Validate task authorization, parameters, expiry and scope.
- Delegate approved tasks to appropriate workers, including DEIMOS.
- Collect worker results and report them to HERA.
- Report incidents and operational/version status to HERA.
- Download and verify approved child packages from HERA's repository.
- Continue local operation when HERA is unavailable.

ARES does not need global site topology and does not directly control
network routers or firewalls.

When HERA is reachable, HERA decides whether DEIMOS should be used and sends
a task to ARES. If HERA is unavailable, ARES may use only its locally cached,
explicitly bounded fallback policy. ARES must record that the decision was
local and not made by HERA.

## 6. Children of ARES

Children are independent processes.

They communicate with their parent ARES through local IPC when managed
by ARES. A sensor may also operate independently if its design supports
standalone operation.

### 6.1 Sensors

Sensors are long-running processes. ARES may run any configured combination.

Windows-oriented honeypot services:

- PHOBOS - RDP.
- ATHENA - SMB and decoy file shares.
- HADES - MSSQL.

Additional honeypot services:

- SSH - SSH service.
- FTP - FTP service.
- NFS - NFS service.
- MySQL - database service.

All of these services are intended to be deployable on the same Debian Linux
ARES host. Enabling one service does not require a different ARES image.

Sensors report events, connections, authentication attempts and other
protocol-specific activity.

### 6.2 DEIMOS

DEIMOS is a worker subordinate to ARES. It is not a separate hierarchy level.

When HERA is available, HERA decides whether an investigation is required
and sends a task to ARES. ARES validates the task's authorization and scope,
then starts or instructs DEIMOS. DEIMOS returns results to ARES, which
forwards them to HERA. HERA updates ZEUS.

DEIMOS must not receive tasks directly from HERA or ZEUS.

If HERA is unavailable, ARES may start DEIMOS only under its cached local
fallback policy and within configured target, rate and duration limits.

## 7. Forensic evidence and retention

Forensic evidence is produced and retained by the sensor that observes the
activity. Sensors preserve their protocol-specific evidence output
independently where their design supports standalone operation. ARES
maintains normalized event and incident references, local retention state
and delivery status. Evidence persistence must not depend on successful IPC
delivery or continuous parent connectivity.

PHOBOS currently writes authentication events to JSONL. A PHOBOS forensic
record must be persisted before PHOBOS announces successful identity capture
to ARES. An IPC failure may delay notification, but must not lose evidence
that PHOBOS has already captured.

Other sensors must apply the same principle to their own protocol-specific
evidence. ARES may retain normalized events, incident references and
delivery state, but the sensor's forensic record remains independently
available according to that sensor's retention design.

FENIX is not a component or service in OLYMP. The earlier FENIX prototype
evolved into PHOBOS; its RDP honeypot functionality is represented by PHOBOS.
General forensic collection and evidence retention are responsibilities of
the sensors and ARES.

## 8. Network architecture

### 8.1 VLAN 18 - control plane

VLAN 18 is the dedicated control and management communication network.
It carries communication between ARES, HERA and ZEUS.

The planned HERA control-plane address convention is `10.x.18.32/24`,
where `x` identifies the site's addressing range. The actual HERA endpoint
is deployment configuration and must be changeable without rebuilding the
ARES image. A newly started ARES uses its configured HERA endpoint to begin
enrollment and establish the control-plane connection.

The control plane is separated from sensor-facing VLANs.
Communication between different sites should use secured routed
connectivity rather than extending one large Layer-2 VLAN between sites.

VLAN membership or source IP alone must never be treated as proof of node
identity or authorization.

### 8.2 Sensor plane

Other VLANs carry traffic to and from honeypot services.

A honeypot host may be connected to multiple VLANs and have multiple
IP addresses.

The host must not route or bridge traffic between sensor VLANs.

Required network protections:

- IPv4 forwarding disabled.
- IPv6 forwarding disabled.
- No bridge connecting sensor VLANs.
- Firewall rules restricting traffic between interfaces.
- Management access restricted to the control plane.
- Explicitly limited outbound communication.

The actual firewall configuration is deployment-specific.

### 8.3 Connection destination

A sensor event must report both:

- Source IP and source port.
- Destination IP and destination port.

HERA uses the destination IP to determine which local VLAN and sensor
were contacted.

ARES must not assume that one honeypot host belongs to only one VLAN.

## 9. Incident and response flow

The intended flow is:

1. A sensor reports a raw event to its local ARES.
2. ARES normalizes and enriches the event, performs local correlation and
   creates or updates a local incident.
3. ARES forwards the incident report to HERA.
4. HERA correlates reports from the site's ARES instances and promptly
   forwards the new incident to ZEUS.
5. HERA decides whether a DEIMOS investigation is appropriate.
6. If approved, HERA sends a task to ARES. ARES validates and delegates it
   to DEIMOS.
7. DEIMOS returns results to ARES; ARES forwards them to HERA.
8. HERA updates the incident and sends the result/update to ZEUS.

The system should distinguish at least these information classes:

- Sensor Event - an observation reported by a sensor.
- Incident Report - a locally correlated incident created or updated by ARES.
- Task/Action Report - an authorized action, its execution state and result.

HERA may also coordinate network infrastructure responses. ARES does not
directly modify router or firewall configuration.

One planned response is to block a source IP from other protected VLANs
while preserving access to the VLAN containing the honeypot that was
contacted. The exact policy, exceptions, duration and implementation are
controlled by HERA.

When several ARES instances report the same source IP, HERA must coordinate
their requests so that one incident does not accidentally remove another
incident's protection.

### Incident identity and lifecycle

Every incident has one immutable, globally unique `incident_id`, initially
created by the ARES that correlates the source events. Forwarding through HERA
and ZEUS must preserve that original identifier and origin identity.

HERA may create a separate site-level correlation identifier
(`site_case_id`) when it correlates multiple ARES incidents. ZEUS may create a
separate global correlation identifier (`global_case_id`) when it correlates
activity across sites. These correlation identifiers supplement rather than
replace the original ARES incident IDs. Correlation must not destroy the
traceability of individual source incidents or sensor events.

Lifecycle and assessment are owned at each hierarchy level:

- ARES owns local evidence collection, local correlation and the local
  assessment of its incident.
- HERA owns the site-level correlation, response decision and state of
  site-level actions, including DEIMOS task coordination.
- ZEUS owns global correlation and the global view/reporting of activity.

A single shared status field must not be overwritten independently by all
three levels. Messages should carry the relevant layer-specific assessment,
revision and timestamps. DEIMOS findings are appended as evidence and linked
to the originating incident and task; they do not replace the original
sensor observations.

Receivers must deduplicate repeated deliveries and preserve update ordering
where required. The exact status enums, transition rules and merge/correlation
policy remain protocol design items to be finalized before implementation.

## 10. Communication model

Events travel upward:

    Sensor -> ARES -> HERA -> ZEUS

Tasks and policies travel downward:

    ZEUS -> HERA -> ARES -> Child

DEIMOS is always addressed through ARES, never directly by HERA or ZEUS.

Local child communication uses the protocol described in
`docs/protocols/IPC.md`. ARES-HERA and HERA-ZEUS use a separate inter-node
control-plane protocol described in `docs/protocols/control-plane.md`.

Inter-node communication is planned to use TLS 1.3 with mutual
certificate authentication (mTLS). Security-sensitive commands and
provenance-sensitive reports are also intended to have application-level
signatures so that origin and integrity can be checked after forwarding.
The message-signature format and cryptographic profile remain to be frozen.

## 11. Identity, trust and enrollment

Every ARES, HERA and ZEUS node must have its own cryptographic identity.
Node identities and private keys must never be shared between cloned VMs.

The target ARES first-boot process is:

- Generate a unique node UUID.
- Generate a private key locally; the private key must not leave the node.
- Verify HERA's server certificate against an OLYMP trust anchor included
  in the trusted base image.
- Submit a certificate signing request and enrollment information to HERA.
- Have HERA authorize the new node and arrange issuance of its individual
  node certificate.
- Establish mTLS and receive the node's site assignment and configuration.

The exact enrollment authorization mechanism (for example, pre-authorized
inventory or a single-use enrollment token) remains an open design decision.
Reachability of HERA or membership in VLAN 18 is not sufficient to authorize
a new node.

The Golden Image must not contain an ARES-specific private key, issued node
certificate, node UUID, reusable enrollment secret or operational history.

## 12. Software distribution and updates

HERA is the local software distribution point for its site.

The planned distribution flow is:

    ZEUS -> approved releases/policies -> HERA repository/cache
    HERA repository -> ARES -> verified child package/update

HERA receives or mirrors approved, signed software releases and exposes a
site-local APT repository or equivalent package source. ARES downloads
packages from HERA, verifies package/repository signatures independently
of the TLS connection, checks compatibility and applies only versions
approved for that site or node.

The update system should support:

- Independent versioning of ARES and each child component.
- A desired-version and installed-version inventory.
- Staged rollout and the ability to pause deployment.
- Retention of a previous known-good version at HERA.
- Health checks after update and a defined rollback procedure.
- Reporting update status and failures to HERA and ZEUS.

Package-signing keys must be separate from node TLS identity keys. HERA's
transport identity must not grant it the ability to create or modify a
valid software package signature.

The repository, package-signing and rollback mechanisms are planned; they
are not implemented in the current ARES baseline.

## 13. Deployment and provisioning

The first deployment target is a single universal Debian Linux Golden Image.
It contains ARES and the supported sensor/worker packages. HERA's assigned
configuration activates the required subset after enrollment. A mixed
combination of RDP, SMB, MSSQL, SSH, FTP, NFS and MySQL services is valid.

The same software can also be delivered later as Debian packages for
installation on an existing Debian host. A custom installer or network
installation workflow may be considered later; it is not required for the
first deployment phase.

The image is generalized before cloning. Machine-specific operating-system
identifiers and SSH host keys are regenerated by each clone. No node
identity, private key, issued certificate, reusable enrollment secret or
incident history may be copied into a new instance.

A newly cloned VM attempts to contact its configured HERA automatically.
If HERA is unavailable, the node retries with backoff and preserves local
operation within its cached policy. Whether a never-enrolled clone may
start exposed sensors before successful enrollment, and which default
profile it may use, remains an open deployment decision.

See `docs/deployment/ares-vm.md` for the provisioning flow.

## 14. Independence and failure handling

Lower levels must remain operational when their parent is unavailable.

- A sensor can operate without ARES where its design supports standalone operation.
- ARES continues local sensor supervision without HERA.
- ARES retains events, incidents and task results for later delivery.
- ARES may use only explicitly bounded local fallback rules for DEIMOS.
- HERA continues local site coordination and serves cached approved packages
  without ZEUS.

A failure of a higher-level component must not automatically stop lower-level
sensors. Reconnection must not cause duplicate incident creation or repeated
execution of a previously completed task.

## 15. Security Onion

Security Onion is not the root of OLYMP.

Individual sensors should remain independently usable and should preserve
their forensic output.

PHOBOS is intended to provide JSONL events usable by Security Onion.

OLYMP may gradually take over honeypot management. This does not imply that
all Security Onion monitoring and analysis capabilities will be replaced.

## 16. Architectural rules

1. OLYMP is a hierarchy, not a flat collection of peer applications.
2. ZEUS is the global root.
3. HERA manages a site and makes site-level DEIMOS decisions.
4. Each honeypot host has one ARES instance.
5. The target ARES VM is one universal Debian Linux image, not separate
   Windows and Linux operating-system images.
6. ARES may enable any supported combination of sensors.
7. ARES manages its own children; DEIMOS is an ARES-managed worker.
8. HERA sends tasks to ARES, never directly to DEIMOS.
9. ARES does not manage network infrastructure.
10. HERA manages local routers and firewalls.
11. VLAN 18 is the control plane, not an identity or authorization mechanism.
12. Inter-node communication must use authenticated and encrypted transport.
13. Cloned nodes must generate unique identities and private keys.
14. HERA is the site-level package distribution point; ARES verifies packages.
15. Sensor VLANs must not be bridged or routed through a honeypot host.
16. Sensors should remain independently usable where designed to do so.
17. Forensic evidence and queued incident reports must not depend on live IPC
    or parent connectivity.
18. Lower levels must continue operating if higher levels fail.
19. Documentation must distinguish implemented, tested and planned behavior.
