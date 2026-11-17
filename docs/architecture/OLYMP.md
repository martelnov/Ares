# OLYMP Architecture

Version: 1.0
Status: Architecture baseline
Date: 2026-11-17

## 1. Purpose

OLYMP is a distributed security and honeypot ecosystem.

Its purpose is to provide specialized honeypot services, local supervision,
forensic collection, investigation and coordinated defensive responses.

The system is intended to reduce dependence on Security Onion for
honeypot management.

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
      +-------------------+
      |                   |
    ARES-WINDOWS        ARES-LINUX
      |                   |
      +-- PHOBOS           +-- FTP
      +-- ATHENA           +-- NFS
      +-- HADES            +-- SSH
      +-- DEIMOS           +-- MySQL
                           +-- DEIMOS

The diagram is conceptual. The actual number of sites, ARES instances
and children is configuration-dependent.

## 3. ZEUS - global root

ZEUS is responsible for global coordination.

Planned responsibilities:

- Global view of all sites.
- Correlation of incidents across sites.
- Central incident history and reporting.
- Distribution of security policies.
- Coordination of HERAs.
- Global operational status.

ZEUS does not directly manage individual honeypot processes.

## 4. HERA - site-level coordination

HERA manages one site.

Responsibilities:

- Coordination of all ARES instances at the site.
- Knowledge of local network topology.
- Knowledge of VLANs, subnets and network devices.
- Coordination of local defensive actions.
- Communication with Cisco and MikroTik infrastructure.
- Forwarding relevant information to ZEUS.
- Receiving policies and instructions from ZEUS.

HERA is responsible for network infrastructure actions.

ARES must not directly manage routers or firewalls.

## 5. ARES - local honeypot controller

One ARES instance runs on each honeypot host.

A host may be physical or virtual.

Windows and Linux honeypots are separate hosts and each has its own ARES.

A honeypot host may have several network interfaces, IP addresses
and connections to multiple VLANs.

ARES responsibilities:

- Start and supervise local child processes.
- Receive events from children.
- Monitor child health and heartbeat.
- Restart failed or intentionally terminated sensors.
- Maintain local incident state.
- Receive tasks from HERA.
- Validate task parameters and scope.
- Delegate tasks to appropriate workers.
- Collect worker results.
- Forward events and results to HERA.
- Continue local operation when HERA is unavailable.

ARES does not need global site topology and does not directly control
network routers or firewalls.

## 6. Children of ARES

Children are independent processes.

They communicate with their parent ARES through local IPC when managed
by ARES. A sensor may also operate independently if its design supports
standalone operation.

### 6.1 Sensors

Sensors are long-running processes.

Windows honeypot:

- PHOBOS - RDP.
- ATHENA - SMB and decoy file shares.
- HADES - MSSQL.

Linux honeypot:

- FTP - FTP service.
- NFS - NFS service.
- SSH - SSH service.
- MySQL - database service.

Sensors report events, connections, authentication attempts and other
protocol-specific activity.

### 6.2 DEIMOS

DEIMOS is a worker subordinate to ARES.

It is not a separate hierarchy level.

HERA sends a task to ARES. ARES validates the task and starts or
instructs DEIMOS. DEIMOS returns results to ARES, which forwards them
to HERA.

DEIMOS must not receive tasks directly from HERA or ZEUS.

## 7. FENIX - forensic evidence

FENIX represents the forensic collection and evidence function.

The current PHOBOS implementation writes authentication events to JSONL.

The forensic record must be persisted before PHOBOS announces successful
identity capture to ARES.

Forensic evidence must not depend on IPC availability.

FENIX is not currently defined as a separate process.

## 8. Network architecture

### 8.1 VLAN 18 - control plane

VLAN 18 is the dedicated control and management communication network.

It carries communication between:

- ARES
- HERA
- ZEUS

The control plane is separated from the sensor-facing VLANs.

Communication between different sites should use secured routed
connectivity rather than extending one large Layer-2 VLAN between sites.

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

## 9. Defensive response

ARES reports security events to HERA.

HERA evaluates local topology and security policy and may coordinate
actions on Cisco or MikroTik devices.

One planned response is to block a source IP from other protected VLANs
while preserving access to the VLAN containing the honeypot that was
contacted.

The exact policy, exceptions, duration and implementation are controlled
by HERA.

ARES does not directly modify router or firewall configuration.

When several ARES instances report the same source IP, HERA must
coordinate their requests so that one incident does not accidentally
remove another incident's protection.

## 10. Communication model

Events travel upward:

    Sensor -> ARES -> HERA -> ZEUS

Tasks and policies travel downward:

    ZEUS -> HERA -> ARES -> Child

Local child communication uses IPC.

ARES-HERA and HERA-ZEUS communication uses the control plane on VLAN 18.

The inter-node protocol is planned to use authenticated and encrypted
communication, preferably mutual TLS.

## 11. Independence and failure handling

Lower levels must remain operational when their parent is unavailable.

- PHOBOS can operate without ARES.
- ARES continues local sensor supervision without HERA.
- HERA continues local site coordination without ZEUS.

Events that cannot be forwarded must be retained locally for later
delivery where required.

A failure of a higher-level component must not automatically stop
lower-level sensors.

## 12. Security Onion

Security Onion is not the root of OLYMP.

Individual sensors should remain independently usable and should
preserve their forensic output.

PHOBOS is intended to provide JSONL events usable by Security Onion.

OLYMP may gradually take over honeypot management. This does not imply
that all Security Onion monitoring and analysis capabilities will be
replaced.

## 13. Architectural rules

1. OLYMP is a hierarchy, not a flat collection of peer applications.
2. ZEUS is the global root.
3. HERA manages a site.
4. Each honeypot host has its own ARES.
5. ARES manages its own children.
6. DEIMOS is a worker managed by ARES.
7. ARES does not manage network infrastructure.
8. HERA manages local routers and firewalls.
9. VLAN 18 is the control plane.
10. Sensor VLANs must not be bridged or routed through a honeypot host.
11. Sensors should remain independently usable where designed to do so.
12. Forensic evidence must not depend on IPC delivery.
13. Lower levels must continue operating if higher levels fail.
