# ARES VM Provisioning and Software Distribution

Version: 0.1
Status: Planned deployment design - not implemented
Date: 2026-11-17

## 1. Purpose

This document describes the target first-phase deployment model for ARES,
including the universal VM image, first-boot enrollment, configuration and
future software updates.

The first phase uses cloning of a prepared virtual machine. A Debian package
installation workflow for existing Linux hosts may be added later.

## 2. One universal Debian Linux image

The target is one universal Debian Linux Golden Image. Separate Windows
and Linux ARES operating-system images are not required.

The image contains:

- Debian Linux and required runtime dependencies;
- ARES;
- supported sensor packages;
- DEIMOS and its required tools;
- first-boot provisioning service;
- OLYMP public trust anchor(s);
- baseline local configuration and service definitions.

Supported sensor packages include:

- PHOBOS - RDP;
- ATHENA - SMB;
- HADES - MSSQL;
- SSH;
- FTP;
- NFS;
- MySQL.

The image may contain all supported packages, but a particular ARES instance
runs only the components enabled by its assigned configuration. Mixed sensor
profiles are valid.

For every child component, ARES reports three distinct states:

- `installed` - package or executable is present;
- `enabled` - configuration permits the component to run;
- `running` - process is currently active.

DEIMOS is installed but is not a continuously running sensor. It is started
for a validated task from HERA, or under a bounded local fallback policy
when HERA is unavailable.

## 3. Golden Image preparation and clone hygiene

The Golden Image must be prepared before it is enrolled as an OLYMP node.
It must not contain:

- an ARES node UUID or site-specific parent assignment;
- an ARES private key or issued node certificate;
- a reusable enrollment token or other node-specific secret;
- incident history, task history or queued operational data;
- site-specific sensor configuration;
- a previously registered SSH host key or other machine-specific identity.

Before sealing the image, the build process must generalize the operating
system. Each clone must generate its own machine identity and SSH host keys
and must receive its own network configuration. The exact image-building
and generalization tooling is a deployment choice.

A clone must never inherit the identity of the VM from which it was made.
If an already enrolled ARES must be cloned, its identity must first be
retired and the clone must go through fresh enrollment with a new key pair.

## 4. First-boot provisioning flow

The planned first-boot sequence is:

1. Debian boots and starts the ARES provisioning service.
2. The service waits for the control-plane interface and required network
   configuration to become available.
3. ARES generates a unique node UUID.
4. ARES generates a private key locally. The private key never leaves the VM.
5. ARES connects to its configured HERA endpoint on VLAN 18. The endpoint
   is supplied by the per-instance provisioning input described below and is
   not a hard-coded build-time constant.
6. ARES verifies HERA's server certificate using the OLYMP public trust
   anchor included in the Golden Image.
7. ARES submits a certificate signing request and enrollment information.
8. HERA authorizes the new node using the selected enrollment mechanism and
   arranges issuance of an individual ARES certificate.
9. ARES establishes mTLS and receives its site assignment, parent identity,
   sensor configuration, policy and approved component versions.
10. ARES validates the configuration and starts only enabled sensors.
11. ARES reports node/component status and begins normal operation.

### Bootstrap data and authoritative site assignment

The universal Golden Image contains no site-specific HERA address or site
assignment. The HERA endpoint is configurable and is supplied to each
deployment through a per-VM provisioning input.

Candidate mechanisms include hypervisor guest metadata, a cloud-init data
source or a per-VM configuration/seed medium. The mechanism has not yet
been selected, but it must not require rebuilding the Golden Image for each
site.

The provisioning input may include a site hint or deployment label to help
HERA identify the intended registration record. HERA is authoritative for
the final `site_id` and `parent_id`; ARES must accept those assignments only
after HERA has been authenticated and the enrollment has been authorized.
A site hint, IP address, VLAN membership or successful connection alone
does not establish trust or grant site membership.

The planned address convention is `10.x.18.32/24`, with `x` identifying the
site addressing range. The concrete HERA endpoint, including any required
port, is deployment configuration. It must be possible to change it without
rebuilding the image.


The exact enrollment authorization mechanism is not yet selected. Candidate
options are a pre-authorized node inventory, a short-lived single-use token
or explicit approval in HERA. A connection from VLAN 18 alone must not
authorize enrollment.

## 5. HERA unavailable during first boot

A newly cloned, not-yet-enrolled VM may be unable to obtain its site
configuration while HERA is unavailable. The provisioning service must
retry with backoff and must not bypass HERA identity verification.

The policy for a never-enrolled clone is still open:

- whether it may start any sensor before enrollment;
- whether it must remain in a non-listening quarantine state;
- whether a minimal local profile may be used;
- which local actions, if any, are permitted before registration.

For an already enrolled ARES, loss of HERA must not stop running sensors.
The node retains local events/incidents/results and follows its cached
policy, including only explicitly bounded autonomous DEIMOS behavior.

## 6. Configuration and sensor activation

HERA assigns a configuration to each ARES. The configuration may enable
any supported combination of sensors and may later be updated without
reinstalling the VM.

The configuration model must distinguish:

- package availability (`installed`);
- desired service state (`enabled` or disabled);
- observed process state (`running`, stopped or failed).

A configuration update must be validated before application. ARES reports
the desired and observed state to HERA so that HERA can detect drift or a
failed child process.

## 7. Software distribution and updates

HERA is the local software distribution point for its site.

The planned release flow is:

    ZEUS approves/releases package
            |
            v
    HERA downloads or mirrors signed package and metadata
            |
            v
    HERA site-local APT repository/cache
            |
            v
    ARES downloads and verifies package
            |
            v
    ARES updates the selected child component

ARES must verify signed repository metadata and package signatures. It must
not rely solely on mTLS or on the fact that a package came from HERA.
Package-signing keys are separate from ARES/HERA/ZEUS node identity keys.

The update design should provide:

- independent versions for ARES and each child;
- compatibility metadata and dependency checks;
- desired and installed version reporting;
- staged rollout and pause controls;
- retention of a previous known-good version at HERA;
- post-update health checks;
- a documented rollback procedure;
- update result reporting to HERA and ZEUS.

The detailed update policy, including whether ARES self-updates through the
same mechanism, remains to be specified.

## 8. Later installation option

A Debian package (`.deb`) or APT repository may later support installation
on an existing Debian Linux physical or virtual host. This is a secondary
path and does not replace the first-phase Golden Image approach.

A custom Debian installer ISO or PXE/network installation may be considered
in a later phase if fully automated OS deployment becomes necessary.

## 9. Implementation status

The universal Golden Image, first-boot provisioning, node enrollment,
configuration retrieval, HERA package repository and update/rollback flow
are planned. They are not implemented in the current ARES baseline.
