# OLYMP

OLYMP is a distributed, hierarchical security and honeypot ecosystem.

The project coordinates specialized honeypot services, local supervision,
forensic collection, investigation and defensive responses.

## Architecture

OLYMP uses a hierarchy:

- ZEUS - global coordination across sites.
- HERA - coordination and policy decisions for one site.
- ARES - local controller for one honeypot host.
- ARES children - protocol sensors and task workers.

See [OLYMP Architecture](docs/architecture/OLYMP.md).

## Deployment model

The target deployment is one universal Debian Linux ARES host image.
The image contains ARES and the supported sensor/worker packages. HERA's
configuration determines which sensors are enabled on a particular host.
There are not separate Windows and Linux ARES operating-system images.
RDP, SMB and MSSQL are Windows-oriented honeypot services running on the
Linux host; SSH, FTP, NFS and MySQL are additional supported service types.

See [ARES VM Provisioning](docs/deployment/ares-vm.md).

## Components

### Sensors

- PHOBOS - RDP honeypot.
- ATHENA - SMB honeypot and decoy file shares.
- HADES - MSSQL honeypot.
- SSH - SSH honeypot.
- FTP - FTP honeypot.
- NFS - NFS honeypot.
- MySQL - MySQL honeypot.

A particular ARES instance may enable any supported combination of sensors.

### Worker

- DEIMOS - active reconnaissance worker managed by ARES.

HERA decides whether a DEIMOS task should be assigned when HERA is available.
ARES validates and executes the task through its local DEIMOS child. ARES
may use a bounded local fallback policy while HERA is unavailable.

## Current implementation

PHOBOS is the first operational sensor.

ARES currently provides initial process supervision and IPC integration
with PHOBOS. The universal VM, provisioning, inter-node security,
incident workflow, HERA/ZEUS communication and software distribution are
planned, not implemented.

See [Implementation Status](docs/status/implementation-status.md).

## Security Onion integration

Individual sensors are intended to remain independently usable and preserve
their forensic output.

PHOBOS maintains forensic JSONL output and is intended to support integration
with Security Onion. OLYMP may gradually take over honeypot management while
Security Onion continues to provide broader security monitoring and analysis.

## Documentation

- [Architecture](docs/architecture/OLYMP.md)
- [Local child IPC protocol](docs/protocols/IPC.md)
- [Inter-node control plane](docs/protocols/control-plane.md)
- [ARES VM provisioning](docs/deployment/ares-vm.md)
- [Implementation Status](docs/status/implementation-status.md)

## Project status

OLYMP is under active development.

Architecture, deployment design and implementation status are documented
separately. Planned functionality must not be interpreted as implemented
functionality.
