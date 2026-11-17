# OLYMP

OLYMP is a distributed, hierarchical security and honeypot ecosystem.

The project is designed to operate and coordinate independent honeypot
systems, collect forensic events, investigate suspicious activity and
coordinate defensive responses.

## Architecture

OLYMP uses a hierarchical architecture:

- ZEUS - global root and coordination.
- HERA - site-level coordination.
- ARES - local controller for one honeypot host.
- Children - specialized sensors and workers.

See [OLYMP Architecture](docs/architecture/OLYMP.md).

## Components

### Windows honeypot

- PHOBOS - RDP honeypot.
- ATHENA - SMB honeypot and decoy file server.
- HADES - MSSQL honeypot.

### Linux honeypot

- FTP - FTP honeypot.
- NFS - NFS honeypot.
- SSH - SSH honeypot.
- MySQL - MySQL honeypot.

### Worker

- DEIMOS - active reconnaissance worker managed by ARES.

## Current implementation

PHOBOS is the first operational sensor.

ARES currently provides initial process supervision and IPC integration
with PHOBOS.

See [Implementation Status](docs/status/implementation-status.md).

## Security Onion integration

Individual sensors are intended to remain independently usable.

PHOBOS maintains its forensic JSONL output and is intended to support
integration with Security Onion.

OLYMP may gradually take over honeypot management while Security Onion
continues to provide broader security monitoring and analysis.

## Documentation

- [Architecture](docs/architecture/OLYMP.md)
- [IPC Protocol](docs/protocols/IPC.md)
- [Implementation Status](docs/status/implementation-status.md)

## Project status

OLYMP is under active development.

Architecture and implementation status are documented separately.
Planned functionality must not be interpreted as implemented functionality.
