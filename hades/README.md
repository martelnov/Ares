> **Development note (0.2d):** This README describes the original PRELOGIN
> prototype. LOGIN7 parsing, TDS framing, TLS, and local-only forensic SQL
> authentication capture are described in [README-0.2a.md](README-0.2a.md),
> [README-0.2b.md](README-0.2b.md), [README-0.2c.md](README-0.2c.md), and
> [README-0.2d.md](README-0.2d.md). No login is ever accepted.

# HADES 0.1 - PRELOGIN protocol prototype

This is the first, **deliberately incomplete** milestone for OLYMP HADES,
a standalone Rust MS SQL Server / TDS authentication honeypot.

## Current status

**Implemented:** bounded TDS packet framing, assembly of PRELOGIN messages,
validated PRELOGIN option-table parser, a minimal server PRELOGIN response,
and unit/integration tests based in part on Microsoft's published example.

**NOT implemented:** TLS handshake, TDS 8.0 TLS-first negotiation, LOGIN7,
SQL authentication, passwords, forensic evidence, JSONL logging, ARES IPC,
concurrent connections, resource hardening, or a production-ready listener.
Do not expose this prototype on a public or attacker-facing network.

The prototype advertises `ENCRYPT_NOT_SUP` because it cannot perform TLS.
It then closes the connection and **never accepts a LOGIN7 or credentials**.
Current clients often require TLS; failure to complete a real SQL connection
at this stage is expected. The visible banner is intentionally minimal.

## Build and test (on a machine with Rust installed)

```bash
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
```

The project deliberately uses no third-party crates yet.

## Manual local-only smoke test

```bash
cargo run
# Defaults to 127.0.0.1:11433, not TCP 1433.
```

To override the test bind address set `HADES_BIND` explicitly. Do not bind to
non-loopback interfaces until the missing security controls are implemented.

## Next milestones

1. Define strict connection state machine and bounded concurrent handling.
2. Implement TDS 7.x TLS wrapped in PRELOGIN and TLS-first TDS 8.0 behavior.
3. Add robust LOGIN7 parsing, SQL Authentication capture and login rejection.
4. Persist sensitive credentials securely, separate metadata-only JSONL feed.
5. Make ARES IPC optional; preserve standalone systemd operation.
6. Validate with real SQL clients, malformed input tests and fuzzing.

The SQL server persona (hostname, instance name, product version, certificates)
will eventually be supplied by ARES or standalone configuration, never silently
chosen by this prototype for production use.

## Protocol references

- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9420b4a3-eb9f-4f5e-90bd-3160444aa5a7

In a second terminal (while `cargo run` is listening):

```bash
python3 tools/prelogin_smoke.py
```

The smoke test sends only a Microsoft example PRELOGIN frame; no username or
password is sent.
