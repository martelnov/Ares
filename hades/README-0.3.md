# HADES 0.3 - TCP CONNECT as first-class forensic evidence

**Experimental, loopback-only. Not ready for deployment in a real network.**

HADES now persists a `tcp_connect` event immediately after `accept()`, **before**
reading PRELOGIN, negotiating TLS, or receiving credentials. A completed TCP
connection to a dedicated decoy is treated as CRITICAL. SYN-only scans do not
reach `accept()` and are not covered by this sensor; use network telemetry for
that. Authorized health checks will also create events until filtered upstream.

Both the CONNECT record and any later SQL authentication attempt have unique
`event.id` fields and share the same `session.id`. Each record contains the
source and destination IP/port and `@timestamp`. LOGIN7 evidence still contains
captured SQL passwords or raw SSPI, and must be protected accordingly.

The file is `sync_data()`-ed **before** HADES sends a PRELOGIN response or
continues with the protocol. If the JSONL sink cannot be opened at startup,
HADES refuses to listen. If a CONNECT event cannot be durably written, the
server stops serving connections rather than operate without evidence. ARES
IPC, Security Onion ingestion, concurrency, and production hardening are not
implemented here. There is **no SQL engine** and authentication always fails.

## Test on AILAB (local-only)

Create an isolated evidence file using a private directory. Use the existing
throwaway TLS certificate and key from 0.2d; never use live credentials.

```sh
cd hades
cargo fmt
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
umask 077
HADES_TLS_CERT=/tmp/hades-test.crt \
HADES_TLS_KEY=/tmp/hades-test.key \
HADES_FORENSIC_JSONL=/tmp/hades-connect-03.jsonl cargo run
```

In another terminal:

```sh
cd hades
python3 tools/connect_smoke.py /tmp/hades-connect-03.jsonl
python3 tools/login7_smoke.py /tmp/hades-test.crt /tmp/hades-connect-03.jsonl
```

Expected: `connect_smoke` finds exactly one CRITICAL `tcp_connect` record
**while TCP is still open and without sending PRELOGIN**; `login7_smoke` finds
both the CONNECT and authentication events with the same `session.id`, verifies
the fake password, and observes SQL error 18456. The server writes no passwords
to stderr.

`HADES_FORENSIC_JSONL` is **now mandatory even without TLS** (the PRELOGIN-only
path). Existing `tls_smoke.py` and `prelogin_smoke.py` also require the variable
when launching the server, so that no connection is silently ignored.

## Deliberately excluded from 0.3

- Direct ARES IPC and HERA/ZEUS communication: JSONL is the sole durable feed.
- Concurrent client handling and cancellation: current listener is sequential.
- Logging malformed PRELOGIN/LOGIN7 details: only TCP CONNECT is guaranteed.
- Real MSSQL client interoperability, TDS 8.0 TLS-first, and public interfaces.
- Filtering known legitimate monitoring sources or deduplicating incidents.

Keep PHOBOS and ARES untouched. Log retention, access-control, secure
transport to Security Onion, and disk-full alarms are operational prerequisites
before any real deployment.
