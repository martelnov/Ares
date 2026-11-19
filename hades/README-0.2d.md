# HADES 0.2d – local-only SQL LOGIN7 + forensic JSONL

**Not for production networks.** This milestone adds an experimental network
LOGIN7 path after TDS 7.x TLS and returns a TDS 18456 login-failure response.
SQL Authentication never succeeds; no database access is implemented.

Every parsed LOGIN7 is written to JSONL **before** the client receives the
failure response. SQL Authentication passwords are decoded and present in the
JSONL in plaintext. For integrated security, the opaque SSPI token is included
as `authentication.sspi_base64`, not decoded as a password. Events include a
UUID and UTC `@timestamp`, suitable for an Elastic Agent file input.

## Local test

Use a dedicated throwaway self-signed certificate. Do not reuse OLYMP mTLS
control-plane keys. All test credentials must be fictitious.

```sh
umask 077
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/hades-test.key -out /tmp/hades-test.crt -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
cd hades
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
HADES_TLS_CERT=/tmp/hades-test.crt HADES_TLS_KEY=/tmp/hades-test.key \
  HADES_FORENSIC_JSONL=/tmp/hades-evidence.jsonl cargo run
```

From a second terminal:

```sh
cd hades
python3 tools/login7_smoke.py /tmp/hades-test.crt /tmp/hades-evidence.jsonl
```

The smoke test uses only `local_fake_user` and `FakeTestOnly!123` and validates
that the server returned error 18456 and persisted those exact test values.

## Current safety requirements and limitations

- The listener is hard-restricted to `127.0.0.1` / `::1` and port 11433 by
  default. Do not change the loopback-only check for this milestone.
- TLS certificate and key **and** `HADES_FORENSIC_JSONL` must be configured
  together. If evidence cannot be opened with restricted permissions (0600),
  startup fails. If writing/syncing fails, the client gets no successful reply.
- JSONL contains cleartext SQL passwords / raw SSPI and is sensitive. Elastic
  Agent may ingest this file into Security Onion ONLY with appropriately
  protected transport, index access and retention. No console password output.
- TDS 7.x TLS path only; TLS-first TDS 8.0 not implemented. Error 18456 packet
  encoded for TDS 7.2+. Earlier versions are not compatibility-tested.
- This milestone remains single-threaded and single-connection-at-a-time,
  without robust load shedding, per-session incident correlation or ARES IPC.
- No malformed LOGIN7 forensics yet. Raw authentication material is not stored
  for invalid packets; later milestones must add bounded parse-failure events.
- Test the implementation with real MSSQL client libraries before deployment.
- A JSONL file is not a substitute for encrypted disks, a least-privileged
  account, controlled backup/rotation, and monitoring of evidence retention.
