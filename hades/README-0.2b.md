# HADES 0.2b — bounded TDS transport primitives

This incremental patch is deliberately **not yet a credential-capturing network
service**. It adds packet-level pieces needed before wiring up TLS and LOGIN7.

- `read_prelogin` remains compatible with the existing localhost smoke test.
- `read_login7` assembles bounded, segmented LOGIN7 messages. It must be
  called **only on a decrypted TLS stream after handshake**; this patch does not
  call it from `main.rs`.
- `read_tls_handshake_packet` and `wrap_tls_handshake_bytes` handle TDS 7.x
  PRELOGIN framing around TLS handshake bytes. They are framing helpers,
  **not an implementation of TLS**.
- Tests cover fragmentation, wrong packet type, truncation, oversized LOGIN7,
  handshake framing and empty TLS payloads.

## Current limits

- TDS packet: 32 KiB
- TDS PRELOGIN / framed TLS handshake data: 64 KiB
- LOGIN7 payload: 131071 bytes (bound from parser)
- No password is accepted or persisted from the network at this stage.
- No successful authentication, no access permissions and no SQL execution.
- Binds to localhost 127.0.0.1:11433 by default.

## Next steps

1. Add rustls server TLS 1.2/1.3 and handshake state for TDS 7.x; ensure
   PRELOGIN requests for encryption are handled accurately. TDS 8.0 (TLS
   before PRELOGIN) is a separate compatibility step.
2. Wire LOGIN7 parsing only after a successful TLS handshake, with an
   authenticated test client and a deliberately fake account.
3. Durable JSONL forensic events, including actual SQL Authentication
   passwords when provided, forwarded to authorized Security Onion ingestion.
   Protect files, transport and index access; no console logging of secrets.
4. Always reject login with a standard TDS error; do not forward credentials
   or perform actual authentication against another host.

Reference: Microsoft MS-TDS sections 2.2.6.5 and 3.3.5.2.
