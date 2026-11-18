# HADES 0.2c - TDS 7.x TLS handshake (local test only)

This patch adds a **real rustls TLS 1.2/1.3 server handshake** with TDS 7.x
PRELOGIN (0x12) encapsulation. The server retains the old non-TLS PRELOGIN
smoke-test path if no certificate/key is configured. If a test cert/key pair
is provided, it advertises `ENCRYPT_REQ`, performs TLS, then **closes** the
connection without reading LOGIN7 or recording credentials.

The new TLS transport is reusable: a future forensic-safe authentication
handler can use the returned `StreamOwned<ServerConnection, TcpStream>` to
read encrypted LOGIN7 via `tds::packet::read_login7`.

## Test TLS locally

The following is for a throwaway localhost test certificate, not OLYMP
control-plane identity keys. Set restrictive permissions on the key.

```bash
umask 077
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/hades-test.key -out /tmp/hades-test.crt \
    -days 1 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
cd hades
cargo fmt
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
HADES_TLS_CERT=/tmp/hades-test.crt HADES_TLS_KEY=/tmp/hades-test.key cargo run
```

In another terminal:

```bash
cd hades
python3 tools/tls_smoke.py /tmp/hades-test.crt
```

`tools/prelogin_smoke.py` remains useful only in the legacy non-TLS mode.
The TLS smoke script verifies a server PRELOGIN with `ENCRYPT_REQ`, performs a
certificate-verified TLS handshake through TDS frames, and sends **no**
credentials. The TCP server only listens on loopback in this version.

## Limitations / not production ready

- No LOGIN7 is read by the network listener; SQL passwords are not captured.
- No forensic JSONL, persistent evidence, login-failure TDS response, IPC,
  concurrent connection handling, or resource-hardening beyond basic bounds.
- TDS 8.0 TLS-first is not supported.
- Test private keys must not be reused in an OLYMP deployment.
- New dependencies: `rustls 0.23` with ring crypto and `rustls-pemfile 2.x`.
- Regenerate and commit Cargo.lock after Cargo resolves dependencies.
- Rust handshake packets are wrapped in TDS PRELOGIN only during negotiation;
  subsequent application packets are carried within the established TLS
  connection. Future code must validate this against actual MSSQL clients.

References: [MS-TDS PRELOGIN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868)
and [MS-TDS TLS negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/09e5bc81-690b-4a9e-942a-24067e87bd9e).
