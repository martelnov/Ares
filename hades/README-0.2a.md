# HADES 0.2a - offline LOGIN7 parser (development stage)

The standalone PRELOGIN listener **remains unchanged**: it still binds to
`127.0.0.1:11433`, advertises `ENCRYPT_NOT_SUP`, and closes after responding.
It does not accept login attempts or store credentials yet.

This stage adds an independently testable, bounded LOGIN7 parser. The parser
checks message length, field offsets and overlap, UTF-16LE encoding, SSPI fields,
and SQL-password's reversible LOGIN7 wire obfuscation. Password/SSPI fields are
redacted from `Debug` output and cannot be accidentally printed that way.

It intentionally rejects extended SSPI and feature extensions until these are
implemented safely. It is a parser milestone **not a usable MSSQL honeypot**.

## Test

```bash
cd hades
cargo fmt
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

The live service is unchanged. Production requirements still include TDS 7.x
PRELOGIN-encapsulated TLS, TDS 8.0 TLS-first, protected evidence persistence,
standard LOGIN7 failure response, JSONL and optional ARES IPC.

Never expose this intermediate prototype to an attacker-facing network.

## References

- MS-TDS LOGIN7: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac
- MS-TDS TLS/SSL Negotiation: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/09e5bc81-690b-4a9e-942a-24067e87bd9e
