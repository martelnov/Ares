//! HADES experimental TDS transport and PRELOGIN parser.
//! Experimental TDS 7.x TLS handshake and local-only LOGIN7 evidence capture.

pub mod tds;

/// TDS 7.x PRELOGIN-framed TLS handshake (test-stage only).
pub mod tls;

/// Protected JSONL forensic sink (SQL Authentication and SSPI evidence).
pub mod forensic;
