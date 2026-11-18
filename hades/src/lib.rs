//! HADES experimental TDS transport and PRELOGIN parser.
//! Experimental TDS 7.x TLS handshake support, but no credential capture.

pub mod tds;

/// TDS 7.x PRELOGIN-framed TLS handshake (test-stage only).
pub mod tls;
