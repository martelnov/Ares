//! TDS 7.x TLS handshake transport. Strictly local test-stage code.
//!
//! TDS 7.x wraps handshake TLS records in PRELOGIN (0x12) frames. Once
//! negotiation succeeds, the application TDS messages travel over the
//! established TLS stream (not in PRELOGIN headers).
//!
//! This module does NOT parse or record SQL credentials, nor grant access.
use crate::tds::packet::{read_tls_handshake_packet, wrap_tls_handshake_bytes};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::fs::File;
use std::io::{self, BufReader, Cursor, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

const MAX_HANDSHAKE_MESSAGES: usize = 32;
const MAX_HANDSHAKE_BYTES: usize = 512 * 1024;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Load a dedicated local test certificate/key pair, requiring TLS 1.2/1.3.
/// Do not reuse the real OLYMP mTLS node-identity private key.
pub fn config_from_pem(cert_path: &Path, key_path: &Path) -> io::Result<Arc<ServerConfig>> {
    let mut cert_file = BufReader::new(File::open(cert_path)?);
    let certificates = rustls_pemfile::certs(&mut cert_file).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(invalid("TLS certificate chain is empty"));
    }

    let mut key_file = BufReader::new(File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_file)?
        .ok_or_else(|| invalid("TLS private key not found"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("no supported TLS protocol versions"))?;
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| invalid("TLS certificate/private key mismatch or invalid key"))?;
    // Avoid post-handshake NewSessionTicket messages during TDS framing.
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

/// Perform TDS 7.x PRELOGIN-encapsulated TLS handshake over an existing TCP
/// socket. Caller must first send PRELOGIN response advertising ENCRYPT_REQ.
///
/// TCP read/write timeouts must be configured by the caller. Returns a normal
/// rustls stream that can later be used for fully encrypted LOGIN7 packets.
/// Currently callers must *not* process credentials: a safe evidence sink is
/// still missing. TDS 8.0 TLS-first is explicitly out of scope.
pub fn negotiate_tds7_tls(
    mut tcp: TcpStream,
    config: Arc<ServerConfig>,
) -> io::Result<StreamOwned<ServerConnection, TcpStream>> {
    let mut tls =
        ServerConnection::new(config).map_err(|_| invalid("failed to initialize TLS server"))?;
    let mut total_bytes = 0usize;

    for _ in 0..MAX_HANDSHAKE_MESSAGES {
        flush_handshake(&mut tcp, &mut tls, &mut total_bytes)?;
        if !tls.is_handshaking() {
            return Ok(StreamOwned::new(tls, tcp));
        }

        let incoming = read_tls_handshake_packet(&mut tcp)?;
        total_bytes = total_bytes.saturating_add(incoming.len());
        if total_bytes > MAX_HANDSHAKE_BYTES {
            return Err(invalid("TDS/TLS handshake byte limit exceeded"));
        }
        let mut cursor = Cursor::new(incoming.as_slice());
        while (cursor.position() as usize) < incoming.len() {
            let count = tls.read_tls(&mut cursor)?;
            if count == 0 {
                return Err(invalid("premature end of TLS input"));
            }
            tls.process_new_packets()
                .map_err(|_| invalid("TLS handshake rejected"))?;
        }
    }

    Err(invalid("TDS/TLS handshake message limit exceeded"))
}

fn flush_handshake(
    tcp: &mut TcpStream,
    tls: &mut ServerConnection,
    total_bytes: &mut usize,
) -> io::Result<()> {
    let mut outgoing = Vec::new();
    while tls.wants_write() {
        let count = tls.write_tls(&mut outgoing)?;
        if count == 0 {
            return Err(invalid("TLS handshake stalled during write"));
        }
        if total_bytes.saturating_add(outgoing.len()) > MAX_HANDSHAKE_BYTES {
            return Err(invalid("TDS/TLS handshake byte limit exceeded"));
        }
    }
    if !outgoing.is_empty() {
        *total_bytes += outgoing.len();
        tcp.write_all(&wrap_tls_handshake_bytes(&outgoing)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_certificate_is_rejected() {
        let result = config_from_pem(
            Path::new("/invalid/nonexistent/hades-cert.pem"),
            Path::new("/invalid/nonexistent/hades-key.pem"),
        );
        assert!(result.is_err());
    }
}
