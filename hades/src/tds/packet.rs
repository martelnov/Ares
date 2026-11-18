//! TDS 8-byte packet framing, bounded reads, and message assembly.
use std::io::{self, Read};

pub const PRELOGIN_TYPE: u8 = 0x12;
pub const LOGIN7_TYPE: u8 = 0x10;
pub const RESPONSE_TYPE: u8 = 0x04;
const HEADER_LEN: usize = 8;
const MAX_PACKET_LEN: usize = 32 * 1024;
const MAX_PRELOGIN_LEN: usize = 64 * 1024;
const MAX_LOGIN_PACKETS: usize = 64;
const MAX_PRELOGIN_PACKETS: usize = 16;
const EOM: u8 = 0x01;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Read one bounded TDS message, potentially split across multiple packets.
/// The TDS packet type is checked on *every* segment, not just the first.
fn read_message<R: Read>(
    stream: &mut R,
    expected_type: u8,
    max_message_len: usize,
    max_packets: usize,
) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    for _ in 0..max_packets {
        let mut hdr = [0u8; HEADER_LEN];
        stream.read_exact(&mut hdr)?;
        if hdr[0] != expected_type {
            return Err(invalid("unexpected TDS packet type"));
        }
        let total = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
        if !(HEADER_LEN..=MAX_PACKET_LEN).contains(&total) {
            return Err(invalid("invalid TDS packet length"));
        }
        let body_len = total - HEADER_LEN;
        if payload.len().saturating_add(body_len) > max_message_len {
            return Err(invalid("TDS message exceeds configured bound"));
        }
        let previous = payload.len();
        payload.resize(previous + body_len, 0);
        stream.read_exact(&mut payload[previous..])?;
        if hdr[1] & EOM != 0 {
            if payload.is_empty() {
                return Err(invalid("empty TDS message"));
            }
            return Ok(payload);
        }
    }
    Err(invalid("too many packets in TDS message"))
}

/// Read the initial unencrypted TDS PRELOGIN message.
pub fn read_prelogin<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    read_message(
        stream,
        PRELOGIN_TYPE,
        MAX_PRELOGIN_LEN,
        MAX_PRELOGIN_PACKETS,
    )
}

/// Read one TDS 7.x LOGIN7 message from an *already decrypted* TLS stream.
/// IMPORTANT: Do not call on the bare TCP socket to accept credentials.
/// This function has no side effects or credential logging.
pub fn read_login7<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    read_message(
        stream,
        LOGIN7_TYPE,
        crate::tds::login7::MAX_LOGIN7_LEN,
        MAX_LOGIN_PACKETS,
    )
}

/// Read one TDS PRELOGIN-framed TLS handshake payload (TDS 7.x).
/// This is framing only; rustls must authenticate/decrypt the TLS records.
pub fn read_tls_handshake_packet<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    read_message(
        stream,
        PRELOGIN_TYPE,
        MAX_PRELOGIN_LEN,
        MAX_PRELOGIN_PACKETS,
    )
}

/// Wrap TLS handshake bytes in one or more TDS 7.x PRELOGIN packets.
/// Handshake data must never be logged or confused with normal PRELOGIN options.
pub fn wrap_tls_handshake_bytes(tls_bytes: &[u8]) -> io::Result<Vec<u8>> {
    if tls_bytes.is_empty() || tls_bytes.len() > MAX_PRELOGIN_LEN {
        return Err(invalid("TLS handshake payload outside bounds"));
    }
    let max_payload = MAX_PACKET_LEN - HEADER_LEN;
    let mut framed = Vec::with_capacity(tls_bytes.len() + 3 * HEADER_LEN);
    let mut chunks = tls_bytes.chunks(max_payload).peekable();
    let mut packet_id = 1u8;
    while let Some(chunk) = chunks.next() {
        let size = HEADER_LEN + chunk.len();
        framed.extend_from_slice(&[
            PRELOGIN_TYPE,
            if chunks.peek().is_none() { EOM } else { 0 },
            (size >> 8) as u8,
            size as u8,
            0,
            0,
            packet_id,
            0,
        ]);
        framed.extend_from_slice(chunk);
        packet_id = packet_id.wrapping_add(1);
    }
    Ok(framed)
}

/// Encode one complete server TABULAR_RESULT (0x04) message with EOM.
pub fn response_packet(payload: &[u8]) -> io::Result<Vec<u8>> {
    let total = HEADER_LEN + payload.len();
    if total > MAX_PACKET_LEN || total > usize::from(u16::MAX) {
        return Err(invalid("response packet exceeds limit"));
    }
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(&[
        RESPONSE_TYPE,
        EOM,
        (total >> 8) as u8,
        total as u8,
        0,
        0,
        1,
        0,
    ]);
    packet.extend_from_slice(payload);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn supports_segmented_prelogin() {
        let mut bytes = vec![0x12, 0, 0, 10, 0, 0, 1, 0, 0, 1];
        bytes.extend_from_slice(&[0x12, 1, 0, 10, 0, 0, 2, 0, 2, 3]);
        assert_eq!(
            read_prelogin(&mut Cursor::new(bytes)).unwrap(),
            [0, 1, 2, 3]
        );
    }

    #[test]
    fn rejects_short_total_length() {
        let bytes = [0x12, 1, 0, 7, 0, 0, 1, 0];
        assert_eq!(
            read_prelogin(&mut Cursor::new(bytes)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_other_packet_types() {
        let bytes = [0x10, 1, 0, 9, 0, 0, 1, 0, 0];
        assert_eq!(
            read_prelogin(&mut Cursor::new(bytes)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_truncated_data() {
        let bytes = [0x12, 1, 0, 12, 0, 0, 1, 0, 0];
        assert_eq!(
            read_prelogin(&mut Cursor::new(bytes)).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn accepts_segmented_login7() {
        let mut wire = vec![LOGIN7_TYPE, 0, 0, 10, 0, 0, 1, 0, 0xaa, 0xbb];
        wire.extend_from_slice(&[LOGIN7_TYPE, EOM, 0, 10, 0, 0, 2, 0, 0xcc, 0xdd]);
        assert_eq!(
            read_login7(&mut Cursor::new(wire)).unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd]
        );
    }

    #[test]
    fn rejects_wrong_type_in_second_login_segment() {
        let mut wire = vec![LOGIN7_TYPE, 0, 0, 9, 0, 0, 1, 0, 0xaa];
        wire.extend_from_slice(&[PRELOGIN_TYPE, EOM, 0, 9, 0, 0, 2, 0, 0xbb]);
        assert_eq!(
            read_login7(&mut Cursor::new(wire)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_oversized_login7_message() {
        let chunk = vec![0xaa; MAX_PACKET_LEN - HEADER_LEN];
        let mut wire = Vec::new();
        for id in 1..=5 {
            wire.extend_from_slice(&[
                LOGIN7_TYPE,
                if id == 5 { EOM } else { 0 },
                0x80,
                0,
                0,
                0,
                id,
                0,
            ]);
            wire.extend_from_slice(&chunk);
        }
        assert_eq!(
            read_login7(&mut Cursor::new(wire)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_truncated_login7_segment() {
        let wire = [LOGIN7_TYPE, EOM, 0, 10, 0, 0, 1, 0, 0xaa];
        assert_eq!(
            read_login7(&mut Cursor::new(wire)).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn tls_handshake_framing_roundtrip() {
        let bytes = vec![0x42u8; 55_000];
        let wire = wrap_tls_handshake_bytes(&bytes).unwrap();
        assert_eq!(wire[0], PRELOGIN_TYPE);
        assert_eq!(
            read_tls_handshake_packet(&mut Cursor::new(wire)).unwrap(),
            bytes
        );
    }

    #[test]
    fn rejects_empty_tls_handshake() {
        assert_eq!(
            wrap_tls_handshake_bytes(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn serializes_response_header() {
        let frame = response_packet(&[0xff]).unwrap();
        assert_eq!(frame, [0x04, 0x01, 0, 9, 0, 0, 1, 0, 0xff]);
    }
}
