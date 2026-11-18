//! TDS 8-byte packet framing, bounded reads, and message assembly.
use std::io::{self, Read};

pub const PRELOGIN_TYPE: u8 = 0x12;
pub const RESPONSE_TYPE: u8 = 0x04;
const HEADER_LEN: usize = 8;
const MAX_PACKET_LEN: usize = 32 * 1024;
const MAX_MESSAGE_LEN: usize = 64 * 1024;
const MAX_PACKETS: usize = 16;
const EOM: u8 = 0x01;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Read and assemble a single TDS PRELOGIN message.
/// Limits are deliberately conservative in this early honeypot prototype.
pub fn read_prelogin<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    for _ in 0..MAX_PACKETS {
        let mut hdr = [0u8; HEADER_LEN];
        stream.read_exact(&mut hdr)?;
        if hdr[0] != PRELOGIN_TYPE {
            return Err(invalid("expected TDS PRELOGIN packet type 0x12"));
        }
        let total = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
        if !(HEADER_LEN..=MAX_PACKET_LEN).contains(&total) {
            return Err(invalid("invalid TDS packet length"));
        }
        let body_len = total - HEADER_LEN;
        if payload.len().saturating_add(body_len) > MAX_MESSAGE_LEN {
            return Err(invalid("TDS PRELOGIN message exceeds limit"));
        }
        let previous = payload.len();
        payload.resize(previous + body_len, 0);
        stream.read_exact(&mut payload[previous..])?;
        if hdr[1] & EOM != 0 {
            if payload.is_empty() {
                return Err(invalid("empty PRELOGIN message"));
            }
            return Ok(payload);
        }
    }
    Err(invalid("too many packets in PRELOGIN message"))
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
    fn serializes_response_header() {
        let frame = response_packet(&[0xff]).unwrap();
        assert_eq!(frame, [0x04, 0x01, 0, 9, 0, 0, 1, 0, 0xff]);
    }
}
