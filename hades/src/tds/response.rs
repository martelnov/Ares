//! MS-TDS server login rejection (ERROR 18456 + DONE_ERROR).
//! Never emits LOGINACK, so authentication cannot succeed.
use crate::tds::packet::response_packet;
use std::io;

const ERROR_TOKEN: u8 = 0xaa;
const DONE_TOKEN: u8 = 0xfd;
const DONE_ERROR: u16 = 0x0002;
const LOGIN_FAILED: u32 = 18456;

/// TDS 7.2+ response: ERROR token, then DONE with an 8-byte row count.
pub fn login_failed_response() -> io::Result<Vec<u8>> {
    let message = "Login failed for user.";
    let utf16: Vec<u16> = message.encode_utf16().collect();
    let server_name: Vec<u16> = "HADES".encode_utf16().collect();
    let mut error = Vec::new();
    error.extend_from_slice(&LOGIN_FAILED.to_le_bytes());
    error.push(1); // error state
    error.push(14); // error class / severity
    error.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
    for character in utf16 {
        error.extend_from_slice(&character.to_le_bytes());
    }
    error.push(server_name.len() as u8);
    for character in server_name {
        error.extend_from_slice(&character.to_le_bytes());
    }
    error.push(0); // zero-length procedure name
    error.extend_from_slice(&0u32.to_le_bytes()); // line number for TDS 7.2+

    let mut payload = Vec::new();
    payload.push(ERROR_TOKEN);
    payload.extend_from_slice(&(error.len() as u16).to_le_bytes());
    payload.extend_from_slice(&error);
    payload.push(DONE_TOKEN);
    payload.extend_from_slice(&DONE_ERROR.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes()); // current command
    payload.extend_from_slice(&0u64.to_le_bytes()); // row count
    response_packet(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_error_18456_and_done_without_login_ack() {
        let packet = login_failed_response().unwrap();
        assert_eq!(packet[0], 0x04);
        assert_eq!(packet[8], ERROR_TOKEN);
        assert_eq!(
            u32::from_le_bytes(packet[11..15].try_into().unwrap()),
            LOGIN_FAILED
        );
        assert!(packet.contains(&DONE_TOKEN));
        assert!(!packet.contains(&0xad)); // No LOGINACK token anywhere
    }
}
