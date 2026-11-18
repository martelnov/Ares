//! Strict, bounded parser of MS-TDS LOGIN7 (section 2.2.6.4).
//!
//! Parser only: the network service still closes after PRELOGIN and MUST NOT
//! consume LOGIN7 until TLS and a protected evidence sink are implemented.
//! No authentication, relay, or credential validation is performed here.
use std::fmt;

pub const MAX_LOGIN7_LEN: usize = 131_071; // 128 KiB minus one, per MS-TDS.
const HEADER_LEN: usize = 94;
const INTEGRATED_SECURITY_FLAG: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ParseError {}

/// Secret payloads are deliberately hidden from Debug output. This type is
/// still prototype-grade: a production evidence sink will need dedicated
/// secret-memory handling and controlled encrypted persistence.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Explicit access for a future protected forensic sink. Never log this.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Best-effort cleanup only; not a guaranteed compiler-resistant wipe.
        self.0.fill(0);
    }
}

pub struct Login7 {
    pub tds_version: u32,
    pub packet_size: u32,
    pub integrated_security: bool,
    pub hostname: String,
    pub username: String,
    pub application: String,
    pub server_name: String,
    pub database: String,
    /// UTF-16LE bytes after reversing the LOGIN7 password obfuscation.
    pub password_utf16le: SecretBytes,
    pub sspi: SecretBytes,
}

impl fmt::Debug for Login7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login7")
            .field("tds_version", &self.tds_version)
            .field("packet_size", &self.packet_size)
            .field("integrated_security", &self.integrated_security)
            .field("hostname", &self.hostname)
            .field("username", &self.username)
            .field("application", &self.application)
            .field("server_name", &self.server_name)
            .field("database", &self.database)
            .field("password_utf16le", &"[REDACTED]")
            .field("sspi", &"[REDACTED]")
            .finish()
    }
}

fn u16le(body: &[u8], offset: usize) -> Result<usize, ParseError> {
    let bytes = body
        .get(offset..offset + 2)
        .ok_or(ParseError("truncated LOGIN7 offset/length"))?;
    Ok(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
}

fn u32le(body: &[u8], offset: usize) -> Result<u32, ParseError> {
    let bytes = body
        .get(offset..offset + 4)
        .ok_or(ParseError("truncated LOGIN7 fixed header"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[derive(Clone, Copy)]
struct Region {
    start: usize,
    len: usize,
}

fn region(
    body: &[u8],
    pair_offset: usize,
    bytes_per_unit: usize,
) -> Result<Option<Region>, ParseError> {
    let start = u16le(body, pair_offset)?;
    let units = u16le(body, pair_offset + 2)?;
    if units == 0 {
        return Ok(None); // Per spec, ignore offset when length is zero.
    }
    let len = units
        .checked_mul(bytes_per_unit)
        .ok_or(ParseError("LOGIN7 field length overflow"))?;
    let end = start
        .checked_add(len)
        .ok_or(ParseError("LOGIN7 field offset overflow"))?;
    if start < HEADER_LEN || end > body.len() {
        return Err(ParseError("LOGIN7 field outside variable data"));
    }
    Ok(Some(Region { start, len }))
}

fn field(body: &[u8], r: Option<Region>) -> &[u8] {
    match r {
        Some(Region { start, len }) => &body[start..start + len],
        None => &[],
    }
}

fn text(bytes: &[u8]) -> Result<String, ParseError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ParseError("odd UTF-16LE field size"));
    }
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<u16>>();
    String::from_utf16(&units).map_err(|_| ParseError("invalid UTF-16LE"))
}

impl Login7 {
    pub fn parse(body: &[u8]) -> Result<Self, ParseError> {
        if !(HEADER_LEN..=MAX_LOGIN7_LEN).contains(&body.len()) {
            return Err(ParseError("invalid LOGIN7 length"));
        }
        if usize::try_from(u32le(body, 0)?).ok() != Some(body.len()) {
            return Err(ParseError("LOGIN7 declared length mismatch"));
        }
        let tds_version = u32le(body, 4)?;
        let packet_size = u32le(body, 8)?;
        if !(512..=65535).contains(&packet_size) {
            return Err(ParseError("invalid client packet size"));
        }
        let integrated_security = body[25] & INTEGRATED_SECURITY_FLAG != 0;

        // 9 UTF-16LE offset/character-count pairs, followed by ClientID,
        // followed by 3 pairs. SSPI's length is in bytes, not UTF-16 chars.
        let mut regions: Vec<Option<Region>> = Vec::with_capacity(12);
        for offset in (36..=68).step_by(4) {
            regions.push(region(body, offset, 2)?);
        }
        let sspi = region(body, 78, 1)?;
        let atch_db = region(body, 82, 2)?;
        let change_password = region(body, 86, 2)?;
        regions.extend([sspi, atch_db, change_password]);

        // Spec: ibHostName always locates start of variable data, even if
        // host name is empty. This also avoids accepting header overlap.
        if u16le(body, 36)? < HEADER_LEN {
            return Err(ParseError("invalid host offset"));
        }
        // cbSSPILong is not supported in this phase. Explicitly reject it.
        if u32le(body, 90)? != 0 {
            return Err(ParseError("extended SSPI is not implemented"));
        }
        for (idx, left) in regions.iter().flatten().enumerate() {
            // Ignore empty values in the preceding positions: overlap check
            // is on the complete set of non-empty ranges.
            for right in regions.iter().flatten().skip(idx + 1) {
                if left.start < right.start + right.len && right.start < left.start + left.len {
                    return Err(ParseError("overlapping LOGIN7 variable fields"));
                }
            }
        }
        // Index 5 is extension field and must be absent until FeatureExt
        // parsing is implemented. Don't silently misinterpret its contents.
        if regions[5].is_some() || (body[27] & 0x10 != 0) {
            return Err(ParseError("LOGIN7 feature extensions not yet supported"));
        }
        let hostname = text(field(body, regions[0]))?;
        let username = text(field(body, regions[1]))?;
        let application = text(field(body, regions[3]))?;
        let server_name = text(field(body, regions[4]))?;
        let database = text(field(body, regions[8]))?;

        let mut password = field(body, regions[2]).to_vec();
        for b in &mut password {
            // Reverse: password wire byte = rotate_left(plaintext ^ A5, 4).
            *b = b.rotate_right(4) ^ 0xa5;
        }
        // Verify UTF-16 without creating another plaintext String.
        if text(&password).is_err() {
            password.fill(0);
            return Err(ParseError("invalid LOGIN7 password UTF-16"));
        }
        if integrated_security && !password.is_empty() {
            password.fill(0);
            return Err(ParseError("password supplied with integrated security"));
        }
        Ok(Self {
            tds_version,
            packet_size,
            integrated_security,
            hostname,
            username,
            application,
            server_name,
            database,
            password_utf16le: SecretBytes(password),
            sspi: SecretBytes(field(body, sspi).to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
    fn fixture(username: &str, pwd: &str) -> Vec<u8> {
        let mut b = vec![0u8; HEADER_LEN];
        b[4..8].copy_from_slice(&0x74000004u32.to_le_bytes());
        b[8..12].copy_from_slice(&4096u32.to_le_bytes());
        b[36..38].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        let user = utf16(username);
        let mut password = utf16(pwd);
        for p in &mut password {
            *p = (*p ^ 0xa5).rotate_left(4);
        }
        for (offset, bytes) in [(40usize, user), (44usize, password)] {
            let len = bytes.len() / 2;
            let start = b.len();
            b[offset..offset + 2].copy_from_slice(&(start as u16).to_le_bytes());
            b[offset + 2..offset + 4].copy_from_slice(&(len as u16).to_le_bytes());
            b.extend_from_slice(&bytes);
        }
        let total = b.len() as u32;
        b[0..4].copy_from_slice(&total.to_le_bytes());
        b
    }

    #[test]
    fn decodes_sql_auth_without_leaking_password_via_debug() {
        let parsed = Login7::parse(&fixture("sa", "PřílišTest123!")).unwrap();
        assert_eq!(parsed.username, "sa");
        assert!(!parsed.integrated_security);
        assert_eq!(
            text(parsed.password_utf16le.expose()).unwrap(),
            "PřílišTest123!"
        );
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("PřílišTest123!"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn accepts_empty_password() {
        let parsed = Login7::parse(&fixture("sa", "")).unwrap();
        assert!(parsed.password_utf16le.is_empty());
    }

    #[test]
    fn handles_integrated_security_without_password() {
        let mut b = fixture("", "");
        b[25] = INTEGRATED_SECURITY_FLAG;
        assert!(Login7::parse(&b).unwrap().integrated_security);
    }

    #[test]
    fn rejects_mismatched_length_and_truncation() {
        let mut b = fixture("sa", "example");
        b[0] = 0;
        assert!(Login7::parse(&b).is_err());
        assert!(Login7::parse(&b[..40]).is_err());
    }

    #[test]
    fn rejects_outside_field() {
        let mut b = fixture("sa", "example");
        b[40..42].copy_from_slice(&0xffffu16.to_le_bytes());
        assert!(Login7::parse(&b).is_err());
    }

    #[test]
    fn rejects_overlapping_fields() {
        let mut b = fixture("sa", "example");
        let user_offset = [b[40], b[41]];
        b[44..46].copy_from_slice(&user_offset);
        assert!(Login7::parse(&b).is_err());
    }

    #[test]
    fn rejects_unsupported_extension() {
        let mut b = fixture("sa", "example");
        b[27] |= 0x10;
        assert!(Login7::parse(&b).is_err());
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        let valid = fixture("sa", "example");
        for cut in 0..valid.len() {
            assert!(Login7::parse(&valid[..cut]).is_err());
        }
    }
}
