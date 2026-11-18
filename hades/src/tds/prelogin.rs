//! PRELOGIN option table parser per MS-TDS section 2.2.6.5.
//! Options are one byte token, two-byte BE offset, two-byte BE length.
//! Offsets are relative to the beginning of the PRELOGIN payload, NOT the
//! containing TDS packet. An 0xff byte terminates the table.
use std::fmt;

const VERSION: u8 = 0x00;
const ENCRYPTION: u8 = 0x01;
const INSTOPT: u8 = 0x02;
const MARS: u8 = 0x04;
const TERMINATOR: u8 = 0xff;
const MAX_OPTIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prelogin {
    pub version: [u8; 6],
    pub encryption: Option<u8>,
    pub instance_name: Option<Vec<u8>>,
    pub mars: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ParseError {}

#[derive(Clone, Copy)]
struct Descriptor {
    token: u8,
    offset: usize,
    len: usize,
}

impl Prelogin {
    /// Parse a bounded PRELOGIN payload. Unknown options are accepted after
    /// their ranges have been checked, for forward compatibility.
    pub fn parse(body: &[u8]) -> Result<Self, ParseError> {
        let mut descriptors: Vec<Descriptor> = Vec::new();
        let mut cursor = 0usize;
        let table_end = loop {
            let token = *body
                .get(cursor)
                .ok_or(ParseError("missing PRELOGIN terminator"))?;
            if token == TERMINATOR {
                break cursor + 1;
            }
            if descriptors.len() == MAX_OPTIONS {
                return Err(ParseError("too many PRELOGIN options"));
            }
            let desc_end = cursor
                .checked_add(5)
                .ok_or(ParseError("descriptor overflow"))?;
            let d = body
                .get(cursor..desc_end)
                .ok_or(ParseError("truncated PRELOGIN option descriptor"))?;
            if descriptors.iter().any(|existing| existing.token == token) {
                return Err(ParseError("duplicate PRELOGIN token"));
            }
            descriptors.push(Descriptor {
                token,
                offset: usize::from(u16::from_be_bytes([d[1], d[2]])),
                len: usize::from(u16::from_be_bytes([d[3], d[4]])),
            });
            cursor = desc_end;
        };
        if descriptors.first().map(|d| d.token) != Some(VERSION) {
            return Err(ParseError("VERSION must be first PRELOGIN option"));
        }
        for (i, desc) in descriptors.iter().enumerate() {
            let end = desc
                .offset
                .checked_add(desc.len)
                .ok_or(ParseError("option range overflow"))?;
            if desc.offset < table_end || end > body.len() {
                return Err(ParseError("PRELOGIN option points outside data region"));
            }
            if desc.len == 0 {
                continue;
            }
            for other in descriptors[..i].iter() {
                if other.len == 0 {
                    continue;
                }
                let other_end = other.offset + other.len;
                if desc.offset < other_end && other.offset < end {
                    return Err(ParseError("overlapping PRELOGIN option ranges"));
                }
            }
        }
        let mut version = None;
        let mut encryption = None;
        let mut instance_name = None;
        let mut mars = None;
        for d in descriptors {
            let bytes = &body[d.offset..d.offset + d.len];
            match d.token {
                VERSION => {
                    if bytes.len() != 6 {
                        return Err(ParseError("VERSION length must be six"));
                    }
                    let mut v = [0u8; 6];
                    v.copy_from_slice(bytes);
                    version = Some(v);
                }
                ENCRYPTION => {
                    if bytes.len() != 1 || !matches!(bytes[0], 0..=3) {
                        return Err(ParseError("unsupported ENCRYPTION option"));
                    }
                    encryption = Some(bytes[0]);
                }
                INSTOPT => {
                    if bytes.is_empty() || *bytes.last().unwrap() != 0 {
                        return Err(ParseError("INSTOPT must be NUL-terminated"));
                    }
                    instance_name = Some(bytes.to_vec());
                }
                MARS => {
                    if bytes.len() != 1 || !matches!(bytes[0], 0..=1) {
                        return Err(ParseError("invalid MARS option"));
                    }
                    mars = Some(bytes[0]);
                }
                _ => {}
            }
        }
        Ok(Self {
            version: version.ok_or(ParseError("missing VERSION"))?,
            encryption,
            instance_name,
            mars,
        })
    }
}

/// Construct a PRELOGIN server payload.
/// Advertises ENCRYPT_NOT_SUP because TLS is NOT implemented yet.
/// Therefore this prototype must NOT accept or process credentials.
pub fn response_payload(client: &Prelogin) -> Vec<u8> {
    // VERSION, ENCRYPTION, INSTOPT, optionally MARS.
    let mut fields: Vec<(u8, Vec<u8>)> = vec![
        (VERSION, vec![15, 0, 0, 0, 0, 0]),
        (ENCRYPTION, vec![2]), // ENCRYPT_NOT_SUP
        (INSTOPT, vec![0]),
    ];
    if client.mars.is_some() {
        fields.push((MARS, vec![0])); // no MARS support
    }
    let mut response = Vec::new();
    let mut offset = fields.len() * 5 + 1;
    for (token, data) in &fields {
        response.push(*token);
        response.extend_from_slice(&(offset as u16).to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        offset += data.len();
    }
    response.push(TERMINATOR);
    for (_, data) in fields {
        response.extend_from_slice(&data);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x0b, 0x00, 0x06, 0x01, 0x00, 0x11, 0x00, 0x01, 0xff, 0x0f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn parse_valid() {
        let p = Prelogin::parse(&valid()).unwrap();
        assert_eq!(p.version[0], 15);
        assert_eq!(p.encryption, Some(0));
    }

    #[test]
    fn output_is_valid_prelogin() {
        let p = Prelogin::parse(&valid()).unwrap();
        let response = Prelogin::parse(&response_payload(&p)).unwrap();
        assert_eq!(response.encryption, Some(2));
        assert_eq!(response.instance_name, Some(vec![0]));
    }

    #[test]
    fn missing_terminator() {
        let mut b = valid();
        b[10] = 0;
        assert!(Prelogin::parse(&b).is_err());
    }

    #[test]
    fn out_of_range_offset() {
        let mut b = valid();
        b[2] = 0xff;
        assert!(Prelogin::parse(&b).is_err());
    }

    #[test]
    fn rejects_overlapping_fields() {
        let mut b = valid();
        b[7] = 0x0b;
        assert!(Prelogin::parse(&b).is_err());
    }

    #[test]
    fn rejects_duplicate_tokens() {
        let mut b = valid();
        b[5] = 0;
        assert!(Prelogin::parse(&b).is_err());
    }

    #[test]
    fn rejects_version_not_first() {
        let mut b = valid();
        b[0] = 1;
        assert!(Prelogin::parse(&b).is_err());
    }

    #[test]
    fn rejects_non_null_instance() {
        let body = [
            0, 0, 11, 0, 6, 2, 0, 17, 0, 2, 0xff, 15, 0, 0, 0, 0, 0, b'A', b'B',
        ];
        assert!(Prelogin::parse(&body).is_err());
    }
}
