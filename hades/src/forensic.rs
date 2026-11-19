//! Local-only forensic JSONL output. The caller MUST persist the event
//! before announcing capture or sending a TDS login failure response.
//!
//! This module intentionally preserves captured SQL credentials in JSONL
//! for authorized Security Onion ingestion. Treat the file as sensitive.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::tds::login7::Login7;

const NOFOLLOW: i32 = libc::O_NOFOLLOW;

/// Open a sensitive, append-only event file; reject symlinks, hardlinks,
/// group/other permissions, and files owned by a different UID.
/// This protects the local prototype, not a complete production sandbox.
pub fn open_evidence(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "evidence file must be owned by HADES, regular, single-linked and mode 0600",
        ));
    }
    Ok(file)
}

#[derive(Serialize)]
struct EventMeta<'a> {
    id: &'a str,
    action: &'static str,
    category: [&'static str; 1],
    outcome: &'static str,
    severity: &'static str,
}

#[derive(Serialize)]
struct SensorMeta {
    name: &'static str,
    protocol: &'static str,
}

#[derive(Serialize)]
struct SourceMeta<'a> {
    ip: &'a str,
    port: u16,
}

#[derive(Serialize)]
struct SessionMeta<'a> {
    id: &'a str,
}

#[derive(Serialize)]
struct AuthenticationMeta<'a> {
    method: &'static str,
    username: &'a str,
    /// Present only if the client supplied SQL Authentication credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    /// Raw integrated-security token, NOT a plaintext password.
    #[serde(skip_serializing_if = "Option::is_none")]
    sspi_base64: Option<&'a str>,
}

#[derive(Serialize)]
struct SqlMeta<'a> {
    client_hostname: &'a str,
    application: &'a str,
    requested_database: &'a str,
    requested_server: &'a str,
    tds_version: u32,
}

#[derive(Serialize)]
struct ForensicEvent<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: &'a str,
    event: EventMeta<'a>,
    sensor: SensorMeta,
    source: SourceMeta<'a>,
    authentication: AuthenticationMeta<'a>,
    sql: SqlMeta<'a>,
    destination: SourceMeta<'a>,
    session: SessionMeta<'a>,
}

/// A TCP connection is evidence even if the peer sends no TDS bytes.
/// Record this BEFORE attempting PRELOGIN or TLS. An event ID identifies
/// this record; the separate session ID ties it to any later LOGIN7 event.
#[derive(Serialize)]
struct ConnectionEvent<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: &'a str,
    event: EventMeta<'a>,
    sensor: SensorMeta,
    source: SourceMeta<'a>,
    destination: SourceMeta<'a>,
    session: SessionMeta<'a>,
}

fn persist_record(file: &mut File, record: &impl Serialize) -> io::Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(record).map_err(io::Error::other)?);
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_data()
}

/// Persist a completed TCP connection without waiting for PRELOGIN.
/// Returns the session ID only after the JSONL has been synchronized.
/// If persistence fails, the caller must stop accepting connections.
pub fn persist_connection(
    file: &mut File,
    peer: SocketAddr,
    local: SocketAddr,
) -> io::Result<String> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(io::Error::other)?;
    let event_id = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();
    let peer_ip = peer.ip().to_string();
    let local_ip = local.ip().to_string();
    let event = ConnectionEvent {
        timestamp: &timestamp,
        event: EventMeta {
            id: &event_id,
            action: "tcp_connect",
            category: ["network"],
            outcome: "success",
            severity: "critical",
        },
        sensor: SensorMeta {
            name: "hades",
            protocol: "mssql",
        },
        source: SourceMeta {
            ip: &peer_ip,
            port: peer.port(),
        },
        destination: SourceMeta {
            ip: &local_ip,
            port: local.port(),
        },
        session: SessionMeta { id: &session_id },
    };
    persist_record(file, &event)?;
    Ok(session_id)
}

fn decode_password(input: &[u8]) -> io::Result<Zeroizing<String>> {
    if !input.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "odd UTF-16 password",
        ));
    }
    let units = input
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair));
    let mut plaintext = Zeroizing::new(String::new());
    for scalar in std::char::decode_utf16(units) {
        plaintext.push(
            scalar.map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-16 password")
            })?,
        );
    }
    Ok(plaintext)
}

/// Append one complete event; synchronize the file before returning success.
/// No separate metadata-only feed: this JSONL contains captured passwords.
/// Never call this function with production or organizational credentials in tests.
pub fn persist_login(
    file: &mut File,
    addr: SocketAddr,
    local: SocketAddr,
    session_id: &str,
    login: &Login7,
) -> io::Result<String> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(io::Error::other)?;
    let id = Uuid::new_v4().to_string();
    let ip = addr.ip().to_string();
    let local_ip = local.ip().to_string();
    let password = if login.integrated_security {
        None
    } else {
        Some(decode_password(login.password_utf16le.expose())?)
    };
    let sspi = if login.sspi.is_empty() {
        None
    } else {
        Some(Zeroizing::new(STANDARD.encode(login.sspi.expose())))
    };
    let record = ForensicEvent {
        timestamp: &timestamp,
        event: EventMeta {
            id: &id,
            action: "authentication_attempt",
            category: ["authentication"],
            outcome: "failure",
            severity: "critical",
        },
        sensor: SensorMeta {
            name: "hades",
            protocol: "mssql",
        },
        source: SourceMeta {
            ip: &ip,
            port: addr.port(),
        },
        authentication: AuthenticationMeta {
            method: if login.integrated_security {
                "integrated"
            } else {
                "sql"
            },
            username: &login.username,
            password: password.as_ref().map(|p| p.as_str()),
            sspi_base64: sspi.as_deref().map(|s| s.as_str()),
        },
        sql: SqlMeta {
            client_hostname: &login.hostname,
            application: &login.application,
            requested_database: &login.database,
            requested_server: &login.server_name,
            tds_version: login.tds_version,
        },
        destination: SourceMeta {
            ip: &local_ip,
            port: local.port(),
        },
        session: SessionMeta { id: session_id },
    };
    persist_record(file, &record)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_password_is_rejected() {
        assert!(decode_password(&[0u8]).is_err());
    }

    #[test]
    fn tcp_connect_is_durable_and_contains_no_authentication() {
        let path = std::env::temp_dir().join(format!("hades-connect-test-{}", Uuid::new_v4()));
        let mut file = open_evidence(&path).unwrap();
        let peer: SocketAddr = "127.0.0.1:41234".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:11433".parse().unwrap();
        let session_id = persist_connection(&mut file, peer, local).unwrap();
        drop(file);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        let event: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(event["event"]["action"], "tcp_connect");
        assert_eq!(event["event"]["severity"], "critical");
        assert_eq!(event["source"]["port"], 41234);
        assert_eq!(event["destination"]["port"], 11433);
        assert_eq!(event["session"]["id"], session_id);
        assert_ne!(event["event"]["id"], event["session"]["id"]);
        assert!(event.get("authentication").is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn null_password_is_valid() {
        assert!(decode_password(&[]).unwrap().is_empty());
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use std::fs;

    #[test]
    fn evidence_file_is_mode_0600() {
        let path = std::env::temp_dir().join(format!("hades-evidence-test-{}", Uuid::new_v4()));
        let file = open_evidence(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_world_readable_file() {
        let path = std::env::temp_dir().join(format!("hades-evidence-test-{}", Uuid::new_v4()));
        fs::write(&path, b"test\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            open_evidence(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(path).unwrap();
    }
}
