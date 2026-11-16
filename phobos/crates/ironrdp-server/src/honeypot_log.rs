//! JSONL security event logging for the RDP honeypot.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Mutex;

use serde_json::json;

static LOG_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn log_auth_attempt(
    peer: Option<SocketAddr>,
    username: &str,
    domain: &str,
    outcome: &str,
    reason: &str,
) -> io::Result<()> {
    let _guard = LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = std::env::var("RDP_HONEYPOT_LOG")
        .unwrap_or_else(|_| "/var/log/rdp-honeypot/events.jsonl".to_owned());

    let event = json!({
        "@timestamp": chrono::Utc::now().to_rfc3339_opts(
            chrono::SecondsFormat::Millis,
            true
        ),
        "event": {
            "kind": "event",
            "category": ["authentication"],
            "type": ["denied"],
            "action": "rdp_auth_attempt",
            "outcome": outcome
        },
        "source": {
            "ip": peer.map(|p| p.ip().to_string()),
            "port": peer.map(|p| p.port())
        },
        "user": {
            "name": username,
            "domain": domain
        },
        "rdp": {
            "authentication": {
                "reason": reason
            }
        }
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let mut line = serde_json::to_vec(&event)?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.flush()?;
    file.sync_all()?;

    // Explicitly close the file before returning to the caller.
    drop(file);

    Ok(())
}

/// Records an accepted TCP connection before RDP negotiation.
pub(crate) fn log_connection(peer: SocketAddr) -> io::Result<()> {
    let _guard = LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = std::env::var("RDP_HONEYPOT_LOG")
        .unwrap_or_else(|_| "/var/log/rdp-honeypot/events.jsonl".to_owned());

    let event = json!({
        "@timestamp": chrono::Utc::now().to_rfc3339_opts(
            chrono::SecondsFormat::Millis,
            true
        ),
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["start"],
            "action": "rdp_connection"
        },
        "source": {
            "ip": peer.ip().to_string(),
            "port": peer.port()
        },
        "network": {
            "transport": "tcp",
            "protocol": "rdp"
        }
    });

    let mut line = serde_json::to_vec(&event)?;
    line.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    file.write_all(&line)?;

    Ok(())
}
